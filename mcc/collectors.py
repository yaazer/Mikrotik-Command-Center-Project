"""UDP collectors: Traffic Flow (IPFIX / NetFlow v9 / v5) and syslog, plus RouterOS message parsing.

Both listeners drop packets from anyone but the router (and config collectors.accept_from), so a
host on the LAN can't feed MCC invented flows or log lines to trick you into blocking someone.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .util import split_hostport

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 132: "SCTP"}
PROTO_NUMS = {v: k for k, v in PROTO_NAMES.items()}


# --------------------------------------------------------------------------------------------
# generic UDP listener
# --------------------------------------------------------------------------------------------
class UdpCollector(threading.Thread):
    def __init__(self, name: str, bind: str, port: int, handler: Callable[[bytes, str], None],
                 allowed: Callable[[str], bool]):
        super().__init__(name="mcc-" + name, daemon=True)
        self.label = name
        self.bind_addr = bind
        self.port = port
        self.handler = handler
        self.allowed = allowed
        self.packets = 0
        self.errors = 0
        self.last_at = 0.0
        self.last_error = ""
        self.rejected: Dict[str, int] = {}
        self.listening = False
        self._stop = threading.Event()
        self.sock: Optional[socket.socket] = None

    def open(self) -> None:
        fam = socket.AF_INET6 if ":" in self.bind_addr else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        s.bind((self.bind_addr, self.port))
        s.settimeout(0.5)
        self.port = s.getsockname()[1]
        self.sock = s
        self.listening = True

    def run(self) -> None:
        if self.sock is None:
            try:
                self.open()
            except OSError as e:
                self.last_error = "cannot listen on UDP {}: {}".format(self.port, e)
                return
        assert self.sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            sender = addr[0]
            if sender.startswith("::ffff:"):
                sender = sender[7:]
            if not self.allowed(sender):
                self.rejected[sender] = self.rejected.get(sender, 0) + 1
                continue
            self.packets += 1
            self.last_at = time.time()
            try:
                self.handler(data, sender)
            except Exception as e:  # a malformed packet must never kill the listener
                self.errors += 1
                self.last_error = "{}: {}".format(type(e).__name__, e)

    def stop(self) -> None:
        self._stop.set()
        self.listening = False
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass

    def status(self) -> Dict[str, Any]:
        return {"port": self.port, "listening": self.listening, "packets": self.packets, "errors": self.errors,
                "last_at": self.last_at, "last_error": self.last_error,
                "rejected": dict(sorted(self.rejected.items(), key=lambda kv: -kv[1])[:10])}


# --------------------------------------------------------------------------------------------
# flow export parsing
# --------------------------------------------------------------------------------------------
# information element id -> (our key, kind)
IE = {
    1: ("bytes", "u"), 2: ("packets", "u"), 4: ("proto", "u"), 6: ("flags", "u"), 7: ("sport", "u"),
    8: ("src", "ip4"), 10: ("in_if", "u"), 11: ("dport", "u"), 12: ("dst", "ip4"), 14: ("out_if", "u"),
    21: ("last_ms", "u"), 22: ("first_ms", "u"), 23: ("bytes_out", "u"), 24: ("packets_out", "u"),
    27: ("src", "ip6"), 28: ("dst", "ip6"), 32: ("icmp", "u"), 85: ("bytes", "u"), 86: ("packets", "u"),
    150: ("start_s", "u"), 151: ("end_s", "u"), 152: ("start_ms", "u"), 153: ("end_ms", "u"),
    225: ("nat_src", "ip4"), 226: ("nat_dst", "ip4"), 227: ("nat_sport", "u"), 228: ("nat_dport", "u"),
}


def _decode(kind: str, raw: bytes) -> Any:
    if kind == "ip4":
        return str(ipaddress.IPv4Address(raw[-4:])) if len(raw) >= 4 else ""
    if kind == "ip6":
        return str(ipaddress.IPv6Address(raw[-16:])) if len(raw) >= 16 else ""
    return int.from_bytes(raw, "big") if raw else 0


class FlowParser:
    """Stateful: v9 and IPFIX send templates once in a while and data records refer to them."""

    def __init__(self) -> None:
        self.templates: Dict[Tuple[str, int, int], List[Tuple[int, int, int]]] = {}
        self.waiting = 0  # data sets seen before their template

    def parse(self, data: bytes, exporter: str) -> List[Dict[str, Any]]:
        if len(data) < 4:
            raise ValueError("short packet")
        version = struct.unpack("!H", data[:2])[0]
        if version == 5:
            return self._v5(data)
        if version == 9:
            return self._v9(data, exporter)
        if version == 10:
            return self._ipfix(data, exporter)
        raise ValueError("unsupported flow version {}".format(version))

    def _v5(self, data: bytes) -> List[Dict[str, Any]]:
        count = struct.unpack("!H", data[2:4])[0]
        flows = []
        for i in range(count):
            off = 24 + i * 48
            rec = data[off:off + 48]
            if len(rec) < 48:
                break
            (src, dst, _nh, in_if, out_if, pkts, octets, first, last, sport, dport, _p1, flags, proto,
             _tos, _sas, _das, _sm, _dm, _p2) = struct.unpack("!4s4s4sHHIIIIHHBBBBHHBBH", rec)
            flows.append(self._norm({"src": str(ipaddress.IPv4Address(src)), "dst": str(ipaddress.IPv4Address(dst)),
                                     "in_if": in_if, "out_if": out_if, "packets": pkts, "bytes": octets,
                                     "first_ms": first, "last_ms": last, "sport": sport, "dport": dport,
                                     "flags": flags, "proto": proto}))
        return flows

    def _v9(self, data: bytes, exporter: str) -> List[Dict[str, Any]]:
        source_id = struct.unpack("!I", data[16:20])[0]
        return self._sets(data, 20, exporter, source_id, tmpl_id=0, opt_id=1, ipfix=False)

    def _ipfix(self, data: bytes, exporter: str) -> List[Dict[str, Any]]:
        length, _t, _seq, domain = struct.unpack("!HIII", data[2:16])
        return self._sets(data[:length], 16, exporter, domain, tmpl_id=2, opt_id=3, ipfix=True)

    def _sets(self, data: bytes, off: int, exporter: str, domain: int, tmpl_id: int, opt_id: int,
              ipfix: bool) -> List[Dict[str, Any]]:
        flows: List[Dict[str, Any]] = []
        while off + 4 <= len(data):
            set_id, set_len = struct.unpack("!HH", data[off:off + 4])
            if set_len < 4:
                break
            body = data[off + 4:off + set_len]
            off += set_len
            if set_id == tmpl_id:
                self._templates(body, exporter, domain, ipfix)
            elif set_id == opt_id:
                continue
            elif set_id >= 256:
                tmpl = self.templates.get((exporter, domain, set_id))
                if tmpl is None:
                    self.waiting += 1
                    continue
                flows.extend(self._records(body, tmpl))
        return flows

    def _templates(self, body: bytes, exporter: str, domain: int, ipfix: bool) -> None:
        p = 0
        while p + 4 <= len(body):
            tid, count = struct.unpack("!HH", body[p:p + 4])
            p += 4
            if tid < 256:
                break
            fields = []
            for _ in range(count):
                if p + 4 > len(body):
                    return
                fid, flen = struct.unpack("!HH", body[p:p + 4])
                p += 4
                ent = 0
                if ipfix and fid & 0x8000:
                    fid &= 0x7FFF
                    ent = struct.unpack("!I", body[p:p + 4])[0]
                    p += 4
                fields.append((fid, flen, ent))
            self.templates[(exporter, domain, tid)] = fields

    def _records(self, body: bytes, tmpl: List[Tuple[int, int, int]]) -> List[Dict[str, Any]]:
        out = []
        fixed = all(fl != 65535 for _, fl, _ in tmpl)
        min_len = sum(fl for _, fl, _ in tmpl) if fixed else 1
        p = 0
        while p + min_len <= len(body) and min_len > 0:
            rec: Dict[str, Any] = {}
            for fid, flen, ent in tmpl:
                if flen == 65535:
                    if p >= len(body):
                        return out
                    flen = body[p]
                    p += 1
                    if flen == 255:
                        flen = struct.unpack("!H", body[p:p + 2])[0]
                        p += 2
                raw = body[p:p + flen]
                p += flen
                if ent == 0 and fid in IE:
                    key, kind = IE[fid]
                    rec[key] = _decode(kind, raw)
            if "src" in rec and "dst" in rec:
                out.append(self._norm(rec))
        return out

    @staticmethod
    def _norm(rec: Dict[str, Any]) -> Dict[str, Any]:
        dur = 0.0
        if rec.get("start_ms") and rec.get("end_ms"):
            dur = max(0.0, (rec["end_ms"] - rec["start_ms"]) / 1000.0)
        elif rec.get("first_ms") is not None and rec.get("last_ms") is not None:
            dur = max(0.0, (rec["last_ms"] - rec["first_ms"]) / 1000.0)
        return {
            "src": rec.get("src", ""), "dst": rec.get("dst", ""),
            "sport": int(rec.get("sport") or 0), "dport": int(rec.get("dport") or 0),
            "proto": int(rec.get("proto") or 0), "bytes": int(rec.get("bytes") or 0),
            "packets": int(rec.get("packets") or 0), "flags": int(rec.get("flags") or 0),
            "in_if": rec.get("in_if"), "out_if": rec.get("out_if"), "duration": dur,
            "nat_src": rec.get("nat_src") or "", "nat_dst": rec.get("nat_dst") or "",
        }


# --------------------------------------------------------------------------------------------
# syslog + RouterOS message parsing
# --------------------------------------------------------------------------------------------
_PRI = re.compile(r"^<(\d{1,3})>")
_BSD_TS = re.compile(r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+")
_TOPICS = re.compile(r"^([a-z0-9-]+(?:,[a-z0-9-]+)*)\s+(.*)$", re.S)
KNOWN_TOPICS = {"info", "error", "warning", "critical", "debug", "firewall", "system", "account", "interface",
                "dhcp", "wireless", "script", "ppp", "pppoe", "ovpn", "ipsec", "dns", "bgp", "ospf", "route",
                "bridge", "certificate", "health", "ssh", "web-proxy", "manager", "wireguard", "caps", "lte",
                "event", "packet", "state", "stp", "watchdog", "backup", "async", "e-mail", "ntp", "upnp"}

FW_RE = re.compile(
    r"^(?:(?P<prefix>.*?)\s+)?(?P<chain>[\w-]+): in:(?P<in>\S+) out:(?P<out>.*?),.*?"
    r"proto (?P<proto>[A-Za-z0-9-]+)(?: \((?P<pinfo>[^)]*)\))?, (?P<src>\S+?)->(?P<dst>\S+?),", re.S)
LOGIN_FAIL_RE = re.compile(r"login failure for user (?P<user>.+?) from (?P<src>\S+) via (?P<via>\S+)")
LOGIN_OK_RE = re.compile(r"user (?P<user>.+?) logged in from (?P<src>\S+) via (?P<via>\S+)")
LINK_RE = re.compile(r"^(?P<iface>\S+) link (?P<state>up|down)\b")


def split_syslog(data: bytes) -> Tuple[str, str]:
    """Returns (topics, message) for a RouterOS syslog packet, BSD-formatted or not."""
    text = data.decode("utf-8", "replace").strip()
    m = _PRI.match(text)
    if m:
        text = text[m.end():]
    m = _BSD_TS.match(text)
    if m:
        text = text[m.end():]
        first, _, rest = text.partition(" ")
        if "," not in first and first not in KNOWN_TOPICS:
            text = rest  # that was the hostname
    m = _TOPICS.match(text)
    if m and (set(m.group(1).split(",")) & KNOWN_TOPICS):
        return m.group(1), m.group(2).strip()
    return "", text


def classify(topics: str, msg: str) -> Dict[str, Any]:
    """Recognise the RouterOS log lines MCC acts on."""
    tset = set(topics.split(",")) if topics else set()
    m = FW_RE.match(msg)
    if m and ("firewall" in tset or not tset or "->" in msg):
        src, sport = split_hostport(m.group("src"))
        dst, dport = split_hostport(m.group("dst"))
        pinfo = m.group("pinfo") or ""
        return {"kind": "fw", "prefix": (m.group("prefix") or "").strip(), "chain": m.group("chain"),
                "in_if": m.group("in"), "out_if": m.group("out").strip(), "proto": m.group("proto").upper(),
                "flags": pinfo, "src": src, "sport": sport or 0, "dst": dst, "dport": dport or 0}
    m = LOGIN_FAIL_RE.search(msg)
    if m:
        return {"kind": "login_fail", "user": m.group("user"), "src": m.group("src"), "via": m.group("via")}
    m = LOGIN_OK_RE.search(msg)
    if m:
        return {"kind": "login_ok", "user": m.group("user"), "src": m.group("src"), "via": m.group("via")}
    m = LINK_RE.match(msg)
    if m:
        return {"kind": "link", "iface": m.group("iface"), "up": m.group("state") == "up"}
    return {"kind": "other"}


def level_of(topics: str) -> str:
    t = set(topics.split(","))
    if "critical" in t:
        return "crit"
    if "error" in t:
        return "error"
    if "warning" in t:
        return "warn"
    if "firewall" in t:
        return "fw"
    return "info"
