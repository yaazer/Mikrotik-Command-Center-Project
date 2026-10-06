"""Traffic model: who on the LAN is talking to whom on the Internet, and how fast.

Two sources feed it:
  * the router's connection table (polled over REST) -- live per-connection rates, available
    without any router changes;
  * Traffic Flow records (IPFIX / NetFlow) -- complete accounting, arrives in 15-60 s batches.
Live rates come from conntrack while it is fresh; flows fill in when it isn't.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Set, Tuple

from . import classify
from .collectors import PROTO_NAMES
from .util import in_networks, ip_obj, is_local_scope, split_hostport, to_int

SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE",
    587: "Submission", 853: "DoT", 993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 1883: "MQTT", 1900: "SSDP",
    3074: "Xbox Live", 3389: "RDP", 3478: "STUN", 4500: "IPsec NAT-T", 5060: "SIP", 5222: "XMPP",
    5353: "mDNS", 5900: "VNC", 8080: "HTTP-alt", 8291: "Winbox", 8443: "HTTPS-alt", 8728: "RouterOS API",
    8729: "RouterOS API-SSL", 9001: "Tor", 19302: "Google STUN", 51820: "WireGuard", 6667: "IRC",
    32400: "Plex", 27015: "Steam",
}

_RATE = re.compile(r"^\s*([\d.]+)\s*([kKMGT]?)(?:bps|b/s)?\s*$")


def parse_rate(value: Any) -> Optional[float]:
    """RouterOS conntrack orig-rate/repl-rate: '12345' or '12.3kbps'. Returns bits/s."""
    if value is None or value == "":
        return None
    m = _RATE.match(str(value))
    if not m:
        return None
    mult = {"": 1, "k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}[m.group(2)]
    return float(m.group(1)) * mult


def service_label(proto: str, port: int) -> str:
    name = SERVICES.get(port, "")
    if proto in ("ICMP", "ICMPv6"):
        return proto
    return "{} {}".format(name, port) if name else "{}/{}".format(proto.lower(), port)


class TrafficModel:
    FLOW_WINDOW = 90.0
    CONN_FRESH = 15.0

    def __init__(self, lan_nets: Callable[[], List[Any]], router_addrs: Callable[[], Set[str]],
                 name_of: Callable[[str], str]):
        self.lan_nets = lan_nets
        self.router_addrs = router_addrs
        self.name_of = name_of
        self.conn_pairs: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        self.conn_count = 0
        self.conn_at = 0.0
        self._prev_bytes: Dict[str, Tuple[float, int, int]] = {}
        self.flows: Deque[Tuple[float, Dict[str, Any]]] = deque()
        self.flow_total = 0
        self.host_hist: Dict[str, Deque[Tuple[float, float, float]]] = defaultdict(lambda: deque(maxlen=300))
        self.baseline_up: Dict[str, float] = {}
        # which router interface a connection left (or arrived) by: path_of(direction, src, dst, reply_dst)
        # -> interface name, or "" when the connection table doesn't say (set by the hub)
        self.path_of: Callable[[str, str, str, str], str] = lambda d, src, dst, rdst: ""

    # -- classification ----------------------------------------------------------------------
    def side(self, ip: str) -> str:
        o = ip_obj(ip)
        if o is None:
            return "?"
        if ip in self.router_addrs():
            return "router"
        if o.is_multicast or o.is_unspecified or str(o) == "255.255.255.255":
            return "skip"
        if in_networks(o, self.lan_nets()) or is_local_scope(o):
            return "lan"
        return "wan"

    def orient(self, src: str, dst: str, reply_src: str = "") -> Optional[Tuple[str, str, str]]:
        """-> (local, remote, direction) where direction 'out' means the local side initiated."""
        s, d = self.side(src), self.side(dst)
        if "skip" in (s, d) or "?" in (s, d):
            return None
        if s in ("lan", "router") and d == "wan":
            return src, dst, "out"
        if s == "wan" and d in ("lan", "router"):
            local = dst
            if d == "router" and reply_src and self.side(reply_src) == "lan":
                local = reply_src  # dst-nat'ed to an internal server
            return local, src, "in"
        if s == "lan" and d in ("lan", "router"):
            return src, dst, "lan"
        if s == "router" and d == "lan":
            return dst, src, "lan"
        return None

    # -- conntrack ---------------------------------------------------------------------------
    def ingest_conns(self, conns: Iterable[Dict[str, Any]], now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Takes /ip/firewall/connection rows, returns them normalised (for the detector)."""
        now = now or time.time()
        pairs: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        seen_ids = set()
        normalised = []
        for c in conns:
            src, sport = split_hostport(c.get("src-address", ""))
            dst, dport = split_hostport(c.get("dst-address", ""))
            rsrc, rport = split_hostport(c.get("reply-src-address", ""))
            rdst, _ = split_hostport(c.get("reply-dst-address", ""))
            o = self.orient(src, dst, rsrc)
            if o is None:
                continue
            local, remote, direction = o
            via = "" if direction == "lan" else self.path_of(direction, src, dst, rdst)
            proto = str(c.get("protocol", "")).upper() or "?"
            if proto.isdigit():
                proto = PROTO_NAMES.get(int(proto), proto)
            # a dst-nat'ed connection's service port is the internal one
            port = (rport if direction == "in" and local == rsrc and rport else dport) or 0
            orig, repl = parse_rate(c.get("orig-rate")), parse_rate(c.get("repl-rate"))
            cid = str(c.get(".id", ""))
            ob, rb = to_int(c.get("orig-bytes")), to_int(c.get("repl-bytes"))
            if orig is None or repl is None:
                prev = self._prev_bytes.get(cid)
                orig = repl = 0.0
                if prev and now > prev[0] and ob >= prev[1] and rb >= prev[2]:
                    dt = now - prev[0]
                    orig, repl = (ob - prev[1]) * 8 / dt, (rb - prev[2]) * 8 / dt
            if cid:
                seen_ids.add(cid)
                self._prev_bytes[cid] = (now, ob, rb)
            # orig = initiator -> responder
            if direction == "out" or direction == "lan":
                up, down = orig, repl
            else:
                up, down = repl, orig
            key = (local, remote, proto, port, via)
            p = pairs.get(key)
            if p is None:
                p = pairs[key] = {"local": local, "remote": remote, "proto": proto, "port": port,
                                  "dir": direction, "via": via, "up": 0.0, "down": 0.0, "conns": 0, "bytes": 0}
            p["up"] += up
            p["down"] += down
            p["conns"] += 1
            p["bytes"] += ob + rb
            normalised.append({"id": cid, "local": local, "remote": remote, "dir": direction, "proto": proto,
                               "port": port, "src": src, "dst": dst, "sport": sport or 0, "dport": dport or 0,
                               "tcp_state": c.get("tcp-state", ""), "up": up, "down": down, "via": via})
        for cid in list(self._prev_bytes):
            if cid not in seen_ids:
                del self._prev_bytes[cid]
        self.conn_pairs = pairs
        self.conn_count = len(normalised)
        self.conn_at = now
        return normalised

    # -- flows -------------------------------------------------------------------------------
    def ingest_flow(self, f: Dict[str, Any], now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        now = now or time.time()
        o = self.orient(f["src"], f["dst"])
        if o is None:
            return None
        local, remote, direction = o
        if direction == "in" and f.get("nat_dst") and self.side(f["nat_dst"]) == "lan":
            local = f["nat_dst"]
        if direction == "out" and f.get("nat_src"):
            pass  # src is already the internal host
        g = dict(f)
        g.update({"local": local, "remote": remote, "dir": direction,
                  "proto_name": PROTO_NAMES.get(f["proto"], str(f["proto"]))})
        self.flows.append((now, g))
        self.flow_total += 1
        self._prune(now)
        return g

    def _prune(self, now: float) -> None:
        cutoff = now - self.FLOW_WINDOW
        while self.flows and self.flows[0][0] < cutoff:
            self.flows.popleft()

    def flow_pairs(self, now: float) -> Dict[Tuple[Any, ...], Dict[str, Any]]:
        self._prune(now)
        pairs: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        span = self.FLOW_WINDOW
        for _ts, f in self.flows:
            local, remote = f["local"], f["remote"]
            proto = f["proto_name"]
            # the service port is the responder's
            if f["src"] == local:
                port = f["dport"] if f["dir"] in ("out", "lan") else f["sport"]
                up = True
            else:
                port = f["sport"] if f["dir"] in ("out", "lan") else f["dport"]
                up = False
            key = (local, remote, proto, port)
            p = pairs.get(key)
            if p is None:
                p = pairs[key] = {"local": local, "remote": remote, "proto": proto, "port": port, "dir": f["dir"],
                                  "via": "", "up": 0.0, "down": 0.0, "conns": 0, "bytes": 0}
            bps = f["bytes"] * 8 / span
            if up:
                p["up"] += bps
            else:
                p["down"] += bps
            p["conns"] += 1
            p["bytes"] += f["bytes"]
        return pairs

    # -- snapshot ----------------------------------------------------------------------------
    def source(self, now: float) -> str:
        if self.conn_at and now - self.conn_at < self.CONN_FRESH:
            return "conntrack"
        if self.flows:
            return "flows"
        return "none"

    def snapshot(self, now: Optional[float] = None, blocked: Optional[Set[str]] = None,
                 threats: Optional[Dict[str, str]] = None, limit_pairs: int = 120,
                 pinned: Optional[Dict[str, bool]] = None, vpn: Optional[Set[str]] = None,
                 vpn_required: Iterable[str] = ()) -> Dict[str, Any]:
        """pinned: address -> is it a LAN host. Pinned devices lead every list (and are listed even
        when idle); conversations involving one come first."""
        now = now or time.time()
        pinned = pinned or {}
        src = self.source(now)
        pairs = self.conn_pairs if src == "conntrack" else self.flow_pairs(now) if src == "flows" else {}
        blocked = blocked or set()
        threats = threats or {}
        hosts: Dict[str, Dict[str, Any]] = {}
        peers: Dict[str, Dict[str, Any]] = {}
        services: Dict[str, Dict[str, Any]] = {}
        types: Dict[str, Dict[str, Any]] = {}
        tot_in = tot_out = 0.0
        plist = []
        classify.apply(pairs.values(), self.name_of)  # p["cat"] / p["cat_why"]
        for p in pairs.values():
            h = hosts.setdefault(p["local"], {"ip": p["local"], "name": self.name_of(p["local"]), "up": 0.0,
                                              "down": 0.0, "conns": 0, "peers": set(), "_cats": []})
            h["conns"] += p["conns"]
            if p["dir"] == "lan":
                continue
            h["up"] += p["up"]
            h["down"] += p["down"]
            h["peers"].add(p["remote"])
            h["_cats"].append((p["cat"], p["up"] + p["down"]))
            r = peers.setdefault(p["remote"], {"ip": p["remote"], "name": self.name_of(p["remote"]), "up": 0.0,
                                               "down": 0.0, "conns": 0, "hosts": set(), "ports": set(), "_cats": []})
            r["_cats"].append((p["cat"], p["up"] + p["down"]))
            t = types.setdefault(p["cat"], {"id": p["cat"], "label": classify.LABEL.get(p["cat"], p["cat"]), "up": 0.0,
                                            "down": 0.0, "conns": 0, "hosts": set(), "peers": set()})
            t["up"] += p["up"]
            t["down"] += p["down"]
            t["conns"] += p["conns"]
            t["hosts"].add(p["local"])
            t["peers"].add(p["remote"])
            r["up"] += p["up"]
            r["down"] += p["down"]
            r["conns"] += p["conns"]
            r["hosts"].add(p["local"])
            r["ports"].add(p["port"])
            label = service_label(p["proto"], p["port"])
            s = services.setdefault(label, {"label": label, "port": p["port"], "proto": p["proto"], "bps": 0.0,
                                            "conns": 0})
            s["bps"] += p["up"] + p["down"]
            s["conns"] += p["conns"]
            tot_in += p["down"]
            tot_out += p["up"]
            plist.append(p)
        plist.sort(key=lambda p: (not (p["local"] in pinned or p["remote"] in pinned), -(p["up"] + p["down"])))
        for ip, h in hosts.items():
            self.host_hist[ip].append((now, h["down"], h["up"]))
            b = self.baseline_up.get(ip)
            self.baseline_up[ip] = h["up"] if b is None else b * 0.995 + h["up"] * 0.005
        def cats(x: Dict[str, Any]) -> Dict[str, Any]:
            c, dom = classify.rollup(x.pop("_cats", []))
            return {"cats": c, "cat": dom}

        for ip, lan in pinned.items():  # pinned but quiet right now: still listed
            if lan and ip not in hosts:
                hosts[ip] = {"ip": ip, "name": self.name_of(ip), "up": 0.0, "down": 0.0, "conns": 0, "peers": set(),
                             "_cats": [], "idle": True}
            elif not lan and ip not in peers:
                peers[ip] = {"ip": ip, "name": self.name_of(ip), "up": 0.0, "down": 0.0, "conns": 0, "hosts": set(),
                             "ports": set(), "_cats": [], "idle": True}
        order = lambda x: (x["ip"] not in pinned, -(x["up"] + x["down"]))
        host_list = sorted(({**h, "peers": len(h["peers"]), "threat": threats.get(ip, ""), "pinned": ip in pinned,
                             "baseline_up": self.baseline_up.get(ip, 0.0), **cats(h)}
                            for ip, h in hosts.items()), key=order)
        peer_list = sorted(({**r, "hosts": sorted(r["hosts"])[:8], "ports": sorted(r["ports"])[:8], "pinned": ip in pinned,
                             "blocked": ip in blocked, "threat": threats.get(ip, ""), **cats(r)}
                            for ip, r in peers.items()), key=order)
        type_list = sorted(({**t, "hosts": len(t["hosts"]), "peers": len(t["peers"]), "bps": t["up"] + t["down"]}
                            for t in types.values()), key=lambda t: -t["bps"])
        vpn_view = self._vpn_view(pairs.values(), vpn or set(), set(vpn_required), blocked, threats, pinned)
        return {
            "source": src,
            "conns": self.conn_count if src == "conntrack" else sum(p["conns"] for p in pairs.values()),
            "in_bps": tot_in, "out_bps": tot_out,
            "hosts": host_list[:60], "host_count": len(host_list),
            "peers": peer_list[:80], "peer_count": len(peer_list),
            "pairs": [{"local": p["local"], "remote": p["remote"], "proto": p["proto"], "port": p["port"],
                       "dir": p["dir"], "via": p.get("via", ""), "up": p["up"], "down": p["down"], "conns": p["conns"],
                       "service": service_label(p["proto"], p["port"]), "cat": p["cat"], "cat_why": p["cat_why"]}
                      for p in plist[:limit_pairs]],
            "services": sorted(services.values(), key=lambda s: -s["bps"])[:20],
            "types": type_list,
            "vpn": vpn_view,
        }

    def _vpn_view(self, pairs: Iterable[Dict[str, Any]], vpn: Set[str], required: Set[str], blocked: Set[str],
                  threats: Dict[str, str], pinned: Dict[str, bool]) -> Dict[str, Any]:
        """Traffic through the VPN tunnel(s), the devices using them, and what those devices send outside.
        A connection's path is the interface it was NAT'd to (its reply-dst address); "" = not known."""
        hosts: Dict[str, Dict[str, Any]] = {}
        peers: Dict[str, Dict[str, Any]] = {}
        through, outside = [], []
        tot = {"in": 0.0, "out": 0.0, "conns": 0, "direct_in": 0.0, "direct_out": 0.0}
        known = False
        for p in pairs:
            if p["dir"] == "lan":
                continue
            via = p.get("via", "")
            known = known or bool(via)
            if not via:
                continue  # path unknown (flow records, or no NAT): neither VPN nor direct
            h = hosts.setdefault(p["local"], {"ip": p["local"], "name": self.name_of(p["local"]), "up": 0.0,
                                              "down": 0.0, "conns": 0, "direct_up": 0.0, "direct_down": 0.0,
                                              "direct_conns": 0, "peers": set(), "_cats": [], "via": set()})
            if via in vpn:
                h["up"] += p["up"]
                h["down"] += p["down"]
                h["conns"] += p["conns"]
                h["peers"].add(p["remote"])
                h["via"].add(via)
                h["_cats"].append((p.get("cat", "other"), p["up"] + p["down"]))
                r = peers.setdefault(p["remote"], {"ip": p["remote"], "name": self.name_of(p["remote"]), "up": 0.0,
                                                   "down": 0.0, "conns": 0, "hosts": set(), "ports": set(), "_cats": []})
                r["up"] += p["up"]
                r["down"] += p["down"]
                r["conns"] += p["conns"]
                r["hosts"].add(p["local"])
                r["ports"].add(p["port"])
                r["_cats"].append((p.get("cat", "other"), p["up"] + p["down"]))
                tot["in"] += p["down"]
                tot["out"] += p["up"]
                tot["conns"] += p["conns"]
                through.append(p)
            else:
                h["direct_up"] += p["up"]
                h["direct_down"] += p["down"]
                h["direct_conns"] += p["conns"]
                outside.append(p)
        for ip in required:  # devices that must use the VPN are listed even when quiet
            hosts.setdefault(ip, {"ip": ip, "name": self.name_of(ip), "up": 0.0, "down": 0.0, "conns": 0,
                                  "direct_up": 0.0, "direct_down": 0.0, "direct_conns": 0, "peers": set(),
                                  "_cats": [], "via": set()})
        users = {ip for ip, h in hosts.items() if h["conns"] or ip in required}
        for ip, h in hosts.items():
            if ip in users:
                tot["direct_in"] += h["direct_down"]
                tot["direct_out"] += h["direct_up"]

        def cats(x: Dict[str, Any]) -> Dict[str, Any]:
            c, dom = classify.rollup(x.pop("_cats", []))
            return {"cats": c, "cat": dom}

        def pair_out(p: Dict[str, Any]) -> Dict[str, Any]:
            return {"local": p["local"], "remote": p["remote"], "proto": p["proto"], "port": p["port"], "dir": p["dir"],
                    "via": p.get("via", ""), "up": p["up"], "down": p["down"], "conns": p["conns"],
                    "service": service_label(p["proto"], p["port"]), "cat": p.get("cat", "other"),
                    "cat_why": p.get("cat_why", "")}

        rate = lambda x: x["up"] + x["down"]  # noqa: E731
        host_list = sorted(({**h, "peers": len(h["peers"]), "via": sorted(h["via"]), "required": ip in required,
                             "pinned": ip in pinned, "threat": threats.get(ip, ""), **cats(h)}
                            for ip, h in hosts.items() if ip in users),
                           key=lambda h: (not h["required"], not h["pinned"], -rate(h)))
        peer_list = sorted(({**r, "hosts": sorted(r["hosts"])[:8], "ports": sorted(r["ports"])[:8],
                             "blocked": ip in blocked, "threat": threats.get(ip, ""), "pinned": ip in pinned, **cats(r)}
                            for ip, r in peers.items()), key=lambda r: -rate(r))
        through.sort(key=lambda p: -rate(p))
        outside = sorted((p for p in outside if p["local"] in users), key=lambda p: (p["local"] not in required, -rate(p)))
        return {"interfaces": sorted(vpn), "known": known, "in_bps": tot["in"], "out_bps": tot["out"],
                "conns": tot["conns"], "direct_in_bps": tot["direct_in"], "direct_out_bps": tot["direct_out"],
                "hosts": host_list[:60], "peers": peer_list[:60], "pairs": [pair_out(p) for p in through[:120]],
                "outside": [pair_out(p) for p in outside[:60]]}

    def host_detail(self, ip: str, now: Optional[float] = None) -> Dict[str, Any]:
        now = now or time.time()
        src = self.source(now)
        pairs = self.conn_pairs if src == "conntrack" else self.flow_pairs(now)
        classify.apply(pairs.values(), self.name_of)
        rows = [p for p in pairs.values() if p["local"] == ip or p["remote"] == ip]
        rows.sort(key=lambda p: -(p["up"] + p["down"]))
        return {
            "pairs": [{**p, "service": service_label(p["proto"], p["port"]), "remote_name": self.name_of(p["remote"]),
                       "local_name": self.name_of(p["local"])} for p in rows[:200]],
            "history": [[round(t, 1), round(d), round(u)] for t, d, u in self.host_hist.get(ip, [])],
        }
