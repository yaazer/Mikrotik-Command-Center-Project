"""Test suite (stdlib only). Runs against the simulated router/switch in mcc/sim.py.

    python tests/run_tests.py            everything
    python tests/run_tests.py detect     tests whose name contains 'detect'
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcc import sim  # noqa: E402
from mcc.actions import ActionError  # noqa: E402
from mcc.collectors import FlowParser, UdpCollector, classify, split_syslog  # noqa: E402
from mcc.config import Config  # noqa: E402
from mcc.detect import Blocklist, Detector  # noqa: E402
from mcc.hub import Hub  # noqa: E402
from mcc.routeros import RouterOS, RouterOSError, cli_line  # noqa: E402
from mcc.server import make_server  # noqa: E402
from mcc.swos import SwOS, SwOSError, hexstr, parse_js  # noqa: E402
from mcc.traffic import TrafficModel, parse_rate  # noqa: E402
from mcc.util import is_local_scope, parse_duration, split_hostport  # noqa: E402

TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


def eq(a, b, msg=""):
    if a != b:
        raise AssertionError("{}: expected {!r}, got {!r}".format(msg or "mismatch", b, a))


def ok(cond, msg):
    if not cond:
        raise AssertionError(msg)


def wait_for(fn, timeout=10.0, step=0.1):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return fn()


class Env:
    """A temp data dir + simulated network + hub, torn down afterwards."""

    def __init__(self, script=False, speed=1.0, connect=True, blocklist="192.0.2.66\n"):
        self.dir = Path(tempfile.mkdtemp(prefix="mcc-test-"))
        (self.dir / "blocklist.txt").write_text(blocklist, encoding="utf-8")
        self.world = sim.World(seed=3, speed=speed, script=script).start()
        self.router = sim.serve(sim.make_router(self.world))
        self.switch = sim.serve(sim.make_swos(self.world))
        self.cfg = Config(self.dir)
        self.cfg.update({"collectors": {"bind": "127.0.0.1", "flow_port": 0, "syslog_port": 0},
                         "blocklist_file": str(self.dir / "blocklist.txt"), "lan_networks": ["192.168.88.0/24"]})
        self.hub = Hub(self.cfg, self.dir)
        self.hub.start()
        if connect:
            self.hub.connect_router("127.0.0.1", "admin", "demo", scheme="http", port=self.router.server_address[1])
            wait_for(lambda: self.hub.router_addrs, 5)

    def ros(self):
        return RouterOS("127.0.0.1", "admin", "demo", "http", self.router.server_address[1])

    def close(self):
        self.hub.stop()
        self.world.stop()
        self.router.shutdown()
        self.switch.shutdown()
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


# ============================================================================================
# parsing
# ============================================================================================
@test
def t_util_parsing():
    eq(parse_duration("1w2d3h4m5s"), 604800 + 2 * 86400 + 3 * 3600 + 4 * 60 + 5, "duration")
    eq(parse_duration("00:01:30"), 90, "clock duration")
    eq(split_hostport("1.2.3.4:443"), ("1.2.3.4", 443), "v4 hostport")
    eq(split_hostport("[2001:db8::1]:53"), ("2001:db8::1", 53), "v6 hostport")
    eq(split_hostport("2001:db8::1"), ("2001:db8::1", None), "bare v6")
    ok(is_local_scope("192.168.1.5") and is_local_scope("fd00::1"), "RFC1918/ULA are local")
    ok(not is_local_scope("203.0.113.9") and not is_local_scope("198.51.100.2"),
       "documentation ranges are NOT local (ipaddress.is_private says they are)")
    eq(parse_rate("12.5kbps"), 12500.0, "rate with unit")
    eq(parse_rate("3000"), 3000.0, "plain rate")


@test
def t_cli_rendering():
    eq(cli_line("PUT", "/ip/firewall/address-list", {"list": "mcc-blocked", "address": "1.2.3.4", "comment": "mcc: x y"}),
       '/ip firewall address-list add list=mcc-blocked address=1.2.3.4 comment="mcc: x y"', "add")
    eq(cli_line("PATCH", "/interface/*3", {"disabled": "true"}, "ether3"), "/interface set ether3 disabled=yes", "set")
    eq(cli_line("DELETE", "/ip/firewall/raw/*A"), "/ip firewall raw remove [find .id=*A]", "remove")
    eq(cli_line("POST", "/ip/traffic-flow/set", {"enabled": "yes"}), "/ip traffic-flow set enabled=yes", "singleton set")


@test
def t_swos_parse():
    d = parse_js("{en:0x3ff,lnk:0x5,nm:['506f727431','7366702b31'],spd:[0x02,0x03],x:[1,-2,3.5],s:\"q\"}")
    eq(d["en"], 0x3FF, "hex int")
    eq([hexstr(n) for n in d["nm"]], ["Port1", "sfp+1"], "hex names")
    eq(d["x"], [1, -2, 3.5], "numbers")
    try:
        parse_js("{en:0x3ff,")
        raise AssertionError("truncated data should fail")
    except SwOSError:
        pass


@test
def t_swos_reader_digest():
    w = sim.World(script=False)
    srv = sim.serve(sim.make_swos(w, password="pw"))
    try:
        host = "127.0.0.1:{}".format(srv.server_address[1])
        data = SwOS(host, "admin", "pw").read()
        eq(len(data["ports"]), 9, "port count")
        eq(data["ports"][1]["name"], "sfp1", "decoded name")
        eq(data["ports"][1]["speed"], "10G", "speed code")
        eq(data["sys"]["model"], "CRS309-1G-8S+", "model")
        ok(data["ports"][6]["link"] is False, "sfp6 has no link")
        try:
            SwOS(host, "admin", "wrong").read()
            raise AssertionError("bad password accepted")
        except SwOSError as e:
            ok("refused" in str(e), "clear auth error: {}".format(e))
    finally:
        srv.shutdown()


def _v5(flows):
    hdr = struct.pack("!HHIIIIBBH", 5, len(flows), 1000, int(time.time()), 0, 1, 0, 0, 0)
    body = b""
    for src, dst, sport, dport, proto, flags, nbytes, pkts in flows:
        body += struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", ipaddress.IPv4Address(src).packed,
                            ipaddress.IPv4Address(dst).packed, b"\0" * 4, 1, 2, pkts, nbytes, 100, 900,
                            sport, dport, 0, flags, proto, 0, 0, 0, 24, 24, 0)
    return hdr + body


@test
def t_flow_parsing():
    p = FlowParser()
    f = p.parse(_v5([("192.168.1.2", "8.8.8.8", 5555, 53, 17, 0, 120, 1)]), "r")
    eq((f[0]["src"], f[0]["dport"], f[0]["proto"], f[0]["bytes"]), ("192.168.1.2", 53, 17, 120), "v5 record")
    eq(round(f[0]["duration"], 1), 0.8, "v5 duration")
    # IPFIX exactly as the simulator (and RouterOS) sends it: template in the first packet only
    w = sim.World(script=False)
    pkt1 = w.ipfix([{"src": "203.0.113.5", "dst": "198.51.100.2", "sport": 4444, "dport": 22, "proto": 6,
                     "flags": 2, "bytes": 44, "packets": 1}], time.time())
    pkt2 = w.ipfix([{"src": "192.168.88.10", "dst": "52.216.8.1", "sport": 50000, "dport": 443, "proto": 6,
                     "flags": 0x1A, "bytes": 10 ** 9, "packets": 700000}], time.time())
    p2 = FlowParser()
    a = p2.parse(pkt1, "r")
    b = p2.parse(pkt2, "r")
    eq((a[0]["src"], a[0]["dport"], a[0]["flags"]), ("203.0.113.5", 22, 2), "ipfix record via template")
    eq(b[0]["bytes"], 10 ** 9, "64-bit counters")
    # data before its template is counted, not crashed on
    p3 = FlowParser()
    eq(p3.parse(pkt2, "r"), [], "no template yet")
    eq(p3.waiting, 1, "waiting counter")
    # NetFlow v9
    tmpl = struct.pack("!HH", 300, 4) + struct.pack("!HHHHHHHH", 8, 4, 12, 4, 11, 2, 1, 4)
    data = ipaddress.IPv4Address("10.0.0.1").packed + ipaddress.IPv4Address("1.1.1.1").packed + struct.pack("!HI", 443, 999)
    v9 = struct.pack("!HHIIII", 9, 2, 0, 0, 1, 7) + struct.pack("!HH", 0, 4 + len(tmpl)) + tmpl + \
        struct.pack("!HH", 300, 4 + len(data)) + data
    r = FlowParser().parse(v9, "r")
    eq((r[0]["src"], r[0]["dst"], r[0]["dport"], r[0]["bytes"]), ("10.0.0.1", "1.1.1.1", 443, 999), "v9")
    for bad in (b"\x00", b"\x00\x07" + b"\x00" * 30):
        try:
            FlowParser().parse(bad, "r")
            raise AssertionError("malformed packet accepted")
        except ValueError:
            pass


@test
def t_syslog_parsing():
    t, m = split_syslog(b"<134>firewall,info MCC-IN input: in:ether1 out:(unknown 0), connection-state:new src-mac "
                        b"64:d1:54:aa:bb:cc, proto TCP (SYN), 203.0.113.9:51515->198.51.100.2:22, len 60")
    eq(t, "firewall,info", "topics")
    c = classify(t, m)
    eq((c["kind"], c["prefix"], c["chain"], c["src"], c["dport"], c["flags"]),
       ("fw", "MCC-IN", "input", "203.0.113.9", 22, "SYN"), "firewall line")
    t, m = split_syslog(b"<30>Oct  5 12:00:00 MikroTik system,error,critical login failure for user admin from "
                        b"203.0.113.7 via winbox")
    eq(t, "system,error,critical", "BSD format with hostname")
    c = classify(t, m)
    eq((c["kind"], c["user"], c["src"], c["via"]), ("login_fail", "admin", "203.0.113.7", "winbox"), "login failure")
    eq(classify("interface,info", "ether3 link down")["kind"], "link", "link")
    icmp = classify("firewall,info", "input: in:ether1 out:(unknown 0), proto ICMP (type 8, code 0), 1.2.3.4->5.6.7.8, len 84")
    eq((icmp["src"], icmp["dport"]), ("1.2.3.4", 0), "ICMP has no ports")


# ============================================================================================
# traffic + detection
# ============================================================================================
def _model():
    return TrafficModel(lambda: [ipaddress.ip_network("192.168.88.0/24")], lambda: {"198.51.100.2", "192.168.88.1"},
                        lambda ip: "")


@test
def t_traffic_orientation():
    m = _model()
    rows = m.ingest_conns([
        {".id": "*1", "src-address": "192.168.88.10:5000", "dst-address": "52.216.8.1:443",
         "reply-src-address": "52.216.8.1:443", "protocol": "tcp", "orig-rate": "8000000", "repl-rate": "1000"},
        {".id": "*2", "src-address": "203.0.113.5:40000", "dst-address": "198.51.100.2:22",
         "reply-src-address": "192.168.88.70:22", "protocol": "tcp", "orig-rate": "2000", "repl-rate": "500000"},
    ])
    eq((rows[0]["local"], rows[0]["dir"], rows[0]["up"]), ("192.168.88.10", "out", 8e6), "outbound: orig = upload")
    eq((rows[1]["local"], rows[1]["remote"], rows[1]["dir"]), ("192.168.88.70", "203.0.113.5", "in"),
       "dst-nat'ed inbound maps to the internal server")
    eq(rows[1]["up"], 500000.0, "inbound: reply = upload")
    snap = m.snapshot()
    eq(snap["source"], "conntrack", "live source")
    eq(round(snap["out_bps"]), 8500000, "total upload")
    # counters without rate fields -> deltas between polls
    m2 = _model()
    base = {".id": "*9", "src-address": "192.168.88.5:1", "dst-address": "1.1.1.1:443", "protocol": "tcp"}
    m2.ingest_conns([dict(base, **{"orig-bytes": "0", "repl-bytes": "0"})], now=100.0)
    r = m2.ingest_conns([dict(base, **{"orig-bytes": "1000", "repl-bytes": "5000"})], now=102.0)
    eq((r[0]["up"], r[0]["down"]), (4000.0, 20000.0), "delta rates")


def _detector(tmp, **detect):
    cfg = Config(tmp)
    cfg.update({"detect": detect} if detect else {})
    (Path(tmp) / "bl.txt").write_text("192.0.2.66\n198.18.0.0/15\n", encoding="utf-8")
    events = []
    lan = ipaddress.ip_network("192.168.88.0/24")
    d = Detector(cfg, lambda ip: ipaddress.ip_address(ip) in lan, Path(tmp), events.append, Blocklist(Path(tmp) / "bl.txt"))
    return d, events


@test
def t_detect_scan_and_logins():
    tmp = tempfile.mkdtemp()
    try:
        d, _ = _detector(tmp)
        now = 1000.0
        for port in range(14):
            d.on_fw({"src": "203.0.113.9", "dst": "198.51.100.2", "dport": 1000 + port, "proto": "TCP"}, now + port)
        ok(not d.list(), "14 ports is below the threshold")
        d.on_fw({"src": "203.0.113.9", "dst": "198.51.100.2", "dport": 2000, "proto": "TCP"}, now + 15)
        t = d.list()[0]
        eq((t["rule"], t["subject"], t["role"]), ("scan", "203.0.113.9", "attacker"), "scan raised")
        eq(t["proposals"][0]["kind"], "block_ip", "suggests a block")
        for port in range(30):
            d.on_fw({"src": "203.0.113.9", "dst": "198.51.100.2", "dport": 3000 + port, "proto": "TCP"}, now + 16)
        eq(len([x for x in d.list() if x["rule"] == "scan"]), 1, "one threat per attacker, not one per packet")
        eq(d.list()[0]["severity"], "high", "escalates with volume")
        for i in range(5):
            d.on_login("203.0.113.77", "admin", "winbox", False, now + i)
        lg = next(x for x in d.list() if x["rule"] == "login")
        eq((lg["severity"], lg["role"]), ("critical", "attacker"), "external login guessing is critical")
        for i in range(5):
            d.on_login("192.168.88.40", "admin", "ssh", False, now + i)
        lan = next(x for x in d.list() if x["rule"] == "login" and x["subject"] == "192.168.88.40")
        eq((lan["severity"], lan["proposals"][0]["kind"]), ("high", "quarantine_host"), "a LAN host is quarantined, not blocked")
        eq(d.level(now + 10), "critical", "overall level")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@test
def t_detect_outbound_rules():
    tmp = tempfile.mkdtemp()
    try:
        d, _ = _detector(tmp, fanout_peers=20, worm_dsts=10)
        now = 1000.0
        base = {"local": "192.168.88.50", "dir": "out", "proto_name": "TCP", "flags": 0x1A, "bytes": 100,
                "packets": 2, "duration": 1.0, "src": "192.168.88.50"}
        for i in range(10):
            d.on_flow(dict(base, dst="45.{}.1.1".format(i), remote="45.{}.1.1".format(i), sport=40000 + i, dport=23), now)
        rules = {t["rule"] for t in d.list()}
        ok("worm" in rules, "10 telnet destinations -> worm: {}".format(rules))
        ok("watchport" in rules, "telnet is a watched port")
        for i in range(20):
            d.on_flow(dict(base, dst="46.{}.1.1".format(i), remote="46.{}.1.1".format(i), sport=41000 + i, dport=443), now)
        ok(any(t["rule"] == "fanout" for t in d.list()), "fan-out")
        d.on_flow(dict(base, src="192.168.88.20", local="192.168.88.20", dst="192.0.2.66", remote="192.0.2.66",
                       sport=50000, dport=443), now)
        bl = next(t for t in d.list() if t["rule"] == "blocklist")
        eq((bl["severity"], bl["subject"]), ("critical", "192.168.88.20"), "blocklisted destination")
        eq([p["kind"] for p in bl["proposals"]], ["block_ip", "quarantine_host", "kill_connections"], "three suggestions")
        # reply traffic from a server isn't a scan of our ephemeral ports
        for i in range(40):
            d.on_flow({"src": "142.250.1.1", "dst": "192.168.88.30", "local": "192.168.88.30", "remote": "142.250.1.1",
                       "dir": "in", "proto_name": "TCP", "flags": 0x18, "sport": 443, "dport": 50000 + i,
                       "bytes": 9000, "packets": 9, "duration": 2.0}, now)
        ok(not any(t["rule"] == "scan" for t in d.list()), "replies don't look like a scan")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@test
def t_detect_state_rules():
    tmp = tempfile.mkdtemp()
    try:
        d, _ = _detector(tmp, quiet_s=60)
        d.on_devices([{"mac": "AA:00:00:00:00:01", "ip": "192.168.88.5"}], 1.0)
        ok(not d.list(), "first poll is the baseline")
        d.on_devices([{"mac": "AA:00:00:00:00:01", "ip": "192.168.88.5"}, {"mac": "AA:00:00:00:00:02", "ip": "192.168.88.6"}], 2.0)
        nd = d.list()[0]
        eq((nd["rule"], nd["target"]), ("new_device", "AA:00:00:00:00:02"), "new device")
        ok(d.mark_known("aa:00:00:00:00:02"), "mark known")
        eq(d.threats[nd["id"]]["status"], "resolved", "marking known resolves it")
        d.on_links("router", {"ether3": {"up": True}}, 10.0)
        d.on_links("router", {"ether3": {"up": False}}, 12.0)
        ld = next(t for t in d.list() if t["rule"] == "link_down")
        eq(ld["status"], "open", "link down")
        d.on_links("router", {"ether3": {"up": True}}, 14.0)
        eq(d.threats[ld["id"]]["status"], "resolved", "link back up resolves it")
        d.on_links("router", {"ether4": {"up": True}}, 10.0)
        d.on_links("router", {"ether4": {"up": False, "disabled": True}}, 12.0)
        ok(not any(t["key"] == "router:ether4" for t in d.list()), "disabling a port isn't a link failure")
        for p in range(15):
            d.on_fw({"src": "203.0.113.1", "dst": "198.51.100.2", "dport": p + 1, "proto": "TCP"}, 100.0)
        d.tick(100.0 + 61)
        sc = next(t for t in d.list() if t["rule"] == "scan")
        eq(sc["status"], "quiet", "goes quiet after quiet_s")
        # history survives a restart, but nothing stays 'open' that MCC wasn't watching
        d.on_fw({"src": "203.0.113.1", "dst": "198.51.100.2", "dport": 99, "proto": "TCP"}, 200.0)
        d2, _ = _detector(tmp, quiet_s=60)
        ok(d2.threats, "threats reloaded")
        ok(all(t["status"] != "open" for t in d2.threats.values()), "reloaded threats are not open")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@test
def t_ignore_false_positives():
    tmp = tempfile.mkdtemp()
    try:
        d, events = _detector(tmp, fanout_peers=5)
        now = time.time()

        def scan(src, base, n=15):
            for p in range(n):
                d.on_fw({"src": src, "dst": "198.51.100.2", "dport": base + p, "proto": "TCP"}, now)

        scan("203.0.113.9", 1000)
        t = next(x for x in d.list() if x["rule"] == "scan")
        # exact: this rule + this key
        sup = d.suppress(rule="scan", scope="exact", key=t["key"], note="our own pentest box", threat_id=t["id"])
        eq(d.threats[t["id"]]["status"], "ignored", "the threat it came from is set aside")
        eq(d.threats[t["id"]]["ignored_by"], sup["id"], "linked to the rule")
        n_events = len(events)
        scan("203.0.113.9", 5000, 30)
        eq(d.threats[t["id"]]["status"], "ignored", "recurrence stays ignored")
        eq(len(events), n_events, "nothing raised or published")
        ok(d.suppressions[0]["hits"] >= 30, "silenced events are counted")
        eq(d.level(now), "calm", "ignored threats don't raise the threat level")
        ok("203.0.113.9" not in d.subject_threats(), "nor mark the address on the map")
        scan("203.0.113.10", 1000)
        ok(any(x["subject"] == "203.0.113.10" and x["status"] == "open" for x in d.list()),
           "an exact ignore doesn't cover another address")
        for i in range(5):
            d.on_login("203.0.113.9", "admin", "ssh", False, now + i)
        ok(any(x["rule"] == "login" and x["subject"] == "203.0.113.9" for x in d.list()),
           "nor another rule for the same address")
        # subject: one rule, anything involving a network
        d.suppress(rule="fanout", scope="subject", subject="192.168.88.0/28", note="backup clients")
        base = {"dir": "out", "proto_name": "TCP", "flags": 0x1A, "bytes": 100, "packets": 2, "duration": 1.0}
        for i in range(6):
            d.on_flow(dict(base, src="192.168.88.5", local="192.168.88.5", dst="45.0.0.{}".format(i),
                           remote="45.0.0.{}".format(i), sport=40000 + i, dport=443), now)
        ok(not any(x["rule"] == "fanout" for x in d.list()), "network-wide subject ignore covers the host")
        # subject_any: every rule for an address
        d.suppress(rule="*", scope="subject_any", subject="203.0.113.10", note="trusted")
        eq(next(x for x in d.list() if x["subject"] == "203.0.113.10")["status"], "ignored", "existing threats set aside")
        # validation
        for bad in ({"rule": "scan", "scope": "exact"}, {"rule": "scan", "scope": "subject", "subject": "nope"},
                    {"rule": "nope", "scope": "subject", "subject": "1.2.3.4"},
                    {"rule": "scan", "scope": "everything", "subject": "1.2.3.4"},
                    {"rule": "scan", "scope": "subject", "subject": "1.2.3.4", "duration": "1y"}):
            try:
                d.suppress(**bad)
                raise AssertionError("accepted {}".format(bad))
            except ValueError:
                pass
        # rules persist, removal makes it alert again
        d2, _ = _detector(tmp, fanout_peers=5)
        eq(len(d2.suppressions), 3, "ignore rules survive a restart")
        d2.unsuppress(sup["id"])
        eq(d2.threats[t["id"]]["status"], "resolved", "removing the rule un-ignores its threat")
        scan_d2 = lambda: [d2.on_fw({"src": "203.0.113.9", "dst": "198.51.100.2", "dport": 7000 + p, "proto": "TCP"}, now)
                           for p in range(15)]
        scan_d2()
        eq(d2.threats[t["id"]]["status"], "open", "and it alerts again when it recurs")
        # expiry
        x = d2.suppress(rule="scan", scope="subject", subject="203.0.113.50", duration="24h")
        d2.suppressions[-1]["expires"] = time.time() - 1
        d2.tick()
        ok(all(s["id"] != x["id"] for s in d2.suppressions), "expired rules are dropped")
        log = (Path(tmp) / "ignore.log.jsonl").read_text(encoding="utf-8")
        ok('"added"' in log and '"removed"' in log and '"expired"' in log, "every change is logged")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _mmdb_bytes(prefixes):
    """A minimal MaxMind DB (IPv4 tree, 24-bit records) for the reader tests.
    prefixes: [(cidr, record dict | ('ptr', index of an earlier record))]"""
    def hdr(typ, size):
        out = bytes([(typ << 5 if typ <= 7 else 0) | (size if size < 29 else 29)])
        if typ > 7:
            out += bytes([typ - 7])
        if size >= 29:
            out += bytes([size - 29])
        return out

    def enc(v):
        if isinstance(v, bool):
            return hdr(14, int(v))
        if isinstance(v, dict):
            return hdr(7, len(v)) + b"".join(enc(k) + enc(x) for k, x in v.items())
        if isinstance(v, str):
            b = v.encode()
            return hdr(2, len(b)) + b
        if isinstance(v, float):
            return hdr(3, 8) + struct.pack(">d", v)
        if isinstance(v, int):
            b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
            return hdr(6, len(b)) + b
        if isinstance(v, list):
            return hdr(11, len(v)) + b"".join(enc(x) for x in v)
        raise TypeError(v)

    data, offsets = b"", []
    for _, rec in prefixes:
        offsets.append(len(data))
        if isinstance(rec, tuple):  # a pointer to an earlier record (exercises pointer decoding)
            data += bytes([0x20 | 0x00, offsets[rec[1]]]) if offsets[rec[1]] < 256 else b""
        else:
            data += enc(rec)
    nodes = [[None, None]]
    for i, (cidr, _) in enumerate(prefixes):
        net = ipaddress.ip_network(cidr)
        bits = int(net.network_address)
        node = 0
        for k in range(net.prefixlen):
            bit = (bits >> (31 - k)) & 1
            if k == net.prefixlen - 1:
                nodes[node][bit] = ("data", offsets[i])
            else:
                if not isinstance(nodes[node][bit], int):
                    nodes.append([None, None])
                    nodes[node][bit] = len(nodes) - 1
                node = nodes[node][bit]
    n = len(nodes)

    def rec(v):
        if v is None:
            return n
        if isinstance(v, tuple):
            return n + 16 + v[1]
        return v
    tree = b"".join(rec(l).to_bytes(3, "big") + rec(r).to_bytes(3, "big") for l, r in nodes)
    meta = enc({"node_count": n, "record_size": 24, "ip_version": 4, "database_type": "Test-City",
                "build_epoch": 1790000000, "description": {"en": "test db"}, "languages": ["en"],
                "binary_format_major_version": 2, "binary_format_minor_version": 0})
    return tree + b"\x00" * 16 + data + b"\xab\xcd\xefMaxMind.com" + meta


@test
def t_geo_reader_and_locator():
    from mcc.geo import MMDB, Geo, normalise
    tmp = Path(tempfile.mkdtemp())
    try:
        city = {"city": {"names": {"en": "Ashburn"}}, "country": {"iso_code": "US", "names": {"en": "United States"}},
                "location": {"latitude": 39.04, "longitude": -77.49}, "subdivisions": [{"names": {"en": "Virginia"}}]}
        (tmp / "geo").mkdir()
        db_path = tmp / "geo" / "test-city.mmdb"
        db_path.write_bytes(_mmdb_bytes([("52.216.0.0/16", city), ("45.57.0.0/16", {"country": {"iso_code": "DE"}}),
                                         ("17.0.0.0/8", ("ptr", 0))]))
        db = MMDB(db_path)
        eq(db.meta["database_type"], "Test-City", "metadata")
        g = normalise(db.lookup("52.216.8.1"))
        eq((g["city"], g["cc"], g["region"], g["lat"], g["precision"]), ("Ashburn", "US", "Virginia", 39.04, "city"),
           "city record")
        de = normalise(db.lookup("45.57.40.1"))
        eq((de["cc"], de["country"], de["precision"]), ("DE", "Germany", "country"), "country-only -> label point")
        eq(normalise(db.lookup("17.253.144.10"))["city"], "Ashburn", "pointer record decoded")
        eq(db.lookup("8.8.8.8"), None, "not in the database")
        ipinfo = normalise({"country_code": "JP", "country": "Japan", "asn": "AS2497"})
        eq((ipinfo["cc"], ipinfo["precision"]), ("JP", "country"), "IPinfo-style record")
        try:
            bad = tmp / "bad.mmdb"
            bad.write_bytes(b"not a database")
            MMDB(bad)
            raise AssertionError("garbage accepted")
        except Exception as e:
            ok("MaxMind" in str(e), "clear error for a non-mmdb file")

        cfg = Config(tmp)
        geo = Geo(cfg, tmp)
        ok(geo.db is not None, "newest .mmdb in data/geo is picked up")
        eq(geo.locate("192.168.1.5"), None, "LAN addresses are never looked up")
        eq(geo.locate("52.216.8.1")["city"], "Ashburn", "locate")
        ok("52.216.8.1" in geo.cache, "cached")
        eq(geo.home(["52.216.1.1"])["source"], "router's public address", "home from the WAN address")
        cfg.update({"geo": {"home": {"lat": 51.5, "lon": -0.12, "label": "London"}}})
        eq(geo.home(["52.216.1.1"])["label"], "London", "home override wins")
        geo2 = Geo(Config(tmp / "empty"), tmp / "empty", demo=sim.demo_geo)
        eq(geo2.locate("45.57.40.1")["city"], "Chicago", "demo fallback without a database")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@test
def t_geo_download():
    """The opt-in database download, against a local stand-in for download.db-ip.com."""
    import gzip
    import http.server
    import mcc.geo as geomod
    tmp = Path(tempfile.mkdtemp())
    payload = gzip.compress(_mmdb_bytes([("52.216.0.0/16", {"country": {"iso_code": "US"}})]))
    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            hits.append(self.path)
            if "city" in self.path and len(hits) == 1:  # this month's file isn't out yet -> falls back a month
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    old = geomod.DBIP_URL
    geomod.DBIP_URL = "http://127.0.0.1:%d/dbip-{edition}-lite-{month}.mmdb.gz" % srv.server_address[1]
    try:
        geo = geomod.Geo(Config(tmp), tmp)
        eq(geo.db, None, "no database to start with")
        done = []
        geo.start_download("city", on_done=lambda: done.append(1))
        ok(wait_for(lambda: geo.download["state"] in ("done", "error"), 10), "download finishes")
        eq(geo.download["state"], "done", "installed: {}".format(geo.download.get("error")))
        eq(len(hits), 2, "tried this month, fell back to last month")
        ok((tmp / "geo" / "dbip-city-lite.mmdb").exists() and geo.db is not None, "loaded")
        eq(geo.locate("52.216.8.1")["cc"], "US", "lookups work right away")
        ok(done, "callback fired")
        ok(not list((tmp / "geo").glob("*.part")), "temp files cleaned up")
        try:
            geo.start_download("planet")
            raise AssertionError("bad edition")
        except ValueError:
            pass
    finally:
        geomod.DBIP_URL = old
        srv.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@test
def t_geo_in_snapshot():
    with Env() as e:
        e.hub.geo.demo = sim.demo_geo
        snap = wait_for(lambda: (lambda s: s if s["traffic"]["peers"] else None)(e.hub.snapshot()), 10)
        g = snap["geo"]
        eq((g["home"]["city"], g["source"]), ("Dallas", "demo"), "home located from the router's public address")
        ok(g["located"] == g["peers"] > 0, "every peer located")
        ok(all(p["geo"] for p in snap["traffic"]["peers"]), "peers carry their location")
        ok(g["countries"] and g["countries"][0]["cc"] == "US", "rolled up by country")
        eq(e.hub.host_view("45.57.40.1")["geo"]["city"], "Chicago", "host drawer gets the location")


@test
def t_blocklist():
    tmp = Path(tempfile.mkdtemp())
    try:
        p = tmp / "bl.txt"
        p.write_text("# comment\n1.2.3.4\n10.20.0.0/16 ; spamhaus\n2001:db8::/32\nnonsense\n", encoding="utf-8")
        b = Blocklist(p)
        ok(b.contains("1.2.3.4") and b.contains("10.20.99.1") and b.contains("2001:db8::5"), "matches")
        ok(not b.contains("10.21.0.1") and not b.contains("1.2.3.5"), "non-matches")
        eq(b.count, 3, "bad lines skipped")
        time.sleep(0.05)
        p.write_text("9.9.9.9\n", encoding="utf-8")
        import os
        os.utime(p, (time.time() + 5, time.time() + 5))
        ok(b.contains("9.9.9.9") and not b.contains("1.2.3.4"), "reloads when the file changes")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================================================
# router client + actions
# ============================================================================================
@test
def t_routeros_client():
    w = sim.World(script=False)
    srv = sim.serve(sim.make_router(w))
    try:
        port = srv.server_address[1]
        ros = RouterOS("127.0.0.1", "admin", "demo", "http", port)
        eq(ros.get("/system/identity")["name"], "core-router", "GET")
        added = ros.add("/ip/firewall/address-list", {"list": "x", "address": "1.2.3.4"})
        ok(added[".id"].startswith("*"), "PUT returns .id")
        eq(len(ros.get_list("/ip/firewall/address-list", {"list": "x"})), 1, "query filter")
        ros.remove("/ip/firewall/address-list", added[".id"])
        try:
            ros.remove("/ip/firewall/address-list", added[".id"])
            raise AssertionError("second delete should 404")
        except RouterOSError as e:
            eq(e.status, 404, "404 status")
        try:
            RouterOS("127.0.0.1", "admin", "nope", "http", port).get("/system/identity")
            raise AssertionError("bad password accepted")
        except RouterOSError as e:
            eq(e.status, 401, "401 status")
        try:
            RouterOS("127.0.0.1", "admin", "demo", "http", 1).get("/system/identity")
            raise AssertionError("unreachable router accepted")
        except RouterOSError as e:
            ok("cannot reach" in str(e), "clear unreachable error")
    finally:
        srv.shutdown()


@test
def t_actions_block_confirm_undo():
    with Env() as e:
        a = e.hub.actions.propose("block_ip", {"ip": "203.0.113.50", "timeout": "1h"}, "test")
        eq(a["status"], "pending", "proposal is pending")
        eq(len(e.world.tables["/ip/firewall/address-list"]), 0, "proposing changes nothing")
        methods = [c["method"] for c in a["changes"]]
        eq(methods, ["PUT", "PUT", "PUT"], "two one-time drop rules + the entry")
        ok(all(c["cli"].startswith("/ip firewall") for c in a["changes"]), "terminal equivalents")
        ok("(A" in a["changes"][-1]["body"]["comment"], "entry comment carries the action id")
        done = e.hub.actions.confirm(a["id"])
        eq(done["status"], "done", "confirmed")
        ok(e.world.blocked("203.0.113.50"), "the simulated router now drops it")
        try:
            e.hub.actions.confirm(a["id"])
            raise AssertionError("confirm twice")
        except ActionError:
            pass
        try:
            e.hub.actions.propose("block_ip", {"ip": "203.0.113.50"})
            raise AssertionError("double block")
        except ActionError as err:
            ok("already" in str(err), "already blocked")
        b = e.hub.actions.propose("block_ip", {"ip": "203.0.113.51", "timeout": "15m"})
        eq(len(b["changes"]), 1, "drop rules aren't proposed again")
        u = e.hub.actions.undo(a["id"])
        eq(u["status"], "undone", "undone")
        ok(not e.world.blocked("203.0.113.50"), "entry removed")
        ok(any(r.get("src-address-list") == "mcc-blocked" for r in e.world.tables["/ip/firewall/raw"]),
           "one-time drop rules stay after undo")
        e.hub.actions.dismiss(b["id"])
        eq(e.hub.actions.items[b["id"]]["status"], "dismissed", "dismissed")
        log = (e.dir / "actions.jsonl").read_text(encoding="utf-8").splitlines()
        events = [json.loads(x)["history"][-1]["event"] for x in log]
        for ev in ("proposed", "executed", "undone", "dismissed"):
            ok(ev in events, "audit log has {}".format(ev))


@test
def t_actions_guards():
    with Env() as e:
        e.cfg.update({"never_block": ["9.9.9.0/24"]})
        for ip, why in (("198.51.100.1", "gateway"), ("192.168.88.1", "router's own"), ("198.51.100.2", "router's own"),
                        ("127.0.0.1", "Refusing"), ("9.9.9.9", "never-block"), ("nonsense", "not an IP")):
            try:
                e.hub.actions.propose("block_ip", {"ip": ip})
                raise AssertionError("{} should be refused".format(ip))
            except ActionError as err:
                ok(why in str(err), "{} refused for the right reason: {}".format(ip, err))
        try:
            e.hub.actions.propose("quarantine_host", {"ip": "203.0.113.5"})
            raise AssertionError("quarantine of an Internet host")
        except ActionError as err:
            ok("isn't on your LAN" in str(err), "quarantine is LAN-only")
        try:
            e.hub.actions.propose("block_ip", {"ip": "1.2.3.4", "timeout": "3y"})
            raise AssertionError("bad timeout")
        except ActionError:
            pass
        wan = e.hub.actions.propose("disable_interface", {"name": "ether1"})
        ok(any("Internet uplink" in w for w in wan["warnings"]), "WAN warning")
        try:
            e.hub.actions.propose("disable_interface", {"name": "ether99"})
            raise AssertionError("unknown interface")
        except ActionError:
            pass


@test
def t_actions_interface_and_kill():
    with Env() as e:
        wait_for(lambda: any(c["_host"] == "192.168.88.30" for c in e.world.conns.values()), 5)
        a = e.hub.actions.propose("disable_interface", {"name": "ether3"})
        e.hub.actions.confirm(a["id"])
        ok(not e.world.iface_up("ether3"), "interface disabled")
        e.hub.actions.undo(a["id"])
        ok(e.world.iface_up("ether3"), "undo re-enables it")
        k = e.hub.actions.propose("kill_connections", {"ip": "192.168.88.20"})
        eq(k["undo"]["possible"], False, "kills can't be undone")
        n_before = sum(1 for c in e.world.conns.values() if c["_host"] == "192.168.88.20")
        ok(n_before > 0, "host had connections")
        r = e.hub.actions.confirm(k["id"])
        ok("dropped" in r["steps"][0]["result"], "reports how many were dropped")
        q = e.hub.actions.propose("quarantine_host", {"ip": "192.168.88.50", "timeout": "15m"})
        e.hub.actions.confirm(q["id"])
        ok(e.world.quarantined("192.168.88.50"), "quarantined")
        rm = e.hub.actions.propose("remove_entry", {"ip": "192.168.88.50", "list": "mcc-quarantine"})
        e.hub.actions.confirm(rm["id"])
        ok(not e.world.quarantined("192.168.88.50"), "released")
        e.hub.actions.undo(rm["id"])
        ok(e.world._listed("192.168.88.50", "mcc-quarantine"), "undoing a release puts it back")
        # pending proposals don't survive a restart
        p = e.hub.actions.propose("block_ip", {"ip": "203.0.113.99"})
        from mcc.actions import ActionEngine
        again = ActionEngine(e.hub, e.dir)
        eq(again.items[p["id"]]["status"], "expired", "pending -> expired after restart")


@test
def t_mitigation_marks_threats():
    with Env() as e:
        t = e.hub.detector.raise_threat("scan", "203.0.113.8", "high", "Port scan", "x", time.time(),
                                        subject="203.0.113.8", role="attacker")
        a = e.hub.actions.propose("block_ip", {"ip": "203.0.113.8"}, "scan", t["id"])
        e.hub.actions.confirm(a["id"])
        eq(e.hub.detector.threats[t["id"]]["status"], "mitigated", "threat marked mitigated")
        ok(a["id"] in e.hub.detector.threats[t["id"]]["mitigated_by"], "linked to the action")


# ============================================================================================
# setup plan
# ============================================================================================
@test
def t_setup_plan_apply_remove():
    with Env() as e:
        plan = e.hub.setup.plan()
        eq([i["id"] for i in plan["items"]], ["flows", "syslog", "logrules", "droprules"], "items")
        ok(all(i["status"] == "missing" for i in plan["items"]), "fresh router: all missing")
        ok(not e.world.flows_on(), "planning changes nothing")
        try:
            e.hub.setup.apply("nope", ["flows"])
            raise AssertionError("unknown plan accepted")
        except RouterOSError as err:
            ok("out of date" in str(err), "stale plan refused")
        res = e.hub.setup.apply(plan["id"], ["flows", "syslog"])
        ok(all(r["ok"] for r in res["results"]), "applied")
        ok(e.world.flows_on(), "flow export on")
        ok(not e.world.log_rules(), "unselected items untouched")
        try:
            e.hub.setup.apply(plan["id"], ["logrules"])
            raise AssertionError("plan reused")
        except RouterOSError:
            pass
        st = {i["id"]: i["status"] for i in e.hub.setup.plan()["items"]}
        eq((st["flows"], st["syslog"], st["logrules"]), ("installed", "installed", "missing"), "re-plan")
        # telemetry now actually arrives
        ok(wait_for(lambda: e.hub.flow_col.packets > 0, 12), "IPFIX received")
        e.world.log("system,error,critical", "login failure for user admin from 203.0.113.3 via ssh")
        ok(wait_for(lambda: e.hub.syslog_col.packets > 0, 5), "syslog received")
        rp = e.hub.setup.removal_plan()
        ok(rp["items"][0]["changes"], "removal has changes")
        e.hub.setup.apply(rp["id"], ["remove"])
        ok(not e.world.tables["/ip/traffic-flow/target"], "flow target removed")
        eq(e.world.single["/ip/traffic-flow"]["enabled"], "false", "traffic-flow restored to off")
        ok(not [r for r in e.world.tables["/system/logging"] if r.get("action") == "mcc"], "logging rules removed")


@test
def t_collector_rejects_strangers():
    with Env() as e:
        e.hub.router_host_ip = "10.99.99.99"  # pretend the router is elsewhere; 127.0.0.1 is now a stranger
        e.hub.router_addrs = set()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"<134>firewall,info fake", ("127.0.0.1", e.hub.syslog_col.port))
        ok(wait_for(lambda: e.hub.syslog_col.rejected.get("127.0.0.1"), 3), "stranger rejected and counted")
        eq(e.hub.syslog_col.packets, 0, "nothing accepted")
        e.cfg.update({"collectors": {"accept_from": ["127.0.0.1"]}})
        s.sendto(b"<134>firewall,info hello", ("127.0.0.1", e.hub.syslog_col.port))
        ok(wait_for(lambda: e.hub.syslog_col.packets == 1, 3), "accepted once allowed")
        s.sendto(b"\x00\x0a garbage", ("127.0.0.1", e.hub.flow_col.port))
        e.cfg.update({"collectors": {"accept_from": ["127.0.0.1"]}})
        ok(wait_for(lambda: e.hub.flow_col.errors == 1, 3), "malformed flow packet counted as an error")
        ok(e.hub.flow_col.is_alive(), "listener survives garbage")
        s.close()


# ============================================================================================
# end to end: hub + simulated incidents
# ============================================================================================
@test
def t_e2e_detect_and_block():
    with Env() as e:
        plan = e.hub.setup.plan()
        e.hub.setup.apply(plan["id"], [i["id"] for i in plan["items"]])
        snap = wait_for(lambda: (lambda s: s if s["traffic"]["hosts"] else None)(e.hub.snapshot()), 10)
        ok(snap, "traffic visible")
        eq(snap["traffic"]["source"], "conntrack", "live from the connection table")
        ok(snap["wan"]["names"] == ["ether1"], "WAN detected from the interface list")
        ok(snap["router"]["board"] == "RB5009UG+S+", "router resource")
        # stage a scan: the world logs it through the MCC-IN rule and exports SYN-only flows
        attacker = "192.0.2.201"
        for i in range(40):
            e.world.lock.acquire()
            try:
                e.world._fwlog("input", attacker, 40000 + i, sim.WAN_IP, 1000 + i)
                e.world._flow(attacker, sim.WAN_IP, 40000 + i, 1000 + i, 6, 0x02, 44, 1)
            finally:
                e.world.lock.release()
        t = wait_for(lambda: next((x for x in e.hub.detector.list() if x["rule"] == "scan" and x["subject"] == attacker), None), 10)
        ok(t, "scan detected from live telemetry")
        a = e.hub.actions.propose(t["proposals"][0]["kind"], t["proposals"][0]["params"], t["title"], t["id"])
        e.hub.actions.confirm(a["id"])
        ok(e.world.blocked(attacker), "attacker blocked on the router")
        ok(wait_for(lambda: attacker in e.hub.blocked, 20), "hub sees the block")
        n = e.hub.detector.threats[t["id"]]["count"]
        e.world.lock.acquire()
        try:
            for i in range(20):
                if not e.world.blocked(attacker):
                    e.world._fwlog("input", attacker, 41000 + i, sim.WAN_IP, 2000 + i)
        finally:
            e.world.lock.release()
        time.sleep(1.0)
        eq(e.hub.detector.threats[t["id"]]["status"], "mitigated", "threat stays mitigated")
        eq(e.hub.detector.threats[t["id"]]["count"], n, "no new hits after the block")
        # late flow records inside the grace window don't reopen it; real traffic after it does
        e.hub.detector.on_fw({"src": attacker, "dst": sim.WAN_IP, "dport": 9999, "proto": "TCP"})
        eq(e.hub.detector.threats[t["id"]]["status"], "mitigated", "late evidence ignored")
        e.hub.detector.threats[t["id"]]["mitigated_at"] -= 600
        for i in range(20):
            e.hub.detector.on_fw({"src": attacker, "dst": sim.WAN_IP, "dport": 5000 + i, "proto": "TCP"})
        eq(e.hub.detector.threats[t["id"]]["status"], "open", "a real recurrence reopens it")
        eq(e.hub.detector.threats[t["id"]]["reopened"], 1, "and says it came back")


@test
def t_e2e_scripted_incidents():
    """The demo's incident script, sped up: the conntrack/log-based rules fire with no setup at all."""
    with Env(script=True, speed=12) as e:
        want = {"bruteforce", "login", "worm", "blocklist", "new_device", "link_down", "watchport"}
        got = wait_for(lambda: (lambda r: r if want <= r else None)({t["rule"] for t in e.hub.detector.list()}), 40, 0.5)
        ok(got, "scripted incidents detected: {}".format(sorted({t["rule"] for t in e.hub.detector.list()})))


@test
def t_switch_polling():
    with Env() as e:
        e.hub.connect_switch("127.0.0.1:{}".format(e.switch.server_address[1]), "admin", "")
        ok(wait_for(lambda: any(p.get("rx_bps") for p in e.hub.switch_ports), 15), "switch port rates computed")
        e.world.sw_link[2] = False
        ok(wait_for(lambda: any(t["rule"] == "link_down" and "sfp2" in t["title"] for t in e.hub.detector.list()), 15),
           "switch port link loss detected")


@test
def t_switch_os_detection():
    """CRS switches run RouterOS or SwOS. Auto-detect must pick the right reader, and a switch that
    serves no SwOS files must be an error, not 'connected' with no ports (the reported bug)."""
    from mcc.rosswitch import detect_os
    with Env() as e:
        sw_world = sim.World(seed=9, script=False).start()
        ros_switch = sim.serve(sim.make_router(sw_world))  # a "switch" running RouterOS
        try:
            ros_host = "127.0.0.1:{}".format(ros_switch.server_address[1])
            swos_host = "127.0.0.1:{}".format(e.switch.server_address[1])
            eq(detect_os(ros_host), "routeros", "RouterOS answers REST with a JSON 401")
            eq(detect_os(swos_host), "swos", "SwOS asks for digest auth")
            eq(detect_os("127.0.0.1:1"), "unknown", "nothing listening")
            res = e.hub.connect_switch(ros_host, "admin", "demo")
            eq(res["kind"], "routeros", "auto-detected RouterOS")
            eq(e.hub.switch_status["kind"], "routeros", "status says RouterOS")
            names = [p["name"] for p in e.hub.switch_ports]
            eq(names, ["ether1", "ether2", "ether3", "ether4", "ether5", "sfp-sfpplus1"], "physical ports only, no bridge")
            sfp = e.hub.switch_ports[-1]
            eq((sfp["link"], sfp["speed"]), (True, "10G"), "link and rate from ethernet/monitor")
            ok(wait_for(lambda: any(p.get("rx_bps") for p in e.hub.switch_ports), 15), "port rates computed from counters")
            ok("RouterOS" in e.hub.switch_sys["version"], "model/version from the switch")
            probe = e.hub.swos.probe()
            ok(probe["os"] == "routeros" and isinstance(probe["/interface"], list), "probe shows the raw REST data")
            try:
                e.hub.connect_switch(ros_host, "admin", "wrong")
                raise AssertionError("bad switch password accepted")
            except SwOSError as err:
                ok("RouterOS" in str(err) and "refused" in str(err), "clear auth error: {}".format(err))
            try:
                e.hub.connect_switch(ros_host, "admin", "demo", kind="swos")
                raise AssertionError("forced SwOS on a RouterOS switch accepted")
            except SwOSError as err:
                ok("link.b" in str(err) and "RouterOS" in str(err), "missing SwOS files explained: {}".format(err))
            try:
                e.hub.connect_switch("127.0.0.1:1", "admin", "")
                raise AssertionError("unreachable switch accepted")
            except SwOSError as err:
                ok("couldn't reach" in str(err), "unreachable explained")
            eq(e.hub.connect_switch(swos_host, "admin", "")["kind"], "swos", "SwOS still works")
        finally:
            ros_switch.shutdown()
            sw_world.stop()


# ============================================================================================
# web server
# ============================================================================================
def _req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": "127.0.0.1:{}".format(port)}
    h.update(headers or {})
    data = json.dumps(body).encode() if body is not None else None
    if data:
        h["Content-Type"] = "application/json"
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    raw = r.read()
    c.close()
    try:
        return r.status, json.loads(raw), r
    except ValueError:
        return r.status, raw, r


@test
def t_server_security():
    with Env() as e:
        httpd, token = make_server(e.hub, "127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        port = httpd.server_address[1]
        try:
            eq(token, "", "no token on loopback")
            st, body, _ = _req(port, "GET", "/api/state")
            eq(st, 200, "state")
            ok("snapshot" in body and "threats" in body, "state payload")
            ok("password" not in json.dumps(body["config"]), "no password in config")
            st, _, _ = _req(port, "GET", "/api/state", headers={"Host": "evil.example:{}".format(port)})
            eq(st, 403, "foreign Host header (DNS rebinding) refused")
            st, _, _ = _req(port, "POST", "/api/actions/propose", {"kind": "block_ip", "params": {"ip": "1.2.3.4"}})
            eq(st, 403, "POST without X-MCC refused")
            st, _, _ = _req(port, "POST", "/api/actions/propose", {"kind": "block_ip", "params": {"ip": "1.2.3.4"}},
                            {"X-MCC": "1", "Origin": "http://evil.example"})
            eq(st, 403, "cross-origin POST refused")
            st, prop, _ = _req(port, "POST", "/api/actions/propose", {"kind": "block_ip", "params": {"ip": "1.2.3.4"}},
                               {"X-MCC": "1", "Origin": "http://127.0.0.1:{}".format(port)})
            eq(st, 200, "same-origin POST works")
            st, _, _ = _req(port, "POST", "/api/actions/{}/confirm".format(prop["id"]), {}, {"X-MCC": "1"})
            eq(st, 400, "confirm needs an explicit confirm:true")
            ok(not e.world.blocked("1.2.3.4"), "still not blocked")
            st, err, _ = _req(port, "POST", "/api/settings", {"lan_networks": ["not-a-net"]}, {"X-MCC": "1"})
            eq(st, 400, "bad settings refused")
            st, _, _ = _req(port, "POST", "/api/settings", {"detect": {"nope": 1}}, {"X-MCC": "1"})
            eq(st, 400, "unknown setting refused")
            t = e.hub.detector.raise_threat("watchport", "192.168.88.21:6667", "medium", "IRC", "x", time.time(),
                                            subject="192.168.88.21", role="host")
            st, _, _ = _req(port, "POST", "/api/threats/{}/ignore".format(t["id"]), {"scope": "subject_any"})
            eq(st, 403, "ignore needs X-MCC like every change")
            st, r, _ = _req(port, "POST", "/api/threats/{}/ignore".format(t["id"]),
                            {"scope": "subject", "duration": "7d", "note": "IRC client"}, {"X-MCC": "1"})
            eq((st, r["threat"]["status"], r["ignore"]["scope"]), (200, "ignored", "subject"), "ignore via API")
            st, _, _ = _req(port, "POST", "/api/threats/{}/ignore".format(t["id"]), {"duration": "forever"}, {"X-MCC": "1"})
            eq(st, 400, "bad duration")
            st, lst, _ = _req(port, "GET", "/api/ignore")
            eq(len(lst["rules"]), 1, "listed")
            st, _, _ = _req(port, "POST", "/api/ignore", {"subject": "not an ip", "rule": "*"}, {"X-MCC": "1"})
            eq(st, 400, "manual rule validated")
            st, _, _ = _req(port, "POST", "/api/ignore/{}/remove".format(r["ignore"]["id"]), {}, {"X-MCC": "1"})
            eq(st, 200, "removed")
            st, _, _ = _req(port, "POST", "/api/ignore/I9999/remove", {}, {"X-MCC": "1"})
            eq(st, 404, "unknown rule")
            st, _, _ = _req(port, "GET", "/../../mcc/config.py")
            eq(st, 404, "path traversal")
            st, html, r = _req(port, "GET", "/")
            eq(st, 200, "index")
            ok("default-src 'self'" in r.getheader("Content-Security-Policy", ""), "CSP header")
            st, _, _ = _req(port, "POST", "/api/connect", {"router": {"host": "127.0.0.1", "user": "admin", "password": "bad",
                                                                       "scheme": "http", "port": e.router.server_address[1]}},
                            {"X-MCC": "1"})
            eq(st, 409, "bad router password is reported, not crashed")
            ok("demo" not in (e.dir / "config.json").read_text(encoding="utf-8"), "password never written to disk")
            # the live stream starts with the full state
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("GET", "/api/stream", headers={"Host": "127.0.0.1:{}".format(port)})
            r = c.getresponse()
            first = r.fp.readline().decode()
            eq(first.strip(), "event: state", "SSE starts with state")
            c.close()
        finally:
            httpd.shutdown()
            httpd.server_close()


@test
def t_server_token_when_exposed():
    with Env(connect=False) as e:
        httpd, token = make_server(e.hub, "0.0.0.0", 0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        port = httpd.server_address[1]
        try:
            ok(len(token) > 16, "token generated")
            st, _, _ = _req(port, "GET", "/api/state")
            eq(st, 401, "no token -> 401")
            st, _, r = _req(port, "GET", "/?token=" + token)
            eq(st, 200, "token in URL")
            cookie = r.getheader("Set-Cookie", "")
            ok("HttpOnly" in cookie and "SameSite=Strict" in cookie, "cookie set")
            st, _, _ = _req(port, "GET", "/api/state", headers={"Cookie": cookie.split(";")[0]})
            eq(st, 200, "cookie accepted")
            st, _, _ = _req(port, "GET", "/api/state?token=wrong")
            eq(st, 401, "wrong token")
        finally:
            httpd.shutdown()
            httpd.server_close()


# ============================================================================================
def main(argv):
    sel = [t for t in TESTS if not argv or any(a in t.__name__ for a in argv)]
    passed = failed = 0
    t0 = time.time()
    for t in sel:
        start = time.time()
        try:
            t()
            passed += 1
            print("  [pass] {} ({:.1f}s)".format(t.__name__, time.time() - start))
        except Exception as e:
            failed += 1
            print("  [FAIL] {}: {}".format(t.__name__, e))
            if not isinstance(e, AssertionError):
                traceback.print_exc()
    print("{} passed, {} failed ({:.0f}s)".format(passed, failed, time.time() - t0))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
