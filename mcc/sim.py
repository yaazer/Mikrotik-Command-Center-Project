"""A simulated MikroTik network for the demo and the tests.

  World       a small LAN (NAS, workstation, TV, cameras...) talking to the Internet, plus a
              repeating script of incidents: SSH brute force on a port forward, router login
              guessing, a port scan, a worm-like camera, a C2 beacon, a new device, a link flap,
              a big upload, an IRC connection, a VPN leak caught by a kill-switch rule.
  FakeRouter  RouterOS 7 REST API over the World (Basic auth). Changes made through it have
              effect: blocked attackers stop, quarantined hosts go quiet, disabled ports drop.
  FakeSwOS    a CRS309 running SwOS: link.b / stats.b / sys.b behind HTTP digest auth.
The World sends IPFIX and syslog only once its own configuration says to (traffic-flow target,
logging action) -- i.e. after you approve MCC's setup plan -- exactly like a real router.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import random
import secrets
import socket
import struct
import threading
import time
import urllib.parse
import base64
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple

WAN_IP = "198.51.100.2"
GATEWAY = "198.51.100.1"
LAN_IP = "192.168.88.1"

HOSTS = [
    # ip, mac, name, router port, switch port, apps: (service, port, proto, down_mbps, up_mbps, conns)
    ("192.168.88.10", "DC:2C:6E:10:00:10", "nas", "sfp-sfpplus1", 2,
     [("s3.amazonaws.com", 443, "tcp", 0.2, 1.5, 2), ("plex.tv", 32400, "tcp", 0.1, 4.0, 1)]),
    ("192.168.88.20", "DC:2C:6E:10:00:20", "workstation", "sfp-sfpplus1", 3,
     [("github.com", 443, "tcp", 1.5, 0.2, 3), ("zoom.us", 8801, "udp", 3.0, 2.2, 1),
      ("cloudflare.com", 443, "tcp", 0.6, 0.05, 4), ("tlu.dl.delivery.mp.microsoft.com", 443, "tcp", 4.0, 0.05, 1)]),
    ("192.168.88.70", "DC:2C:6E:10:00:70", "homelab", "sfp-sfpplus1", 4,
     [("deb.debian.org", 443, "tcp", 2.0, 0.1, 1)]),
    ("192.168.88.21", "3C:22:FB:00:00:21", "laptop", "ether2", 0,
     [("youtube.com", 443, "tcp", 6.0, 0.2, 2), ("icloud.com", 443, "tcp", 0.3, 0.1, 2)]),
    ("192.168.88.22", "3C:22:FB:00:00:22", "phone", "ether2", 0,
     [("icloud.com", 443, "tcp", 0.2, 0.05, 2), ("google.com", 443, "tcp", 0.5, 0.05, 2),
      ("scontent.cdninstagram.com", 443, "tcp", 1.5, 0.1, 1)]),
    ("192.168.88.30", "A4:77:33:00:00:30", "living-room-tv", "ether3", 0,
     [("netflix.com", 443, "tcp", 16.0, 0.3, 2)]),
    ("192.168.88.40", "18:C0:4D:00:00:40", "gaming-pc", "ether4", 0,
     [("steampowered.com", 27015, "udp", 1.2, 0.6, 1), ("steampowered.com", 443, "tcp", 9.0, 0.1, 1)]),
    ("192.168.88.50", "9C:8E:CD:00:00:50", "ip-camera", "ether5", 0,
     [("api.wyzecam.com", 443, "tcp", 0.05, 1.2, 1)]),
    ("192.168.88.60", "00:1B:A9:00:00:60", "printer", "ether5", 0,
     [("time.cloudflare.com", 123, "udp", 0.001, 0.001, 1)]),
]

SERVICES = {
    "s3.amazonaws.com": "52.216.8.1", "plex.tv": "52.5.140.2", "github.com": "140.82.112.4",
    "zoom.us": "170.114.10.77", "cloudflare.com": "104.16.132.229", "deb.debian.org": "151.101.2.132",
    "youtube.com": "142.250.72.14", "icloud.com": "17.253.144.10", "google.com": "142.250.72.46",
    "netflix.com": "45.57.40.1", "steampowered.com": "155.133.248.36", "api.wyzecam.com": "47.88.10.20",
    "tlu.dl.delivery.mp.microsoft.com": "13.107.4.50", "scontent.cdninstagram.com": "157.240.11.174",
    "time.cloudflare.com": "162.159.200.1", "irc.libera.chat": "203.0.113.200", "update-check.biz": "192.0.2.66",
}

C2_IP = "192.0.2.66"  # on the demo blocklist

# Demo geolocation: the simulated services sit somewhere plausible; any other address is spread
# deterministically over a world list. (Real installs use an .mmdb database -- see mcc/geo.py.)
_CITY = {  # name: (lat, lon, cc, country)
    "Dallas": (32.78, -96.80, "US", "United States"), "Ashburn": (39.04, -77.49, "US", "United States"),
    "San Jose": (37.34, -121.89, "US", "United States"), "San Francisco": (37.77, -122.42, "US", "United States"),
    "Cupertino": (37.32, -122.03, "US", "United States"), "Atlanta": (33.75, -84.39, "US", "United States"),
    "Chicago": (41.88, -87.63, "US", "United States"), "Seattle": (47.61, -122.33, "US", "United States"),
    "New York": (40.71, -74.01, "US", "United States"), "Toronto": (43.65, -79.38, "CA", "Canada"),
    "Amsterdam": (52.37, 4.90, "NL", "Netherlands"), "Frankfurt": (50.11, 8.68, "DE", "Germany"),
    "London": (51.51, -0.13, "GB", "United Kingdom"), "Paris": (48.86, 2.35, "FR", "France"),
    "Stockholm": (59.33, 18.07, "SE", "Sweden"), "Bucharest": (44.43, 26.10, "RO", "Romania"),
    "Singapore": (1.35, 103.82, "SG", "Singapore"), "Tokyo": (35.68, 139.69, "JP", "Japan"),
    "Seoul": (37.57, 126.98, "KR", "South Korea"), "Sydney": (-33.87, 151.21, "AU", "Australia"),
    "Mumbai": (19.08, 72.88, "IN", "India"), "São Paulo": (-23.55, -46.63, "BR", "Brazil"),
    "Mexico City": (19.43, -99.13, "MX", "Mexico"), "Johannesburg": (-26.20, 28.05, "ZA", "South Africa"),
    "Lagos": (6.52, 3.38, "NG", "Nigeria"), "Hong Kong": (22.32, 114.17, "HK", "Hong Kong"),
    "Jakarta": (-6.21, 106.85, "ID", "Indonesia"), "Warsaw": (52.23, 21.01, "PL", "Poland"),
    "Madrid": (40.42, -3.70, "ES", "Spain"), "Buenos Aires": (-34.60, -58.38, "AR", "Argentina"),
}
_SERVICE_CITY = {
    "s3.amazonaws.com": "Ashburn", "plex.tv": "Ashburn", "github.com": "Ashburn", "zoom.us": "San Jose",
    "cloudflare.com": "San Francisco", "deb.debian.org": "Amsterdam", "youtube.com": "Atlanta",
    "icloud.com": "Cupertino", "google.com": "Atlanta", "netflix.com": "Chicago", "steampowered.com": "Frankfurt",
    "api.wyzecam.com": "Seattle", "tlu.dl.delivery.mp.microsoft.com": "Chicago",
    "scontent.cdninstagram.com": "Atlanta", "time.cloudflare.com": "San Francisco", "irc.libera.chat": "Stockholm",
    "update-check.biz": "Bucharest",
}
_WORLD = sorted(c for c in _CITY if c != "Dallas")


def demo_geo(ip: str) -> Optional[Dict[str, Any]]:
    by_ip = {SERVICES[s]: c for s, c in _SERVICE_CITY.items()}
    city = "Dallas" if ip == WAN_IP else by_ip.get(ip)
    if city is None:
        city = _WORLD[int(hashlib.md5(ip.encode()).hexdigest(), 16) % len(_WORLD)]
    lat, lon, cc, country = _CITY[city]
    return {"lat": lat, "lon": lon, "cc": cc, "country": country, "city": city, "region": "", "precision": "city"}

ROUTER_PORTS = ["ether1", "ether2", "ether3", "ether4", "ether5", "sfp-sfpplus1"]
SWITCH_PORTS = ["ether1", "sfp1", "sfp2", "sfp3", "sfp4", "sfp5", "sfp6", "sfp7", "sfp8"]

# (offset s, event, duration s) within each cycle
SCRIPT = [(6, "ssh_brute", 50), (20, "login_fail", 45), (40, "scan", 40), (75, "worm", 40), (100, "c2", 60),
          (125, "new_device", 1), (140, "link_flap", 20), (165, "exfil", 150), (185, "irc", 60), (235, "vpn_leak", 30)]
CYCLE = 330


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        import sys
        if not isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            super().handle_error(request, client_address)


def _s(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _dur(secs: float) -> str:
    secs = int(max(0, secs))
    w, secs = divmod(secs, 604800)
    d, secs = divmod(secs, 86400)
    h, secs = divmod(secs, 3600)
    m, s = divmod(secs, 60)
    out = "".join("{}{}".format(v, u) for v, u in ((w, "w"), (d, "d"), (h, "h"), (m, "m")) if v)
    return out + "{}s".format(s) if (s or not out) else out


def _parse_dur(text: str) -> float:
    import re
    total = 0.0
    for num, u in re.findall(r"(\d+)(w|d|h|m|s)", text or ""):
        total += int(num) * {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}[u]
    return total


class World:
    def __init__(self, seed: int = 7, speed: float = 1.0, script: bool = True):
        self.lock = threading.RLock()
        self.rng = random.Random(seed)
        self.speed = speed
        self.script_on = script
        self.t0 = time.time()
        self.boot = time.time() - 3 * 86400 - 5 * 3600
        self.ids: Dict[str, int] = defaultdict(lambda: 0x10)
        self.tables: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.single: Dict[str, Dict[str, Any]] = {}
        self.conns: Dict[str, Dict[str, Any]] = {}
        self.conn_seq = 0x1000
        self.log_seq = 0x100
        self.logs: List[Dict[str, Any]] = []
        self.active: Dict[str, Dict[str, Any]] = {}
        self.cycle_start = time.time()
        self.cycle_done: set = set()
        self.cpu = 6.0
        self.flood = 0.0
        self.flow_pending: List[Dict[str, Any]] = []
        self.flow_seq = 0
        self.flow_pkts = 0
        self.last_flow_export = 0.0
        self.sw_rx = [0.0] * len(SWITCH_PORTS)
        self.sw_tx = [0.0] * len(SWITCH_PORTS)
        self.sw_link = [True, True, True, True, True, True, False, False, False]
        self.attackers: Dict[str, str] = {}
        self.extra_hosts: List[Tuple[str, str, str, str, int, list]] = []
        self._stop = threading.Event()
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._new_attackers()
        self._build()

    # -- setup ---------------------------------------------------------------------------------
    def nid(self, table: str) -> str:
        self.ids[table] += 1
        return "*{:X}".format(self.ids[table])

    def add(self, table: str, row: Dict[str, Any]) -> Dict[str, Any]:
        r = {".id": self.nid(table)}
        r.update({k: _s(v) for k, v in row.items()})
        self.tables[table].append(r)
        return r

    def _new_attackers(self) -> None:
        r = self.rng
        self.attackers = {"ssh": "203.0.113.{}".format(r.randint(10, 99)),
                          "login": "203.0.113.{}".format(r.randint(100, 180)),
                          "scan": "192.0.2.{}".format(r.randint(120, 250))}

    def _build(self) -> None:
        for i, name in enumerate(ROUTER_PORTS):
            self.add("/interface", {"name": name, "type": "ether", "running": True, "disabled": False,
                                    "rx-byte": self.rng.randint(10 ** 9, 10 ** 11), "tx-byte": self.rng.randint(10 ** 9, 10 ** 11),
                                    "rx-packet": 0, "tx-packet": 0, "rx-error": 0, "tx-error": 0, "rx-drop": 0,
                                    "tx-drop": 0, "mac-address": "48:A9:8A:00:00:{:02X}".format(i + 1), "link-downs": 0,
                                    "comment": {"ether1": "WAN - fiber ONT", "ether2": "Wi-Fi AP",
                                                "sfp-sfpplus1": "10G to CRS309"}.get(name, ""),
                                    "mtu": 1500})
        self.add("/interface", {"name": "bridge", "type": "bridge", "running": True, "disabled": False,
                                "rx-byte": 0, "tx-byte": 0, "mac-address": "48:A9:8A:00:00:10", "comment": "defconf"})
        self.add("/interface/list", {"name": "WAN", "comment": "defconf"})
        self.add("/interface/list", {"name": "LAN", "comment": "defconf"})
        self.add("/interface/list/member", {"list": "WAN", "interface": "ether1"})
        self.add("/interface/list/member", {"list": "LAN", "interface": "bridge"})
        self.add("/ip/address", {"address": LAN_IP + "/24", "network": "192.168.88.0", "interface": "bridge"})
        self.add("/ip/address", {"address": WAN_IP + "/24", "network": "198.51.100.0", "interface": "ether1"})
        self.add("/ip/route", {"dst-address": "0.0.0.0/0", "gateway": GATEWAY, "immediate-gw": GATEWAY + "%ether1",
                               "active": True, "distance": 1})
        self.add("/ip/route", {"dst-address": "192.168.88.0/24", "gateway": "bridge", "active": True, "distance": 0})
        for chain, action, extra, comment in (
                ("input", "accept", {"connection-state": "established,related,untracked"}, "defconf: accept established,related,untracked"),
                ("input", "drop", {"connection-state": "invalid"}, "defconf: drop invalid"),
                ("input", "accept", {"protocol": "icmp"}, "defconf: accept ICMP"),
                ("input", "drop", {"in-interface-list": "!LAN"}, "defconf: drop all not coming from LAN"),
                ("forward", "fasttrack-connection", {"connection-state": "established,related"}, "defconf: fasttrack"),
                ("forward", "accept", {"connection-state": "established,related,untracked"}, "defconf: accept established,related, untracked"),
                ("forward", "drop", {"connection-state": "invalid"}, "defconf: drop invalid"),
                ("forward", "drop", {"connection-state": "new", "connection-nat-state": "!dstnat", "in-interface-list": "WAN"},
                 "defconf: drop all from WAN not DSTNATed")):
            self.add("/ip/firewall/filter", dict(chain=chain, action=action, comment=comment, **extra))
        self.add("/ip/firewall/nat", {"chain": "srcnat", "action": "masquerade", "out-interface-list": "WAN",
                                      "comment": "defconf: masquerade"})
        self.add("/ip/firewall/nat", {"chain": "dstnat", "action": "dst-nat", "protocol": "tcp", "dst-port": "22",
                                      "in-interface-list": "WAN", "to-addresses": "192.168.88.70", "comment": "homelab ssh"})
        self.add("/ip/firewall/nat", {"chain": "dstnat", "action": "dst-nat", "dst-port": "51413",
                                      "in-interface-list": "WAN", "to-addresses": "192.168.88.70", "comment": "torrents"})
        for t in ("/ip/firewall/raw", "/ip/firewall/address-list", "/ipv6/firewall/raw", "/ipv6/firewall/filter",
                  "/ipv6/firewall/address-list", "/ip/traffic-flow/target", "/ipv6/address"):
            self.tables[t] = []
        for topics, action in (("info", "memory"), ("error", "memory"), ("warning", "memory"), ("critical", "echo")):
            self.add("/system/logging", {"topics": topics, "action": action})
        for name, target in (("memory", "memory"), ("disk", "disk"), ("echo", "echo"), ("remote", "remote")):
            self.add("/system/logging/action", {"name": name, "target": target,
                                                **({"remote": "0.0.0.0", "remote-port": 514} if target == "remote" else {})})
        for h in HOSTS:
            self._add_host(*h)
        for name, ip in SERVICES.items():
            self.add("/ip/dns/cache", {"name": name, "type": "A", "data": ip, "ttl": "1h"})
        self.single["/system/identity"] = {"name": "core-router"}
        self.single["/ip/traffic-flow"] = {"enabled": "false", "interfaces": "all", "cache-entries": "32k",
                                           "active-flow-timeout": "30m", "inactive-flow-timeout": "15s",
                                           "packet-sampling": "false"}
        self.log("system,info", "router rebooted")
        self.log("system,info,account", "user admin logged in from 192.168.88.20 via winbox")

    def _add_host(self, ip: str, mac: str, name: str, rport: str, sport: int, apps: list) -> None:
        self.add("/ip/dhcp-server/lease", {"address": ip, "mac-address": mac, "host-name": name, "server": "defconf",
                                           "status": "bound", "dynamic": True, "last-seen": "5s",
                                           "active-address": ip, "active-mac-address": mac})
        self.add("/ip/arp", {"address": ip, "mac-address": mac, "interface": "bridge", "dynamic": True,
                             "complete": True, "status": "reachable"})
        self.add("/interface/bridge/host", {"mac-address": mac, "on-interface": rport, "interface": "bridge",
                                            "local": False, "dynamic": True})

    # -- helpers -------------------------------------------------------------------------------
    def log(self, topics: str, msg: str) -> None:
        self.log_seq += 1
        t = time.localtime()
        self.logs.append({".id": "*{:X}".format(self.log_seq), "time": time.strftime("%H:%M:%S", t),
                          "topics": topics, "message": msg})
        del self.logs[:-1000]
        self._syslog(topics, msg)

    def _syslog(self, topics: str, msg: str) -> None:
        acts = {a["name"]: a for a in self.tables["/system/logging/action"] if a.get("target") == "remote"}
        tset = set(topics.split(","))
        for rule in self.tables["/system/logging"]:
            a = acts.get(rule.get("action", ""))
            if not a or rule.get("disabled") == "true":
                continue
            if set(rule.get("topics", "").split(",")) <= tset:
                try:
                    self._udp.sendto("<134>{} {}".format(topics, msg).encode("utf-8"),
                                     (a.get("remote", "0.0.0.0"), int(a.get("remote-port", 514))))
                except OSError:
                    pass
                return

    def iface(self, name: str) -> Optional[Dict[str, Any]]:
        return next((r for r in self.tables["/interface"] if r["name"] == name), None)

    def iface_up(self, name: str) -> bool:
        r = self.iface(name)
        return bool(r) and r["running"] == "true" and r["disabled"] == "false"

    def _listed(self, ip: str, lst: str) -> bool:
        return any(e.get("list") == lst and e.get("address", "").split("/")[0] == ip and e.get("disabled") != "true"
                   for e in self.tables["/ip/firewall/address-list"])

    def blocked(self, ip: str) -> bool:
        rule = any(r.get("src-address-list") == "mcc-blocked" and r.get("action") == "drop"
                   for r in self.tables["/ip/firewall/raw"])
        return rule and self._listed(ip, "mcc-blocked")

    def quarantined(self, ip: str) -> bool:
        rule = any(r.get("src-address-list") == "mcc-quarantine" and r.get("action") == "drop"
                   for r in self.tables["/ip/firewall/filter"])
        return rule and self._listed(ip, "mcc-quarantine")

    def log_rules(self) -> bool:
        return any(r.get("action") == "log" and r.get("log-prefix") == "MCC-IN" for r in self.tables["/ip/firewall/filter"])

    def flows_on(self) -> bool:
        return self.single["/ip/traffic-flow"].get("enabled") in ("true", "yes") and \
            bool(self.tables["/ip/traffic-flow/target"])

    # -- connections ---------------------------------------------------------------------------
    def new_conn(self, src: str, sport: int, dst: str, dport: int, proto: str, up: float, down: float, life: float,
                 kind: str = "app", host: str = "", nat_to: str = "", state: str = "established") -> Dict[str, Any]:
        self.conn_seq += 1
        cid = "*{:X}".format(self.conn_seq)
        inbound = bool(nat_to)
        c = {".id": cid, "protocol": proto, "src-address": "{}:{}".format(src, sport),
             "dst-address": "{}:{}".format(dst, dport),
             "reply-src-address": "{}:{}".format(nat_to or dst, dport),
             "reply-dst-address": "{}:{}".format(src if inbound else WAN_IP, sport if inbound else self.rng.randint(20000, 60000)),
             "orig-bytes": 0, "repl-bytes": 0, "orig-packets": 0, "repl-packets": 0,
             "tcp-state": state if proto == "tcp" else "", "timeout": "23h59m59s",
             "_up": up, "_down": down, "_born": time.time(), "_life": life, "_kind": kind, "_host": host,
             "_exported": (0, 0), "_src": src, "_dst": dst, "_sport": sport, "_dport": dport, "_in": inbound,
             "_phase": self.rng.random() * 6.28}
        self.conns[cid] = c
        return c

    def host_list(self) -> List[Tuple[str, str, str, str, int, list]]:
        return HOSTS + self.extra_hosts

    def _spawn_apps(self, now: float) -> None:
        per_host: Dict[Tuple[str, str], int] = defaultdict(int)
        for c in self.conns.values():
            if c["_kind"] == "app":
                per_host[(c["_host"], c["_dst"] + ":" + str(c["_dport"]))] += 1
        for ip, mac, name, rport, sport, apps in self.host_list():
            if not self.iface_up(rport) or self.quarantined(ip):
                continue
            for svc, port, proto, down, up, n in apps:
                rip = SERVICES.get(svc, svc)
                key = (ip, rip + ":" + str(port))
                while per_host[key] < n:
                    per_host[key] += 1
                    self.new_conn(ip, self.rng.randint(40000, 65000), rip, port, proto,
                                  up * 1e6 / n, down * 1e6 / n, self.rng.uniform(25, 140), "app", ip)
        # the homelab seeds Linux ISOs: a BitTorrent swarm of unnamed peers on random high ports,
        # some it dials (from its listen port 51413) and some that dial in through a port forward
        if self.iface_up("sfp-sfpplus1") and not self.quarantined("192.168.88.70"):
            swarm = sum(1 for c in self.conns.values() if c["_kind"] == "torrent")
            while swarm < 14:
                swarm += 1
                peer = "{}.{}.{}.{}".format(self.rng.choice([31, 46, 77, 88, 91, 109, 176, 185, 188, 213]),
                                            self.rng.randint(1, 254), self.rng.randint(1, 254), self.rng.randint(1, 254))
                down, up = self.rng.uniform(0.2e6, 1.6e6), self.rng.uniform(0.1e6, 0.9e6)
                if self.rng.random() < 0.4:
                    self.new_conn(peer, self.rng.randint(20000, 65000), WAN_IP, 51413, self.rng.choice(["tcp", "udp"]),
                                  up, down, self.rng.uniform(20, 90), "torrent", "192.168.88.70", nat_to="192.168.88.70")
                else:
                    self.new_conn("192.168.88.70", 51413, peer, self.rng.randint(10000, 65000),
                                  self.rng.choice(["tcp", "udp"]), up, down, self.rng.uniform(20, 90), "torrent",
                                  "192.168.88.70")
        # inbound HTTPS-ish visitors to the homelab ssh forward are attacks; legit visitors use 443 tunnels
        if self.rng.random() < 0.05 and self.iface_up("sfp-sfpplus1"):
            client = "{}.{}.{}.{}".format(self.rng.choice([24, 73, 98, 174]), self.rng.randint(1, 254),
                                          self.rng.randint(1, 254), self.rng.randint(1, 254))
            if not self.blocked(client):
                self.new_conn(client, self.rng.randint(30000, 60000), WAN_IP, 22, "tcp", 0.02e6, 0.01e6,
                              self.rng.uniform(30, 300), "visitor", "192.168.88.70", nat_to="192.168.88.70")

    # -- the incident script -------------------------------------------------------------------
    def _script(self, now: float) -> None:
        if not self.script_on:
            return
        el = (now - self.cycle_start) * self.speed
        if el >= CYCLE:
            self.cycle_start = now
            self.cycle_done = set()
            self._new_attackers()
            el = 0
        for off, name, dur in SCRIPT:
            if el >= off and name not in self.cycle_done:
                self.cycle_done.add(name)
                self.active[name] = {"start": now, "end": now + dur / self.speed, "acc": 0.0, "n": 0}
                getattr(self, "_start_" + name, lambda e: None)(self.active[name])
        for name in list(self.active):
            e = self.active[name]
            if now >= e["end"]:
                getattr(self, "_end_" + name, lambda e: None)(e)
                del self.active[name]
            else:
                getattr(self, "_step_" + name, lambda e, now: None)(e, now)

    def _every(self, e: Dict[str, Any], interval: float, now: float) -> int:
        """How many times an every-`interval`-seconds thing is due since the last tick."""
        e.setdefault("last", e["start"])
        n = int((now - e["last"]) * self.speed / interval)
        if n:
            e["last"] += n * interval / self.speed
        return n

    def _step_ssh_brute(self, e: Dict[str, Any], now: float) -> None:
        a = self.attackers["ssh"]
        if self.blocked(a):
            return
        for _ in range(self._every(e, 1.1, now)):
            self.new_conn(a, self.rng.randint(30000, 61000), WAN_IP, 22, "tcp", 4e3, 6e3, 3.0, "attack",
                          "192.168.88.70", nat_to="192.168.88.70")
            self._flow(a, "192.168.88.70", self.rng.randint(30000, 61000), 22, 6, 0x1b, 2200, 14)

    def _step_login_fail(self, e: Dict[str, Any], now: float) -> None:
        a = self.attackers["login"]
        if self.blocked(a):
            return
        for _ in range(self._every(e, 4.0, now)):
            user = self.rng.choice(["admin", "admin", "root", "support", "user", "mikrotik"])
            via = self.rng.choice(["winbox", "ssh", "winbox"])
            self.log("system,error,critical", "login failure for user {} from {} via {}".format(user, a, via))
            self._fwlog("input", a, self.rng.randint(30000, 61000), WAN_IP, 8291 if via == "winbox" else 22)

    def _step_scan(self, e: Dict[str, Any], now: float) -> None:
        a = self.attackers["scan"]
        if self.blocked(a):
            return
        for _ in range(self._every(e, 0.25, now)):
            port = self.rng.choice([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 1723, 3306,
                                    3389, 5060, 5432, 5900, 6379, 8080, 8291, 8443, 8728, 9200, 11211, 27017])
            port = port if self.rng.random() < 0.7 else self.rng.randint(1, 65535)
            self._fwlog("input", a, self.rng.randint(40000, 65000), WAN_IP, port)
            self._flow(a, WAN_IP, self.rng.randint(40000, 65000), port, 6, 0x02, 44, 1)

    def _step_worm(self, e: Dict[str, Any], now: float) -> None:
        cam = "192.168.88.50"
        if self.quarantined(cam) or not self.iface_up("ether5"):
            return
        for _ in range(self._every(e, 0.6, now)):
            dst = "{}.{}.{}.{}".format(self.rng.randint(11, 223), self.rng.randint(0, 255), self.rng.randint(0, 255),
                                       self.rng.randint(1, 254))
            port = self.rng.choice([23, 23, 2323])
            sp = self.rng.randint(40000, 65000)
            self.new_conn(cam, sp, dst, port, "tcp", 600, 0, 4.0, "attack", cam, state="syn-sent")
            self._flow(cam, dst, sp, port, 6, 0x02, 60, 1)

    def _start_c2(self, e: Dict[str, Any]) -> None:
        if not self.quarantined("192.168.88.20") and not self.blocked(C2_IP):
            e["conn"] = self.new_conn("192.168.88.20", 51515, C2_IP, 443, "tcp", 9e3, 3e3, 1e9, "attack",
                                      "192.168.88.20")[".id"]

    def _step_c2(self, e: Dict[str, Any], now: float) -> None:
        cid = e.get("conn")
        if cid and (self.blocked(C2_IP) or self.quarantined("192.168.88.20")):
            self.conns.pop(cid, None)
            e["conn"] = None

    def _end_c2(self, e: Dict[str, Any]) -> None:
        if e.get("conn"):
            self.conns.pop(e["conn"], None)

    def _start_new_device(self, e: Dict[str, Any]) -> None:
        n = len(self.extra_hosts) + 1
        ip = "192.168.88.{}".format(150 + n)
        mac = "F0:9F:C2:{:02X}:{:02X}:{:02X}".format(self.rng.randint(0, 255), self.rng.randint(0, 255),
                                                     self.rng.randint(0, 255))
        host = (ip, mac, "", "ether2", 0, [("google.com", 443, "tcp", 0.4, 0.05, 1)])
        self.extra_hosts.append(host)
        self._add_host(*host)
        self.log("dhcp,info", "defconf assigned {} for {}".format(ip, mac))

    def _start_link_flap(self, e: Dict[str, Any]) -> None:
        r = self.iface("ether3")
        if r and r["disabled"] == "false":
            r["running"] = "false"
            r["link-downs"] = str(int(r.get("link-downs", "0")) + 1)
            self.log("interface,info", "ether3 link down")
        self.sw_link[5] = False
        for cid in [c for c, v in self.conns.items() if v["_host"] == "192.168.88.30"]:
            self.conns.pop(cid, None)

    def _end_link_flap(self, e: Dict[str, Any]) -> None:
        r = self.iface("ether3")
        if r and r["disabled"] == "false":
            r["running"] = "true"
            self.log("interface,info", "ether3 link up (speed 1G, full duplex)")
        self.sw_link[5] = True

    def _start_exfil(self, e: Dict[str, Any]) -> None:
        if not self.quarantined("192.168.88.10"):
            e["conn"] = self.new_conn("192.168.88.10", 50123, SERVICES["s3.amazonaws.com"], 443, "tcp",
                                      140e6, 1.2e6, 1e9, "attack", "192.168.88.10")[".id"]

    def _step_exfil(self, e: Dict[str, Any], now: float) -> None:
        if e.get("conn") and self.quarantined("192.168.88.10"):
            self.conns.pop(e["conn"], None)
            e["conn"] = None

    def _end_exfil(self, e: Dict[str, Any]) -> None:
        if e.get("conn"):
            self.conns.pop(e["conn"], None)

    def _start_irc(self, e: Dict[str, Any]) -> None:
        irc = SERVICES["irc.libera.chat"]
        if not self.blocked(irc) and not self.quarantined("192.168.88.21"):
            self.new_conn("192.168.88.21", 49999, irc, 6667, "tcp", 2e3, 4e3, 60 / self.speed, "attack",
                          "192.168.88.21")

    def _step_vpn_leak(self, e: Dict[str, Any], now: float) -> None:
        # the phone's VPN drops; a kill-switch rule logged VPN-LEAK catches it going straight out the WAN
        if self.quarantined("192.168.88.22"):
            return
        for _ in range(self._every(e, 2.5, now)):
            dst = self.rng.choice([SERVICES["google.com"], SERVICES["icloud.com"], SERVICES["scontent.cdninstagram.com"]])
            self.log("firewall,info", "VPN-LEAK forward: in:bridge out:ether1, connection-state:new src-mac "
                                      "3c:22:fb:00:00:22, proto TCP (SYN), 192.168.88.22:{}->{}:443, len 60".format(
                                          self.rng.randint(40000, 65000), dst))

    # -- telemetry out -------------------------------------------------------------------------
    def _fwlog(self, chain: str, src: str, sport: int, dst: str, dport: int) -> None:
        if not self.log_rules():
            return
        self.log("firewall,info", "MCC-IN {}: in:ether1 out:(unknown 0), connection-state:new src-mac "
                                  "64:d1:54:aa:bb:cc, proto TCP (SYN), {}:{}->{}:{}, len 60".format(
                                      chain, src, sport, dst, dport))

    def _flow(self, src: str, dst: str, sport: int, dport: int, proto: int, flags: int, nbytes: int, pkts: int) -> None:
        if self.flows_on():
            self.flow_pending.append({"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto,
                                      "flags": flags, "bytes": nbytes, "packets": pkts})

    def _export(self, now: float) -> None:
        if not self.flows_on():
            self.flow_pending = []
            return
        if now - self.last_flow_export >= 5.0:
            self.last_flow_export = now
            for c in self.conns.values():
                ob, rb = int(c["orig-bytes"]), int(c["repl-bytes"])
                eo, er = c["_exported"]
                proto = 6 if c["protocol"] == "tcp" else 17
                if ob > eo:
                    self.flow_pending.append({"src": c["_src"], "dst": c["_dst"] if not c["_in"] else c["_host"],
                                              "sport": c["_sport"], "dport": c["_dport"], "proto": proto,
                                              "flags": 0x1a if proto == 6 else 0, "bytes": ob - eo,
                                              "packets": max(1, (ob - eo) // 1200)})
                if rb > er:
                    self.flow_pending.append({"src": c["_dst"] if not c["_in"] else c["_host"], "dst": c["_src"],
                                              "sport": c["_dport"], "dport": c["_sport"], "proto": proto,
                                              "flags": 0x1a if proto == 6 else 0, "bytes": rb - er,
                                              "packets": max(1, (rb - er) // 1200)})
                c["_exported"] = (ob, rb)
        if not self.flow_pending:
            return
        targets = [(t.get("dst-address"), int(t.get("port", 2055))) for t in self.tables["/ip/traffic-flow/target"]
                   if t.get("disabled") != "true"]
        flows, self.flow_pending = self.flow_pending, []
        for i in range(0, len(flows), 25):
            pkt = self.ipfix(flows[i:i + 25], now)
            for t in targets:
                try:
                    self._udp.sendto(pkt, t)
                except OSError:
                    pass

    def ipfix(self, flows: List[Dict[str, Any]], now: float) -> bytes:
        fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 1), (1, 8), (2, 8), (152, 8), (153, 8)]
        sets = b""
        if self.flow_pkts % 10 == 0:
            tmpl = struct.pack("!HH", 256, len(fields)) + b"".join(struct.pack("!HH", f, l) for f, l in fields)
            sets += struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl
        recs = b""
        ms = int(now * 1000)
        for f in flows:
            recs += (ipaddress.IPv4Address(f["src"]).packed + ipaddress.IPv4Address(f["dst"]).packed +
                     struct.pack("!HHBBQQQQ", f["sport"], f["dport"], f["proto"], f["flags"], f["bytes"], f["packets"],
                                 ms - 4000, ms))
        sets += struct.pack("!HH", 256, 4 + len(recs)) + recs
        self.flow_pkts += 1
        self.flow_seq += len(flows)
        return struct.pack("!HHIII", 10, 16 + len(sets), int(now), self.flow_seq, 1) + sets

    # -- the clock -----------------------------------------------------------------------------
    def step(self, dt: float) -> None:
        now = time.time()
        with self.lock:
            self._script(now)
            self._spawn_apps(now)
            wave = 0.75 + 0.25 * math.sin(now / 40.0)
            port_rx: Dict[str, float] = defaultdict(float)
            port_tx: Dict[str, float] = defaultdict(float)
            sw_rx = [0.0] * len(SWITCH_PORTS)
            sw_tx = [0.0] * len(SWITCH_PORTS)
            wan_rx = wan_tx = 0.0
            hosts = {h[0]: h for h in self.host_list()}
            for cid in list(self.conns):
                c = self.conns[cid]
                if now - c["_born"] > c["_life"]:
                    del self.conns[cid]
                    continue
                h = hosts.get(c["_host"])
                if h and (not self.iface_up(h[3]) or self.quarantined(h[0])):
                    del self.conns[cid]
                    continue
                if c["_in"] and self.blocked(c["_src"]) or (not c["_in"] and self.blocked(c["_dst"])):
                    del self.conns[cid]
                    continue
                jitter = (0.6 + 0.4 * math.sin(now / 7.0 + c["_phase"])) * (wave if c["_kind"] == "app" else 1)
                up, down = c["_up"] * jitter, c["_down"] * jitter
                # orig = initiator -> responder
                o_bps, r_bps = (down, up) if c["_in"] else (up, down)
                c["orig-bytes"] = int(c["orig-bytes"]) + int(o_bps * dt / 8)
                c["repl-bytes"] = int(c["repl-bytes"]) + int(r_bps * dt / 8)
                c["orig-packets"] = int(c["orig-packets"]) + max(1, int(o_bps * dt / 9600))
                c["repl-packets"] = int(c["repl-packets"]) + max(1, int(r_bps * dt / 9600))
                c["orig-rate"], c["repl-rate"] = int(o_bps), int(r_bps)
                wan_rx += down
                wan_tx += up
                if h:
                    port_tx[h[3]] += down
                    port_rx[h[3]] += up
                    if h[4]:
                        sw_tx[h[4]] += down
                        sw_rx[h[4]] += up
                        sw_tx[1] += up
                        sw_rx[1] += down
            port_rx["ether1"] += wan_rx
            port_tx["ether1"] += wan_tx
            port_rx["bridge"] = sum(v for k, v in port_rx.items() if k != "ether1")
            port_tx["bridge"] = sum(v for k, v in port_tx.items() if k != "ether1")
            for r in self.tables["/interface"]:
                if r["running"] != "true" or r["disabled"] != "false":
                    continue
                rx = port_rx.get(r["name"], 0.0) + self.rng.uniform(2e3, 2e4)
                tx = port_tx.get(r["name"], 0.0) + self.rng.uniform(2e3, 2e4)
                r["rx-byte"] = str(int(r["rx-byte"]) + int(rx * dt / 8))
                r["tx-byte"] = str(int(r["tx-byte"]) + int(tx * dt / 8))
                r["rx-packet"] = str(int(r.get("rx-packet", "0")) + int(rx * dt / 9600))
                r["tx-packet"] = str(int(r.get("tx-packet", "0")) + int(tx * dt / 9600))
            sw_rx[0] += 5e3
            sw_tx[0] += 8e3
            sw_rx[5] += 3e5 if self.sw_link[5] else 0
            sw_tx[5] += 6e5 if self.sw_link[5] else 0
            for i in range(len(SWITCH_PORTS)):
                if self.sw_link[i]:
                    self.sw_rx[i] += sw_rx[i] * dt / 8
                    self.sw_tx[i] += sw_tx[i] * dt / 8
            load = (wan_rx + wan_tx) / 1e9 * 30 + len(self.conns) / 200.0
            self.cpu = max(1.0, min(100.0, self.cpu * 0.7 + (4 + load + self.rng.uniform(0, 4)) * 0.3))
            for e in self.tables["/ip/firewall/address-list"]:
                if e.get("timeout"):
                    e["_left"] = e.get("_left", _parse_dur(e["timeout"])) - dt
                    if e["_left"] <= 0:
                        e["_dead"] = True
                    else:
                        e["timeout"] = _dur(e["_left"])
            self.tables["/ip/firewall/address-list"] = [e for e in self.tables["/ip/firewall/address-list"]
                                                        if not e.get("_dead")]
            self._export(now)

    def run(self) -> None:
        last = time.time()
        while not self._stop.is_set():
            self._stop.wait(0.5)
            now = time.time()
            self.step(now - last)
            last = now

    def start(self) -> "World":
        threading.Thread(target=self.run, name="sim-world", daemon=True).start()
        return self

    def stop(self) -> None:
        self._stop.set()

    # -- REST views ----------------------------------------------------------------------------
    def resource(self) -> Dict[str, Any]:
        return {"uptime": _dur(time.time() - self.boot), "version": "7.16.1 (stable)", "build-time": "2024-10-10",
                "free-memory": str(int(1024 ** 3 * 0.78 - len(self.conns) * 2000)), "total-memory": str(1024 ** 3),
                "cpu": "ARM64", "cpu-count": "4", "cpu-frequency": "1400", "cpu-load": str(int(self.cpu)),
                "free-hdd-space": "98000000", "total-hdd-space": "134217728", "architecture-name": "arm64",
                "board-name": "RB5009UG+S+", "platform": "MikroTik"}

    def health(self) -> List[Dict[str, Any]]:
        t = 47 + self.cpu * 0.15 + self.rng.uniform(-0.5, 0.5)
        return [{".id": "*D", "name": "voltage", "value": "24.1", "type": "V"},
                {".id": "*E", "name": "cpu-temperature", "value": "{:.0f}".format(t), "type": "C"},
                {".id": "*F", "name": "board-temperature1", "value": "{:.0f}".format(t - 9), "type": "C"}]


# ----------------------------------------------------------------------------------------------
# Fake RouterOS REST
# ----------------------------------------------------------------------------------------------
SINGLETONS = {"/system/resource", "/system/identity", "/ip/traffic-flow", "/system/health"}


def make_router(world: World, user: str = "admin", password: str = "demo", bind: str = "127.0.0.1",
                port: int = 0) -> ThreadingHTTPServer:
    expected = "Basic " + base64.b64encode("{}:{}".format(user, password).encode()).decode()

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a: Any) -> None:
            pass

        def _out(self, status: int, obj: Any) -> None:
            body = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _err(self, status: int, msg: str, detail: str = "") -> None:
            self._out(status, {"error": status, "message": msg, **({"detail": detail} if detail else {})})

        def _handle(self, method: str) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            if self.headers.get("Authorization") != expected:
                return self._err(401, "Unauthorized")
            url = urllib.parse.urlparse(self.path)
            if not url.path.startswith("/rest/"):
                return self._err(404, "Not Found")
            path = url.path[5:].rstrip("/")
            q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
            try:
                body = json.loads(raw) if raw else {}
            except ValueError:
                return self._err(400, "Bad Request", "JSON parse error")
            with world.lock:
                try:
                    status, out = route(method, path, q, body)
                except KeyError as e:
                    return self._err(404, "Not Found", str(e))
            if status >= 400:
                return self._err(status, out if isinstance(out, str) else "Bad Request")
            self._out(status, out)

        def do_GET(self) -> None:
            self._handle("GET")

        def do_PUT(self) -> None:
            self._handle("PUT")

        def do_PATCH(self) -> None:
            self._handle("PATCH")

        def do_DELETE(self) -> None:
            self._handle("DELETE")

        def do_POST(self) -> None:
            self._handle("POST")

    def public(row: Dict[str, Any], proplist: Optional[str]) -> Dict[str, Any]:
        out = {k: _s(v) for k, v in row.items() if not k.startswith("_")}
        if proplist:
            keep = set(proplist.split(","))
            out = {k: v for k, v in out.items() if k in keep}
        return out

    def table(path: str) -> List[Dict[str, Any]]:
        if path == "/ip/firewall/connection":
            return list(world.conns.values())
        if path == "/log":
            return world.logs
        if path not in world.tables:
            raise KeyError(path)
        return world.tables[path]

    def route(method: str, path: str, q: Dict[str, str], body: Dict[str, Any]) -> Tuple[int, Any]:
        if path in SINGLETONS:
            if method != "GET":
                return 400, "Bad Request"
            if path == "/system/resource":
                return 200, world.resource()
            if path == "/system/health":
                return 200, world.health()
            return 200, dict(world.single[path])
        if method == "POST" and path == "/interface/ethernet/monitor":
            names = str(body.get("numbers", "")).split(",")
            out = []
            for r in world.tables["/interface"]:
                if r["name"] in names:
                    up = r["running"] == "true" and r["disabled"] == "false"
                    out.append({"name": r["name"], "status": "link-ok" if up else "no-link",
                                **({"rate": "10Gbps" if r["name"].startswith("sfp") else "1Gbps", "full-duplex": "true"} if up else {})})
            return 200, out
        if method == "POST":
            menu, _, cmd = path.rpartition("/")
            if cmd == "set" and menu in world.single:
                for k, v in body.items():
                    world.single[menu][k] = {"yes": "true", "no": "false"}.get(str(v), str(v))
                return 200, []
            return 400, "no such command"
        menu, _, last = path.rpartition("/")
        if last.startswith("*"):
            rows = table(menu)
            row = next((r for r in rows if r[".id"] == last), None)
            if row is None:
                return 404, "no such item"
            if method == "GET":
                return 200, public(row, None)
            if method == "PATCH":
                for k, v in body.items():
                    row[k] = {"yes": "true", "no": "false"}.get(str(v), str(v))
                if menu == "/interface" and "disabled" in body:
                    disabled = row["disabled"] == "true"
                    row["running"] = "false" if disabled else "true"
                    world.log("interface,info", "{} link {}".format(row["name"], "down" if disabled else "up"))
                return 200, public(row, None)
            if method == "DELETE":
                if menu == "/ip/firewall/connection":
                    world.conns.pop(last, None)
                else:
                    rows.remove(row)
                return 204, None
            return 400, "Bad Request"
        rows = table(path)
        if method == "GET":
            prop = q.pop(".proplist", None)
            out = []
            for r in rows:
                if all(_s(r.get(k, "")) == v for k, v in q.items()):
                    out.append(public(r, prop))
            return 200, out
        if method == "PUT":
            if path in ("/ip/firewall/connection", "/log"):
                return 400, "Bad Request"
            body = dict(body)
            before = body.pop("place-before", None)
            if path.endswith("address-list"):
                if any(e.get("list") == body.get("list") and e.get("address") == body.get("address") for e in rows):
                    return 400, "failure: already have such entry"
                body.setdefault("creation-time", time.strftime("%Y-%m-%d %H:%M:%S"))
                body.setdefault("dynamic", "true" if body.get("timeout") else "false")
            row = {".id": world.nid(path)}
            row.update({k: {"yes": "true", "no": "false"}.get(str(v), str(v)) for k, v in body.items()})
            row.setdefault("disabled", "false")
            idx = next((i for i, r in enumerate(rows) if r[".id"] == before), None) if before else None
            if idx is None:
                rows.append(row)
            else:
                rows.insert(idx, row)
            return 201, public(row, None)
        return 400, "Bad Request"

    return QuietServer((bind, port), H)


# ----------------------------------------------------------------------------------------------
# Fake SwOS (digest auth)
# ----------------------------------------------------------------------------------------------
def _hex(s: str) -> str:
    return s.encode().hex()


def make_swos(world: World, user: str = "admin", password: str = "", bind: str = "127.0.0.1",
              port: int = 0) -> ThreadingHTTPServer:
    realm = "CRS309-1G-8S+"
    nonces: set = set()

    def md5(s: str) -> str:
        return hashlib.md5(s.encode()).hexdigest()

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a: Any) -> None:
            pass

        def _authed(self) -> bool:
            h = self.headers.get("Authorization") or ""
            if not h.startswith("Digest "):
                return False
            parts = dict((k.strip(), v.strip().strip('"')) for k, _, v in
                         (p.partition("=") for p in h[7:].split(",")))
            if parts.get("nonce") not in nonces or parts.get("username") != user:
                return False
            ha1 = md5("{}:{}:{}".format(user, realm, password))
            ha2 = md5("GET:{}".format(parts.get("uri", "")))
            want = md5("{}:{}:{}:{}:{}:{}".format(ha1, parts["nonce"], parts.get("nc", ""), parts.get("cnonce", ""),
                                                  parts.get("qop", ""), ha2))
            return secrets.compare_digest(want, parts.get("response", ""))

        def do_GET(self) -> None:
            if not self._authed():
                nonce = secrets.token_hex(16)
                nonces.add(nonce)
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Digest realm="{}", qop="auth", nonce="{}"'.format(realm, nonce))
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            name = self.path.lstrip("/")
            with world.lock:
                if name == "link.b":
                    en = (1 << len(SWITCH_PORTS)) - 1
                    lnk = sum(1 << i for i, up in enumerate(world.sw_link) if up)
                    spd = ",".join("0x{:02x}".format(2 if i == 0 else 3) for i in range(len(SWITCH_PORTS)))
                    nm = ",".join("'{}'".format(_hex(n)) for n in SWITCH_PORTS)
                    body = "{{en:0x{:x},lnk:0x{:x},dpx:0x{:x},spd:[{}],nm:[{}],prt:0x{:x}}}".format(
                        en, lnk, en, spd, nm, len(SWITCH_PORTS))
                elif name == "stats.b":
                    def arr(vals: List[float], hi: bool) -> str:
                        return ",".join("0x{:x}".format((int(v) >> 32) if hi else (int(v) & 0xFFFFFFFF)) for v in vals)
                    body = "{{rb:[{}],rbh:[{}],tb:[{}],tbh:[{}],rfcs:[{}]}}".format(
                        arr(world.sw_rx, False), arr(world.sw_rx, True), arr(world.sw_tx, False),
                        arr(world.sw_tx, True), ",".join("0x0" for _ in SWITCH_PORTS))
                elif name == "sys.b":
                    body = "{{id:'{}',brd:'{}',ver:'{}',upt:0x{:x}}}".format(
                        _hex("core-switch"), _hex("CRS309-1G-8S+"), _hex("2.17"), int(time.time() - world.boot) * 100)
                else:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return QuietServer((bind, port), H)


def serve(server: ThreadingHTTPServer) -> ThreadingHTTPServer:
    threading.Thread(target=server.serve_forever, name="sim-http", daemon=True).start()
    return server
