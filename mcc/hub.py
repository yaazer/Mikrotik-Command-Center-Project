"""The hub: owns the device connections, pollers, collectors, live state and history, and fans
events out to every open console over server-sent events."""

from __future__ import annotations

import copy
import ipaddress
import queue
import socket
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple

from .actions import BLOCK_LIST, QUARANTINE_LIST, ActionEngine
from .collectors import FlowParser, UdpCollector, classify, level_of, split_syslog
from .config import Config
from .classify import CATEGORIES
from .detect import RULES, Detector
from .geo import Geo
from .identify import Fingerprints, identify
from .names import NameMemory
from .oui import MacVendors, normalise_mac
from .pins import Pins
from .routeros import CertificateChanged, RouterOS, RouterOSError, local_ip_toward
from .setup_plan import SetupPlanner
from .rosswitch import RouterOSSwitch, detect_os
from .swos import SwOS, SwOSError
from .traffic import TrafficModel
from .util import in_networks, is_local_scope, ip_obj, parse_duration, parse_networks, to_bool, to_float, to_int

HIST = 900  # points kept per series (30 min at the default 2 s poll)
# Optional tables read to identify devices: a router without the package (or menu) answers with an error, and
# MCC then leaves that table alone for a while instead of asking every poll.
WIFI_TABLES = ("/interface/wifi/registration-table", "/interface/wireless/registration-table",
               "/caps-man/registration-table", "/interface/wifiwave2/registration-table")
RETRY_TABLE_S = 600


# RouterOS interface types that are VPN tunnels (pppoe-out is an Internet uplink, not a VPN)
VPN_TYPES = {"wg": "WireGuard", "wireguard": "WireGuard", "ovpn-out": "OpenVPN", "ovpn-client": "OpenVPN",
             "l2tp-out": "L2TP", "sstp-out": "SSTP", "pptp-out": "PPTP", "gre-tunnel": "GRE", "ipip-tunnel": "IPIP",
             "eoip-tunnel": "EoIP", "6to4-tunnel": "6to4", "vxlan": "VXLAN", "zerotier": "ZeroTier"}

class Broadcaster:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.clients: Set["queue.Queue[Tuple[str, Any]]"] = set()
        self.ticks_skipped = 0
        self.resyncs = 0

    def subscribe(self) -> "queue.Queue[Tuple[str, Any]]":
        q: "queue.Queue[Tuple[str, Any]]" = queue.Queue(maxsize=400)
        with self.lock:
            self.clients.add(q)
        return q

    def unsubscribe(self, q: "queue.Queue[Tuple[str, Any]]") -> None:
        with self.lock:
            self.clients.discard(q)

    # a client this far behind gets no new ticks until it catches up: each tick is a full snapshot that
    # supersedes the last, so dropping stale ones loses nothing -- forcing a resync would rebuild its page
    TICK_BACKLOG = 8

    def publish(self, event: str, data: Any) -> None:
        with self.lock:
            dead = []
            for q in self.clients:
                if event == "tick" and q.qsize() >= self.TICK_BACKLOG:
                    self.ticks_skipped += 1
                    continue
                try:
                    q.put_nowait((event, data))
                except queue.Full:
                    dead.append(q)  # a stalled browser tab; it reconnects and resyncs
            self.resyncs += len(dead)
            for q in dead:
                self.clients.discard(q)
                try:
                    q.put_nowait(("resync", {}))
                except queue.Full:
                    pass


class Hub:
    def __init__(self, cfg: Config, data_dir: Optional[Path] = None):
        self.cfg = cfg
        self.data_dir = Path(data_dir or cfg.data_dir)
        self.bus = Broadcaster()
        self.lock = threading.RLock()
        self.ros: Optional[RouterOS] = None
        self._ros_slow: Optional[RouterOS] = None
        self.swos: Optional[SwOS] = None
        self.router_host_ip = ""
        self.router_status: Dict[str, Any] = {"state": "disconnected", "error": "", "last_ok": 0.0, "tasks": {}}
        self.switch_status: Dict[str, Any] = {"state": "off", "error": "", "last_ok": 0.0}
        self.router_info: Dict[str, Any] = {}
        self.ifaces: Dict[str, Dict[str, Any]] = {}
        self._if_prev: Dict[str, Tuple[float, int, int]] = {}
        self.iface_hist: Dict[str, Deque[Tuple[float, float, float]]] = defaultdict(lambda: deque(maxlen=HIST))
        self.health_hist: Deque[Tuple[float, float, float]] = deque(maxlen=HIST)
        self.switch_ports: List[Dict[str, Any]] = []
        self.switch_sys: Dict[str, Any] = {}
        self._sw_prev: Dict[int, Tuple[float, float, float]] = {}
        self.switch_hist: Dict[int, Deque[Tuple[float, float, float]]] = defaultdict(lambda: deque(maxlen=HIST))
        self.devices: Dict[str, Dict[str, Any]] = {}
        self.mac_of: Dict[str, str] = {}  # LAN address -> MAC
        self.vendors = MacVendors(self.data_dir)  # IEEE MAC vendor registry (bundled snapshot, or refreshed in Setup)
        self.fingerprints = Fingerprints(self.data_dir)  # what each device's traffic revealed about it
        self._table_off: Dict[str, float] = {}  # optional router tables that errored -> retry after
        self.ip_names: Dict[str, str] = {}
        self.dns_names: Dict[str, str] = {}
        self.name_memory = NameMemory(self.data_dir)  # names seen before: kept across restarts and DNS-cache expiry
        self.router_addrs: Set[str] = set()
        self.router_nets: List[Tuple[str, Any]] = []  # (interface, network)
        self.addr_iface: Dict[str, str] = {}  # router address -> its interface
        self.vpn_peers: List[Dict[str, Any]] = []  # WireGuard peers
        self.gateways: Set[str] = set()
        self._wan: Set[str] = set()
        self.entries: List[Dict[str, Any]] = []
        self.blocked: Set[str] = set()
        self.logs: Deque[Dict[str, Any]] = deque(maxlen=3000)
        self.log_seq = 0
        self._log_pending: List[Dict[str, Any]] = []
        self._last_log_id = -1
        self.syslog_at = 0.0
        self.flow_records = 0
        self._flow_rate: Deque[Tuple[float, int]] = deque(maxlen=120)
        self._mcc_ip = ""
        self._force: Set[str] = set()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self.threads: List[threading.Thread] = []
        self.started = time.time()

        self.traffic = TrafficModel(self.lan_nets, lambda: self.router_addrs, self.name_of)
        self.traffic.path_of = self._path_of
        # Threat updates are coalesced and sent with the tick: during a scan or a busy torrent swarm a
        # threat can be updated hundreds of times a second, and each update carries its evidence.
        self._threat_dirty: Dict[str, Dict[str, Any]] = {}
        self._dirty_lock = threading.Lock()
        self.tick_ms = 0.0
        self.detector = Detector(cfg, self.is_lan, self.data_dir, on_change=self._threat_changed)
        self.detector.on_suppressions = lambda lst: self.publish("ignore", lst)
        self.actions = ActionEngine(self, self.data_dir)
        self.setup = SetupPlanner(self, self.data_dir)
        self.geo = Geo(cfg, self.data_dir)
        self.pins = Pins(self.data_dir)
        self.flow_parser = FlowParser()
        col = cfg.get("collectors")
        self.flow_col = UdpCollector("flows", col["bind"], int(col["flow_port"]), self._on_flow, self._allowed)
        self.syslog_col = UdpCollector("syslog", col["bind"], int(col["syslog_port"]), self._on_syslog, self._allowed)

    # ------------------------------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------------------------------
    def start(self, fallback_ports: bool = False) -> None:
        for c in (self.flow_col, self.syslog_col):
            try:
                c.open()
            except OSError as e:
                if fallback_ports:
                    c.port = 0
                    c.open()
                else:
                    c.last_error = "cannot listen on UDP {}: {}".format(c.port, e)
            c.start()
        for name, fn in (("fast", self._fast_loop), ("slow", self._slow_loop), ("switch", self._switch_loop),
                         ("tick", self._tick_loop)):
            t = threading.Thread(target=fn, name="mcc-" + name, daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        self.flow_col.stop()
        self.syslog_col.stop()
        self.name_memory.save()
        self.fingerprints.save()
        for r in (self.ros, self._ros_slow):
            if r:
                r.close()

    def publish(self, event: str, data: Any) -> None:
        self.bus.publish(event, data)

    def refresh_soon(self, *what: str) -> None:
        self._force.update(what or ("meta", "conns"))
        self._wake.set()

    # ------------------------------------------------------------------------------------------
    # connections
    # ------------------------------------------------------------------------------------------
    def connect_router(self, host: str, user: str, password: str, scheme: str = "https", port: int = 0,
                       verify_tls: bool = False, pin: bool = True, repin: bool = False) -> Dict[str, Any]:
        host = host.strip()
        if not host or not user:
            raise RouterOSError("router address and user are required")
        pinned = "" if repin else (self.cfg.get("router.pinned_sha256") or "")
        if self.cfg.get("router.host") != host:
            pinned = ""  # a different router: don't hold it to the old one's certificate
        ros = RouterOS(host, user, password, scheme, port or None, verify_tls, pinned)
        self.router_status.update({"state": "connecting", "error": ""})
        try:
            res = ros.get("/system/resource") or {}
            ident = ros.get("/system/identity") or {}
        except RouterOSError as e:
            self.router_status.update({"state": "error", "error": str(e)})
            raise
        newly_pinned = ""
        if scheme == "https" and pin and not pinned and ros.fingerprint:
            ros.pinned = ros.fingerprint
            newly_pinned = ros.fingerprint
        self.cfg.update({"router": {"host": host, "user": user, "scheme": scheme, "port": port,
                                    "verify_tls": verify_tls,
                                    "pinned_sha256": ros.pinned if scheme == "https" and pin else ""}})
        try:
            self.router_host_ip = socket.gethostbyname(host)
        except OSError:
            self.router_host_ip = host
        self._mcc_ip = ""
        self._table_off.clear()
        old = (self.ros, self._ros_slow)
        with self.lock:
            self.ros, self._ros_slow = ros, ros.clone()
            self.router_status.update({"state": "ok", "error": "", "last_ok": time.time()})
            self.router_info.update({"identity": (ident or {}).get("name", ""), "board": res.get("board-name", ""),
                                     "version": res.get("version", "")})
        for r in old:
            if r:
                r.close()
        self.refresh_soon("meta", "conns", "devices", "log", "dns", "health")
        self.publish("status", self.status())
        return {"identity": self.router_info.get("identity"), "board": res.get("board-name"),
                "version": res.get("version"), "fingerprint": ros.fingerprint, "newly_pinned": newly_pinned,
                "pinned": ros.pinned}

    def disconnect_router(self) -> None:
        with self.lock:
            old = (self.ros, self._ros_slow)
            self.ros = self._ros_slow = None
            self.router_status.update({"state": "disconnected", "error": ""})
        for r in old:
            if r:
                r.close()
        self.publish("status", self.status())

    def connect_switch(self, host: str, user: str, password: str, scheme: str = "http",
                       kind: str = "auto") -> Dict[str, Any]:
        """kind: 'auto' (detect), 'swos' or 'routeros'. CRS switches can run either OS."""
        host = host.strip()
        if kind not in ("auto", "swos", "routeros"):
            raise SwOSError("switch type must be auto, swos or routeros")
        detected = detect_os(host, scheme) if kind == "auto" else kind
        if detected == "unknown":
            raise SwOSError("couldn't reach {} over {}, or it isn't a MikroTik switch (no RouterOS REST API "
                            "and no SwOS web UI answered)".format(host, scheme.upper()))
        if detected == "routeros":
            sw: Any = RouterOSSwitch(host, user or "admin", password or "", scheme)
            try:
                data = sw.read()
            except RouterOSError as e:
                sw.close()
                raise SwOSError("the switch runs RouterOS; its REST API said: {}{}".format(
                    e, " (the www or www-ssl service must be enabled, and the user needs the rest-api policy)"
                    if e.status in (0, 403) else ""))
        else:
            sw = SwOS(host, user or "admin", password or "", scheme, fields=self.cfg.get("switch.fields") or {})
            data = sw.read()  # raises SwOSError
        if not data["ports"]:
            raise SwOSError("connected to the switch but found no ports in its data -- open Switch probe")
        self.cfg.update({"switch": {"host": host, "user": user or "admin", "scheme": scheme, "kind": kind}})
        old, self.swos = self.swos, sw
        if old is not None and hasattr(old, "close"):
            old.close()
        self._sw_prev.clear()
        self.switch_status.update({"state": "ok", "error": "", "last_ok": time.time(), "kind": detected})
        self._ingest_switch(data, time.time())
        self.publish("status", self.status())
        return {"ports": len(data["ports"]), "sys": data["sys"], "kind": detected}

    def disconnect_switch(self) -> None:
        old, self.swos = self.swos, None
        if old is not None and hasattr(old, "close"):
            old.close()
        self.switch_status.update({"state": "off", "error": "", "kind": ""})
        self.switch_ports = []

    # ------------------------------------------------------------------------------------------
    # knowledge used by the other modules
    # ------------------------------------------------------------------------------------------
    def lan_nets(self) -> List[Any]:
        return parse_networks(self.cfg.get("lan_networks") or [])

    def never_block_nets(self) -> List[Any]:
        return parse_networks(self.cfg.get("never_block") or [])

    def is_lan(self, ip: str) -> bool:
        o = ip_obj(ip)
        if o is None:
            return False
        return in_networks(o, self.lan_nets()) or is_local_scope(o)

    def name_of(self, ip: str) -> str:
        return self.ip_names.get(ip) or self.dns_names.get(ip) or self.name_memory.get(ip)

    # -- pinned devices: always on the map, first in the lists ------------------------------------
    def pinned(self) -> Dict[str, Dict[str, Any]]:
        """Current address -> pin (a LAN device's pin follows its MAC to a new address)."""
        devs = self.devices
        return self.pins.resolve(lambda mac: (devs.get(mac) or {}).get("ip") or None)

    def pins_list(self) -> List[Dict[str, Any]]:
        return sorted(({**x, "name": self.name_of(ip) or x.get("name", ""), "lan": self.is_lan(ip)}
                       for ip, x in self.pinned().items()), key=lambda x: x.get("added", 0))

    def set_pin(self, ip: str, pinned: bool) -> List[Dict[str, Any]]:
        lan = self.is_lan(ip)
        dev = next((d for d in self.devices.values() if d.get("ip") == ip), None) if lan else None
        if self.pins.set(ip, pinned, mac=(dev or {}).get("mac", ""), name=self.name_of(ip), lan=lan):
            self.publish("pins", self.pins_list())
        return self.pins_list()

    def mcc_ip(self) -> str:
        adv = (self.cfg.get("collectors.advertise_ip") or "").strip()
        if adv:
            return adv
        if not self._mcc_ip and self.router_host_ip:
            self._mcc_ip = local_ip_toward(self.router_host_ip)
        return self._mcc_ip

    def collector_port(self, kind: str) -> int:
        return (self.flow_col if kind == "flow" else self.syslog_col).port

    def wan_ifaces(self) -> Set[str]:
        configured = set(self.cfg.get("wan.interfaces") or [])
        # a VPN's own default route (in its routing table) doesn't make the tunnel a WAN: its traffic is
        # already counted on the real WAN, encrypted
        return configured or (set(self._wan) - self.vpn_ifaces())

    # -- VPN tunnels -------------------------------------------------------------------------------
    def vpn_ifaces(self) -> Set[str]:
        configured = {str(x).strip() for x in self.cfg.get("vpn.interfaces") or [] if str(x).strip()}
        if configured:
            return configured
        return {n for n, i in list(self.ifaces.items()) if i.get("type") in VPN_TYPES}

    def _path_of(self, direction: str, src: str, dst: str, reply_dst: str) -> str:
        """The router interface a connection used: the interface owning the address it was NAT'd to
        (outbound), or the one it arrived at (inbound); else a tunnel whose own subnet holds the far end."""
        if direction == "out" and reply_dst and reply_dst != src:
            return self.addr_iface.get(reply_dst, "")
        if direction == "in":
            hit = self.addr_iface.get(dst, "")
            if hit:
                return hit
        far = dst if direction == "out" else src
        o = ip_obj(far)
        if o is not None:
            vpn = self.vpn_ifaces()
            for iface, net in self.router_nets:
                if iface in vpn and o.version == net.version and o in net:
                    return iface
        return ""

    def vpn_status(self, now: Optional[float] = None) -> Dict[str, Any]:
        """Each tunnel: up / down / stale (WireGuard: no recent handshake) / disabled, with its peers."""
        stale_s = float(self.cfg.get("detect.vpn_handshake_s") or 300)
        tunnels = []
        with self.lock:
            ifaces = dict(self.ifaces)
            peers = list(self.vpn_peers)
            addrs = dict(self.addr_iface)
        for name in sorted(self.vpn_ifaces()):
            i = ifaces.get(name, {})
            mine = [p for p in peers if p.get("interface") == name]
            hs = [p["handshake_s"] for p in mine if p.get("handshake_s") is not None]
            if not i:
                status = "missing"
            elif i.get("disabled"):
                status = "disabled"
            elif not i.get("running"):
                status = "down"
            elif mine and (not hs or min(hs) > stale_s):
                status = "stale"
            else:
                status = "up"
            ep = next((p["endpoint"] for p in mine if p.get("endpoint")), "")
            tunnels.append({"name": name, "type": i.get("type", ""), "kind": VPN_TYPES.get(i.get("type", ""), "Tunnel"),
                            "status": status, "rx_bps": i.get("rx_bps", 0.0), "tx_bps": i.get("tx_bps", 0.0),
                            "comment": i.get("comment", ""), "addresses": sorted(a for a, n in addrs.items() if n == name),
                            "endpoint": ep, "endpoint_geo": self.geo.locate(ep) if ep else None,
                            "handshake_s": min(hs) if hs else None, "peers": mine})
        return {"tunnels": tunnels, "configured": bool(self.cfg.get("vpn.interfaces")),
                "required": list(self.cfg.get("vpn.required") or [])}

    def _poll_vpn(self, ros: RouterOS, now: float) -> None:
        peers: List[Dict[str, Any]] = []
        vpn = self.vpn_ifaces()
        if any(self.ifaces.get(n, {}).get("type") in ("wg", "wireguard") for n in vpn):
            try:
                rows = ros.get_list("/interface/wireguard/peers")
            except RouterOSError:
                rows = []
            for r in rows:
                if r.get("interface") not in vpn:
                    continue
                hs = r.get("last-handshake")
                peers.append({"interface": r.get("interface"), "name": r.get("name") or r.get("comment") or "",
                              "endpoint": r.get("current-endpoint-address") or r.get("endpoint-address") or "",
                              "port": to_int(r.get("current-endpoint-port") or r.get("endpoint-port")),
                              "handshake_s": parse_duration(hs) if hs else None,
                              "rx": to_int(r.get("rx")), "tx": to_int(r.get("tx")),
                              "allowed": r.get("allowed-address", ""), "disabled": to_bool(r.get("disabled"))})
        with self.lock:
            self.vpn_peers = peers
        self.detector.on_vpn(self.vpn_status(now)["tunnels"], now)

    def protected_ips(self) -> Dict[str, str]:
        p: Dict[str, str] = {}
        for g in self.gateways:
            p[g] = "it is your Internet gateway; blocking it takes the whole network offline"
        for a in self.router_addrs:
            p[a] = "it is one of the router's own addresses"
        if self.router_host_ip:
            p[self.router_host_ip] = "it is the router MCC manages"
        me = self.mcc_ip()
        if me:
            p[me] = "it is the machine MCC runs on"
        return p

    def mgmt_ifaces(self) -> Dict[str, str]:
        """Router interfaces MCC's own management traffic depends on."""
        out: Dict[str, str] = {}
        me = ip_obj(self.mcc_ip())
        rh = ip_obj(self.router_host_ip)
        for iface, net in self.router_nets:
            if (me is not None and me.version == net.version and me in net) or \
                    (rh is not None and str(rh) in self.router_addrs and rh.version == net.version and rh in net):
                out[iface] = "MCC reaches the router through {}".format(iface)
        mac = next((d["mac"] for d in self.devices.values() if d.get("ip") == self.mcc_ip()), "")
        if mac:
            port = self.devices[mac].get("port")
            if port:
                out[port] = "this machine ({}) is plugged into {}".format(self.mcc_ip(), port)
        return out

    def _allowed(self, sender: str) -> bool:
        if sender == self.router_host_ip or sender in self.router_addrs:
            return True
        if sender in (self.cfg.get("collectors.accept_from") or []):
            return True
        return False

    # ------------------------------------------------------------------------------------------
    # collectors
    # ------------------------------------------------------------------------------------------
    def _on_flow(self, data: bytes, sender: str) -> None:
        flows = self.flow_parser.parse(data, sender)
        now = time.time()
        with self.lock:
            self.flow_records += len(flows)
            self._flow_rate.append((now, len(flows)))
            seen = []
            for f in flows:
                g = self.traffic.ingest_flow(f, now)
                if g is not None:
                    self.detector.on_flow(g, now)
                    seen.append(g)
        if seen and self.traffic.source(now) != "conntrack":  # the connection table already covers it
            self.fingerprints.observe(self.mac_of, [_flow_conn(g) for g in seen], self.name_of, now,
                                      self.router_addrs)

    def _on_syslog(self, data: bytes, sender: str) -> None:
        topics, msg = split_syslog(data)
        self.syslog_at = time.time()
        self._ingest_log("syslog", topics, msg, "", detect=True)

    def _ingest_log(self, source: str, topics: str, msg: str, when: str, detect: bool) -> None:
        info = classify(topics, msg)
        now = time.time()
        with self.lock:
            self.log_seq += 1
            entry = {"seq": self.log_seq, "ts": now, "time": when, "source": source, "topics": topics,
                     "level": level_of(topics) if topics else ("fw" if info["kind"] == "fw" else "info"),
                     "kind": info["kind"], "msg": msg}
            if info["kind"] in ("fw", "login_fail", "login_ok"):
                entry["ip"] = info.get("src", "")
            self.logs.append(entry)
            self._log_pending.append(entry)
            if not detect:
                return
            if info["kind"] == "fw":
                self.detector.on_fw(info, now)
            elif info["kind"] in ("login_fail", "login_ok"):
                self.detector.on_login(info["src"], info["user"], info["via"], info["kind"] == "login_ok", now)

    # ------------------------------------------------------------------------------------------
    # pollers
    # ------------------------------------------------------------------------------------------
    def _run_tasks(self, tasks: List[Tuple[str, Callable[[], float], Callable[[RouterOS, float], None]]],
                   which: str) -> None:
        next_at: Dict[str, float] = {}
        while not self._stop.is_set():
            ros = self.ros if which == "fast" else self._ros_slow
            if ros is None:
                self._wake.wait(0.5)
                self._wake.clear()
                continue
            now = time.time()
            for name, every, fn in tasks:
                if self._stop.is_set() or (self.ros is None):
                    break
                forced = name in self._force
                if now < next_at.get(name, 0) and not forced:
                    continue
                self._force.discard(name)
                try:
                    fn(ros, now)
                    self.router_status["tasks"][name] = ""
                    if name == "fast":
                        self.router_status.update({"state": "ok", "error": "", "last_ok": now})
                except CertificateChanged as e:
                    self.router_status.update({"state": "error", "error": str(e)})
                    self.disconnect_router()
                    self.router_status.update({"state": "error", "error": str(e)})
                    break
                except RouterOSError as e:
                    self.router_status["tasks"][name] = str(e)
                    if e.status == 401:
                        self.router_status.update({"state": "error", "error": str(e)})
                        self.disconnect_router()
                        self.router_status.update({"state": "error", "error": str(e)})
                        break
                    if name == "fast":
                        self.router_status.update({"state": "error", "error": str(e)})
                except Exception as e:  # keep polling whatever one table does
                    self.router_status["tasks"][name] = "{}: {}".format(type(e).__name__, e)
                next_at[name] = now + max(0.5, float(every()))
            self._wake.wait(0.25)
            self._wake.clear()

    def _fast_loop(self) -> None:
        p = lambda k: (lambda: self.cfg.get("poll." + k))  # noqa: E731
        self._run_tasks([("fast", p("router_s"), self._poll_fast), ("health", lambda: 10, self._poll_health)], "fast")

    def _slow_loop(self) -> None:
        p = lambda k: (lambda: self.cfg.get("poll." + k))  # noqa: E731
        self._run_tasks([("meta", lambda: 60, self._poll_meta), ("conns", p("conns_s"), self._poll_conns),
                         ("log", p("log_s"), self._poll_log), ("devices", p("devices_s"), self._poll_devices),
                         ("dns", p("dns_s"), self._poll_dns), ("vpn", lambda: 10, self._poll_vpn)], "slow")

    def _poll_fast(self, ros: RouterOS, now: float) -> None:
        res = ros.get("/system/resource") or {}
        rows = ros.get_list("/interface", {".proplist": ".id,name,type,running,disabled,rx-byte,tx-byte,"
                                                        "rx-packet,tx-packet,rx-error,tx-error,rx-drop,tx-drop,"
                                                        "comment,mac-address,link-downs,last-link-up-time"})
        total = to_int(res.get("total-memory"))
        free = to_int(res.get("free-memory"))
        cpu = to_float(res.get("cpu-load"))
        with self.lock:
            self.router_info.update({
                "board": res.get("board-name", ""), "version": res.get("version", ""),
                "arch": res.get("architecture-name", ""), "cpu": cpu, "cpu_count": to_int(res.get("cpu-count"), 1),
                "uptime": res.get("uptime", ""), "uptime_s": parse_duration(res.get("uptime", "")),
                "mem_total": total, "mem_used": max(0, total - free),
                "hdd_total": to_int(res.get("total-hdd-space")), "hdd_free": to_int(res.get("free-hdd-space"))})
            self.health_hist.append((now, cpu, (total - free) * 100.0 / total if total else 0.0))
            seen = set()
            wan = self.wan_ifaces()
            for r in rows:
                name = r.get("name", "")
                if not name:
                    continue
                seen.add(name)
                rx, tx = to_int(r.get("rx-byte")), to_int(r.get("tx-byte"))
                prev = self._if_prev.get(name)
                rx_bps = tx_bps = 0.0
                if prev and now > prev[0] and rx >= prev[1] and tx >= prev[2]:
                    dt = now - prev[0]
                    rx_bps, tx_bps = (rx - prev[1]) * 8 / dt, (tx - prev[2]) * 8 / dt
                self._if_prev[name] = (now, rx, tx)
                if prev:
                    self.iface_hist[name].append((now, rx_bps, tx_bps))
                self.ifaces[name] = {
                    "id": r.get(".id"), "name": name, "type": r.get("type", ""), "comment": r.get("comment", ""),
                    "running": to_bool(r.get("running")), "disabled": to_bool(r.get("disabled")),
                    "rx_bps": rx_bps, "tx_bps": tx_bps, "rx_bytes": rx, "tx_bytes": tx,
                    "rx_err": to_int(r.get("rx-error")), "tx_err": to_int(r.get("tx-error")),
                    "rx_drop": to_int(r.get("rx-drop")), "tx_drop": to_int(r.get("tx-drop")),
                    "mac": r.get("mac-address", ""), "link_downs": to_int(r.get("link-downs")),
                    "wan": name in wan}
            for gone in set(self.ifaces) - seen:
                del self.ifaces[gone]
            states = {n: {"up": i["running"], "disabled": i["disabled"]} for n, i in self.ifaces.items()
                      if i["type"] in ("ether", "wlan", "wifi", "vlan", "pppoe-out", "lte", "sfp", "") or
                      n.startswith(("ether", "sfp", "combo", "wlan", "wifi", "qsfp"))}
        self.detector.on_links("router", states, now)
        self.detector.on_health(cpu, self.router_info.get("temp"), now)

    def _poll_health(self, ros: RouterOS, now: float) -> None:
        try:
            h = ros.get("/system/health")
        except RouterOSError as e:
            if e.status in (400, 404):
                return
            raise
        vals: Dict[str, float] = {}
        if isinstance(h, list):
            for row in h:
                if isinstance(row, dict) and row.get("name"):
                    vals[row["name"]] = to_float(row.get("value"))
        elif isinstance(h, dict):
            vals = {k: to_float(v) for k, v in h.items() if not k.startswith(".")}
        temp = next((vals[k] for k in ("cpu-temperature", "temperature", "board-temperature1", "sfp-temperature")
                     if k in vals), None)
        with self.lock:
            self.router_info.update({"temp": temp, "voltage": vals.get("voltage"),
                                     "health": {k: v for k, v in vals.items()}})

    def _poll_meta(self, ros: RouterOS, now: float) -> None:
        ident = ros.get("/system/identity") or {}
        addrs, nets, owner = set(), [], {}
        for base in ("/ip/address", "/ipv6/address"):
            try:
                rows = ros.get_list(base)
            except RouterOSError:
                continue
            for r in rows:
                a = r.get("address", "")
                if not a:
                    continue
                try:
                    iface = ipaddress.ip_interface(a)
                except ValueError:
                    continue
                addrs.add(str(iface.ip))
                owner[str(iface.ip)] = r.get("interface", "")
                nets.append((r.get("interface", ""), iface.network))
        gws, wan = set(), set()
        try:
            for r in ros.get_list("/ip/route", {"dst-address": "0.0.0.0/0"}):
                if r.get("routing-table", "main") != "main":
                    continue  # e.g. a VPN's own table: policy routing, not the router's Internet uplink
                if to_bool(r.get("active", "true")) or r.get("active") is None:
                    gw = str(r.get("immediate-gw") or r.get("gateway") or "")
                    ip, _, ifn = gw.partition("%")
                    if ip_obj(ip):
                        gws.add(ip)
                    if ifn:
                        wan.add(ifn)
        except RouterOSError:
            pass
        try:
            for m in ros.get_list("/interface/list/member"):
                if m.get("list") == "WAN" and m.get("interface"):
                    wan.add(m["interface"])
        except RouterOSError:
            pass
        with self.lock:
            self.router_info["identity"] = ident.get("name", self.router_info.get("identity", ""))
            self.router_addrs, self.router_nets, self.gateways, self._wan = addrs, nets, gws, wan
            self.addr_iface = owner
        self._refresh_entries()

    def _refresh_entries(self) -> None:
        entries = self.actions.entries()
        with self.lock:
            self.entries = entries
            self.blocked = {e["ip"] for e in entries if e["list"] == BLOCK_LIST}

    def _poll_conns(self, ros: RouterOS, now: float) -> None:
        rows = ros.get_list("/ip/firewall/connection", {
            ".proplist": ".id,src-address,dst-address,reply-src-address,reply-dst-address,protocol,orig-bytes,"
                         "repl-bytes,orig-rate,repl-rate,tcp-state"})
        with self.lock:
            conns = self.traffic.ingest_conns(rows, now)
        self.detector.on_conns(conns, now)
        self.fingerprints.observe(self.mac_of, conns, self.name_of, now, self.router_addrs)
        required = set(self.cfg.get("vpn.required") or [])
        if required:
            vpn = self.vpn_ifaces()
            # path known (NAT'd to an interface address) and not a tunnel: it got out directly
            bypass = [c for c in conns if c["local"] in required and c["dir"] != "lan" and c["via"] and c["via"] not in vpn]
            if bypass:
                self.detector.on_vpn_bypass(bypass, now)
        if "meta" in self._force or now - getattr(self, "_entries_at", 0) > 15:
            self._entries_at = now
            self._refresh_entries()

    def _poll_log(self, ros: RouterOS, now: float) -> None:
        rows = ros.get_list("/log", {".proplist": ".id,time,topics,message"})
        if not rows:
            return

        def num(r: Dict[str, Any]) -> int:
            try:
                return int(str(r.get(".id", "")).lstrip("*"), 16)
            except ValueError:
                return 0

        ids = [num(r) for r in rows]
        top = max(ids)
        first = self._last_log_id < 0
        start = self._last_log_id
        if not first and top < start:
            start = -1  # the router rebooted and its log ids started over
        syslog_live = time.time() - self.syslog_at < 120
        new = [(i, r) for i, r in zip(ids, rows) if i > start]
        if first:
            new = new[-200:]  # some history for the screen, but don't alert on the past
        for _, r in new:
            topics = r.get("topics", "")
            if syslog_live and set(topics.split(",")) & {"firewall", "critical", "interface"}:
                continue  # syslog already delivered it
            self._ingest_log("router", topics, r.get("message", ""), r.get("time", ""), detect=not first)
        self._last_log_id = top

    def _poll_devices(self, ros: RouterOS, now: float) -> None:
        leases, arp, hosts = [], [], []
        try:
            leases = ros.get_list("/ip/dhcp-server/lease")  # incl. class-id (DHCP option 60) where reported
        except RouterOSError:
            pass
        arp = ros.get_list("/ip/arp")
        try:
            hosts = ros.get_list("/interface/bridge/host")
        except RouterOSError:
            pass
        port_of = {}
        for h in hosts:
            if not to_bool(h.get("local")) and h.get("mac-address"):
                port_of[h["mac-address"].upper()] = h.get("on-interface") or h.get("interface", "")
        devs: Dict[str, Dict[str, Any]] = {}
        for l in leases:
            mac = (l.get("mac-address") or l.get("active-mac-address") or "").upper()
            if not mac:
                continue
            devs[mac] = {"mac": mac, "ip": l.get("active-address") or l.get("address", ""),
                         "name": l.get("comment") or l.get("host-name") or "", "hostname": l.get("host-name", ""),
                         "class_id": l.get("class-id", ""), "dhcp": True, "status": l.get("status", ""), "static": not to_bool(l.get("dynamic")),
                         "last_seen": l.get("last-seen", ""), "iface": ""}
        for a in arp:
            mac = (a.get("mac-address") or "").upper()
            ip = a.get("address", "")
            if not mac or not ip:
                continue
            d = devs.setdefault(mac, {"mac": mac, "ip": ip, "name": a.get("comment", ""), "hostname": "",
                                      "class_id": "", "dhcp": False, "status": a.get("status", "") or "arp",
                                      "static": not to_bool(a.get("dynamic")), "last_seen": "", "iface": ""})
            d["iface"] = a.get("interface", "")
            if not d.get("ip"):
                d["ip"] = ip
        neighbors = self._optional_table(ros, "/ip/neighbor", now)
        nb_mac = {(n.get("mac-address") or "").upper(): n for n in neighbors if n.get("mac-address")}
        nb_ip = {n.get("address"): n for n in neighbors if n.get("address")}
        wifi: Dict[str, Dict[str, Any]] = {}
        for path in WIFI_TABLES:
            for r in self._optional_table(ros, path, now):
                mac = (r.get("mac-address") or "").upper()
                if mac:
                    wifi.setdefault(mac, {"interface": r.get("interface", ""), "ssid": r.get("ssid", ""),
                                          "band": r.get("band", ""),
                                          "signal": r.get("signal") or r.get("signal-strength") or r.get("rx-signal") or ""})
        wifi_ifaces = {n for n, i in list(self.ifaces.items()) if i.get("type") in ("wlan", "wifi", "wifiwave2", "cap")}
        for mac, d in devs.items():
            d["port"] = port_of.get(mac, "")
            w = wifi.get(mac) or ({"interface": d["port"]} if d["port"] in wifi_ifaces else None)
            nb = nb_mac.get(mac) or nb_ip.get(d.get("ip"))
            d["vendor"] = self.vendors.lookup(mac)
            d["identity"] = identify(d, d["vendor"], self.fingerprints.hints(mac), nb, w)
        names = {d["ip"]: d["name"] for d in devs.values() if d.get("ip") and d.get("name")}
        with self.lock:
            self.devices = devs
            self.mac_of = {d["ip"]: mac for mac, d in devs.items() if d.get("ip")}
            self.ip_names = names
        self.name_memory.remember("device", names, now)
        self.detector.on_devices(list(devs.values()), now)

    def _optional_table(self, ros: RouterOS, path: str, now: float) -> List[Dict[str, Any]]:
        """A table only some routers have (a package, or a menu of a newer version): [] when it's missing."""
        if now < self._table_off.get(path, 0):
            return []
        try:
            return ros.get_list(path)
        except RouterOSError:
            self._table_off[path] = now + RETRY_TABLE_S
            return []

    def identify_mac(self, mac: str) -> Dict[str, Any]:
        """What MCC knows about a MAC: its vendor, and its identity if it's on the network."""
        mac = ":".join(normalise_mac(mac)[i:i + 2] for i in range(0, 12, 2))
        vendor = self.vendors.lookup(mac)
        dev = self.devices.get(mac)
        ident = dev["identity"] if dev and dev.get("identity") else identify({"mac": mac}, vendor,
                                                                             self.fingerprints.hints(mac))
        return {"mac": mac, "vendor": vendor, "device": dev, "identity": ident}

    def _poll_dns(self, ros: RouterOS, now: float) -> None:
        try:
            rows = ros.get_list("/ip/dns/cache")
        except RouterOSError:
            return
        names = {}
        for r in rows:
            if r.get("type", "A") in ("A", "AAAA"):
                data = r.get("data") or r.get("address") or ""
                if ip_obj(data) and r.get("name"):
                    names[data] = r["name"].rstrip(".")
        with self.lock:
            self.dns_names = names
        self.name_memory.remember("dns", names, now)

    def _switch_loop(self) -> None:
        while not self._stop.is_set():
            sw = self.swos
            if sw is None:
                self._stop.wait(1.0)
                continue
            now = time.time()
            try:
                data = sw.read()
                self._ingest_switch(data, now)
                self.switch_status.update({"state": "ok", "error": "", "last_ok": now})
            except (SwOSError, RouterOSError) as e:
                self.switch_status.update({"state": "error", "error": str(e)})
            except Exception as e:
                self.switch_status.update({"state": "error", "error": "{}: {}".format(type(e).__name__, e)})
            self._stop.wait(max(1.0, float(self.cfg.get("poll.switch_s") or 5)))

    def _ingest_switch(self, data: Dict[str, Any], now: float) -> None:
        ports = []
        for p in data.get("ports", []):
            n = p["n"]
            rx_bps, tx_bps = p.get("rx_rate_bps"), p.get("tx_rate_bps")
            if rx_bps is None and p.get("rx_bytes") is not None and p.get("tx_bytes") is not None:
                prev = self._sw_prev.get(n)
                rx_bps = tx_bps = None
                if prev and now > prev[0] and p["rx_bytes"] >= prev[1] and p["tx_bytes"] >= prev[2]:
                    dt = now - prev[0]
                    rx_bps, tx_bps = (p["rx_bytes"] - prev[1]) * 8 / dt, (p["tx_bytes"] - prev[2]) * 8 / dt
                self._sw_prev[n] = (now, p["rx_bytes"], p["tx_bytes"])
            q = dict(p)
            q["rx_bps"], q["tx_bps"] = rx_bps, tx_bps
            if rx_bps is not None:
                self.switch_hist[n].append((now, rx_bps, tx_bps or 0.0))
            ports.append(q)
        with self.lock:
            self.switch_ports = ports
            self.switch_sys = data.get("sys", {})
        self.detector.on_links("switch", {p["name"] or str(p["n"]): {"up": bool(p.get("link")),
                                                                    "disabled": p.get("enabled") is False}
                                          for p in ports if p.get("link") is not None}, now)

    # ------------------------------------------------------------------------------------------
    # snapshots
    # ------------------------------------------------------------------------------------------
    def _threat_changed(self, t: Dict[str, Any]) -> None:
        # its own lock: this runs inside the detector's lock, and snapshot() takes hub -> detector
        with self._dirty_lock:
            self._threat_dirty[t["id"]] = t

    def _tick_loop(self) -> None:
        while not self._stop.is_set():
            t0 = time.time()
            try:
                self.detector.tick(t0)
                snap = self.snapshot(t0)
                self.detector.on_hosts(snap["traffic"]["hosts"], t0)
                with self.lock:
                    logs, self._log_pending = self._log_pending, []
                with self._dirty_lock:
                    dirty, self._threat_dirty = self._threat_dirty, {}
                if dirty:
                    with self.detector.lock:  # a stable copy: the detector keeps updating the originals
                        changed = [copy.deepcopy(t) for t in dirty.values()]
                    for t in changed:
                        self.publish("threat", t)
                if logs:
                    self.publish("logs", logs[-300:])
                self.publish("tick", snap)
            except Exception as e:
                self.router_status["tasks"]["tick"] = "{}: {}".format(type(e).__name__, e)
            took = time.time() - t0
            self.tick_ms = self.tick_ms * 0.8 + took * 1000 * 0.2
            self._stop.wait(max(0.1, 1.0 - took))

    def flow_rate(self, now: float) -> float:
        recent = [n for t, n in self._flow_rate if now - t <= 60]
        return sum(recent) / 60.0

    def status(self) -> Dict[str, Any]:
        now = time.time()
        r = dict(self.router_status)
        r["tasks"] = {k: v for k, v in r.get("tasks", {}).items() if v}
        r["host"] = self.cfg.get("router.host")
        r["stale"] = bool(self.ros) and now - r.get("last_ok", 0) > 15
        return {
            "router": r,
            "switch": dict(self.switch_status, host=self.cfg.get("switch.host")),
            "flows": dict(self.flow_col.status(), records=self.flow_records, rate=self.flow_rate(now),
                          live=now - self.flow_col.last_at < 120, templates_waiting=self.flow_parser.waiting),
            "syslog": dict(self.syslog_col.status(), live=now - self.syslog_at < 120),
            "traffic_source": self.traffic.source(now),
            "mcc_ip": self.mcc_ip() if self.ros else "",
            # how hard the server is working: a tick near 1000 ms means this machine can't keep up
            "server": {"tick_ms": round(self.tick_ms, 1), "clients": len(self.bus.clients),
                       "ticks_skipped": self.bus.ticks_skipped, "resyncs": self.bus.resyncs},
        }

    def snapshot(self, now: Optional[float] = None) -> Dict[str, Any]:
        now = now or time.time()
        pins = {ip: self.is_lan(ip) for ip in self.pinned()}
        with self.lock:
            traffic = self.traffic.snapshot(now, self.blocked, self.detector.subject_threats(), limit_pairs=80,
                                            pinned=pins, vpn=self.vpn_ifaces(),
                                            vpn_required=self.cfg.get("vpn.required") or [])
            ifaces = sorted(self.ifaces.values(), key=lambda i: (not i["wan"], i["name"]))
            wan = [i for i in ifaces if i["wan"]]
            info = dict(self.router_info)
            ports = list(self.switch_ports)
        threats = self.detector.list()
        open_t = [t for t in threats if t["status"] == "open"]
        return {
            "t": now,
            "level": self.detector.level(now),
            "status": self.status(),
            "router": info,
            "ifaces": ifaces,
            "wan": {"rx_bps": sum(i["rx_bps"] for i in wan), "tx_bps": sum(i["tx_bps"] for i in wan),
                    "names": [i["name"] for i in wan],
                    "down_mbps": self.cfg.get("wan.down_mbps"), "up_mbps": self.cfg.get("wan.up_mbps")},
            "switch": {"ports": ports, "sys": self.switch_sys},
            "traffic": traffic,
            "vpn": self.vpn_status(now),
            "geo": self._geo_view(traffic),
            "counts": {"threats_open": len(open_t),
                       "threats_new": len([t for t in open_t if now - t.get("first_ts", 0) < 300]),
                       "actions_pending": len([a for a in self.actions.items.values() if a["status"] == "pending"]),
                       "blocked": len(self.blocked), "devices": len(self.devices), "log_seq": self.log_seq},
        }

    def public_addrs(self) -> List[str]:
        return sorted(a for a in self.router_addrs if ip_obj(a) is not None and not is_local_scope(a))

    def _geo_view(self, traffic: Dict[str, Any]) -> Dict[str, Any]:
        """Locate the Internet peers (in place) and roll them up by country."""
        countries: Dict[str, Dict[str, Any]] = {}
        located = 0
        for p in traffic["peers"]:
            g = self.geo.locate(p["ip"])
            p["geo"] = g
            if not g:
                continue
            located += 1
            c = countries.setdefault(g["cc"] or "?", {"cc": g["cc"], "country": g["country"], "up": 0.0, "down": 0.0,
                                                      "peers": 0, "threat": ""})
            c["up"] += p["up"]
            c["down"] += p["down"]
            c["peers"] += 1
            if p.get("threat"):
                c["threat"] = p["threat"]
        return {"home": self.geo.home(self.public_addrs()), "source": "database" if self.geo.db else
                "demo" if self.geo.demo else "none", "dbip": bool(self.geo.db and "dbip" in self.geo.db.path.name.lower()),
                "located": located, "peers": len(traffic["peers"]),
                "countries": sorted(countries.values(), key=lambda c: -(c["up"] + c["down"]))[:20]}

    def full_state(self) -> Dict[str, Any]:
        now = time.time()
        snap = self.snapshot(now)
        with self.lock:
            hist = {n: [[round(t, 1), round(rx), round(tx)] for t, rx, tx in h] for n, h in self.iface_hist.items()}
            health = [[round(t, 1), round(c, 1), round(m, 1)] for t, c, m in self.health_hist]
            sw = {str(n): [[round(t, 1), round(rx), round(tx)] for t, rx, tx in h] for n, h in self.switch_hist.items()}
            logs = list(self.logs)[-500:]
        return {"snapshot": snap, "history": {"ifaces": hist, "health": health, "switch": sw},
                "threats": self.detector.list(), "actions": self.actions.list(), "logs": logs,
                "entries": self.entries, "config": self.cfg.public(), "rules": RULES,
                "ignore": self.detector.suppressions_list(), "categories": CATEGORIES, "pins": self.pins_list()}

    def devices_view(self) -> List[Dict[str, Any]]:
        known = self.detector.known_devices()
        pins = self.pinned()
        snap_hosts = {h["ip"]: h for h in self.traffic.snapshot(time.time())["hosts"]}
        out = []
        with self.lock:
            for mac, d in self.devices.items():
                k = known.get(mac, {})
                h = snap_hosts.get(d.get("ip", ""), {})
                out.append(dict(d, known=bool(k.get("known", True)), first_seen=k.get("first_seen", ""),
                                pinned=d.get("ip", "") in pins,
                                up=h.get("up", 0.0), down=h.get("down", 0.0), conns=h.get("conns", 0),
                                threat=self.detector.subject_threats().get(d.get("ip", ""), ""),
                                quarantined=any(e["ip"] == d.get("ip") and e["list"] == QUARANTINE_LIST
                                                for e in self.entries)))
        out.sort(key=lambda d: (not d["pinned"], d["known"], [int(x) if x.isdigit() else 0 for x in d.get("ip", "").split(".")]))
        return out

    def host_view(self, ip: str) -> Dict[str, Any]:
        det = self.traffic.host_detail(ip)
        for p in det["pairs"]:  # where each path goes (the drawer and the globe single it out)
            other = p["remote"] if p["local"] == ip else p["local"]
            p["other_geo"] = None if self.is_lan(other) else self.geo.locate(other)
        dev = next((d for d in self.devices.values() if d.get("ip") == ip), None)
        threats = [t for t in self.detector.list() if t.get("subject") == ip or t.get("target") == ip]
        actions = [a for a in self.actions.list() if a["params"].get("ip") == ip]
        entries = [e for e in self.entries if e["ip"] == ip]
        return {"ip": ip, "name": self.name_of(ip), "lan": self.is_lan(ip), "device": dev, "threats": threats[:20],
                "actions": actions[:20], "entries": entries, "protected": self.protected_ips().get(ip, ""),
                "blocklisted": self.detector.blocklist.contains(ip), "geo": self.geo.locate(ip),
                "pinned": ip in self.pinned(), **det}


def _flow_conn(g: Dict[str, Any]) -> Dict[str, Any]:
    """A flow record in the connection table's shape (for device fingerprints): the port is the responder's."""
    initiator_side = g["src"] == g["local"]
    if g["dir"] in ("out", "lan"):
        port = g["dport"] if initiator_side else g["sport"]
    else:
        port = g["sport"] if initiator_side else g["dport"]
    return {"local": g["local"], "remote": g["remote"], "dir": g["dir"], "proto": g.get("proto_name", ""), "port": port}
