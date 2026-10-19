"""The network's shape: Internet -> router -> switches (and access points) -> devices, with each link's ports,
state and live rate. Worked out from what MCC already reads, never by probing:

  * the router's neighbor table (LLDP / CDP / MNDP): which router port a switch or access point is on, and
    the switch's own port facing it (interface-name);
  * the router's bridge host table: which router port each MAC is behind;
  * each switch's learnt MAC table (SwOS !dhost.b, RouterOS bridge hosts): which switch port each device and
    each other switch is on. A switch that sees another switch on a port other than its uplink is that
    switch's parent -- that is how switches chained behind each other are found;
  * the switch's uplink set by hand in Setup, which wins over all of the above.

Where MCC can't tell, it says so: several devices on one router port with nothing known between them hang
off a "switch or access point" placeholder, and a link that is a guess is marked inferred.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .util import ip_obj

INFRA_CAPS = ("bridge", "wlan-ap", "router", "repeater")


def _port_of_neighbor(n: Dict[str, Any]) -> str:
    """RouterOS lists a neighbor's interface as 'ether2' or 'ether2,bridge': the port, not the bridge."""
    parts = [p.strip() for p in str(n.get("interface") or "").split(",") if p.strip()]
    return next((p for p in parts if not p.startswith("bridge")), parts[0] if parts else "")


def _host_ip(host: str) -> str:
    h = (host or "").strip()
    if h.startswith("["):
        h = h[1:].partition("]")[0]
    elif h.count(":") == 1:
        h = h.split(":")[0]
    return h if ip_obj(h) else ""


def build(router: Dict[str, Any], ifaces: List[Dict[str, Any]], devices: List[Dict[str, Any]],
          neighbors: List[Dict[str, Any]], switches: List[Dict[str, Any]],
          host_rates: Optional[Dict[str, Tuple[float, float]]] = None, vpn: Iterable[str] = ()) -> Dict[str, Any]:
    """router: {identity, board, version}; ifaces: the router's interfaces (name, type, running, disabled, rx_bps,
    tx_bps, mac, wan); devices: hub device records (mac, ip, name, hostname, port, identity); neighbors: the
    router's /ip/neighbor rows; switches: [{id, label, host, state, error, kind, sys, ports, topo: {hosts: [(mac,
    port)], neighbors, table}, uplink: {parent, port, local_port}}]; host_rates: ip -> (up, down) Internet bps."""
    host_rates = host_rates or {}
    vpn = set(vpn)
    nodes: Dict[str, Dict[str, Any]] = {}
    notes: List[str] = []
    ifx = {i["name"]: i for i in ifaces}
    router_macs = {str(i.get("mac") or "").upper() for i in ifaces if i.get("mac")}

    def node(nid: str, **kw: Any) -> Dict[str, Any]:
        n = nodes.setdefault(nid, {"id": nid, "parent": "", "port": "", "local_port": "", "how": "", "inferred": False})
        n.update(kw)
        return n

    node("internet", type="internet", label="Internet")
    rlabel = router.get("identity") or "router"
    node("router", type="router", label=rlabel, sub=" · ".join(x for x in (router.get("board"), router.get("version") and
                                                                              router["version"].split()[0]) if x),
         parent="internet", how="wan")
    wans = [i for i in ifaces if i.get("wan")]
    nodes["router"]["port"] = ", ".join(i["name"] for i in wans)

    # -- managed switches: who they are --------------------------------------------------------------------------
    sw_macs: Dict[str, Set[str]] = {}
    for s in switches:
        macs = {m.upper() for m in [s.get("sys", {}).get("mac", "")] + list(s.get("sys", {}).get("macs") or []) if m}
        ip = _host_ip(s.get("host", ""))
        for d in devices:
            if ip and d.get("ip") == ip and d.get("mac"):
                macs.add(d["mac"].upper())
        sw_macs[s["id"]] = macs
    sw_by_mac = {m: sid for sid, ms in sw_macs.items() for m in ms}

    def match_switch(n: Dict[str, Any]) -> str:
        mac = str(n.get("mac-address") or "").upper()
        if mac in sw_by_mac:
            return sw_by_mac[mac]
        for s in switches:
            ident = (s.get("sys") or {}).get("identity")
            if (n.get("address") and n.get("address") == _host_ip(s.get("host", ""))) or (ident and n.get("identity") == ident):
                if mac:
                    sw_macs[s["id"]].add(mac)
                return s["id"]
        return ""

    sw_nb: Dict[str, Dict[str, Any]] = {}
    infra_nb: List[Dict[str, Any]] = []
    for n in neighbors:
        sid = match_switch(n)
        if sid:
            sw_nb.setdefault(sid, n)
            continue
        caps = str(n.get("system-caps-enabled") or n.get("system-caps") or "").lower()
        if any(c in caps for c in INFRA_CAPS) or str(n.get("platform", "")).lower().startswith("mikrotik"):
            infra_nb.append(n)
    sw_by_mac = {m: sid for sid, ms in sw_macs.items() for m in ms}
    dev_port = {str(d.get("mac") or "").upper(): d.get("port") or "" for d in devices}

    tables = {s["id"]: [(m.upper(), p) for m, p in (s.get("topo") or {}).get("hosts") or []] for s in switches}
    # each switch's uplink port: where the router's own MACs are learnt, else what it told the router (LLDP/MNDP)
    uplink: Dict[str, str] = {}
    for s in switches:
        sid = s["id"]
        manual = (s.get("uplink") or {}).get("local_port") or ""
        seen = [p for m, p in tables[sid] if m in router_macs]
        uplink[sid] = manual or (max(set(seen), key=seen.count) if seen else "") or \
            str((sw_nb.get(sid) or {}).get("interface-name") or "")

    def located(mac: str) -> List[Tuple[str, str]]:
        """Managed switches that learnt this MAC on a port other than their uplink: [(switch, port)]."""
        return [(sid, p) for sid, rows in tables.items() for m, p in rows if m == mac and p != uplink.get(sid)]

    # -- managed switches: where they hang ------------------------------------------------------------------------
    for s in switches:
        sid = s["id"]
        sysd = s.get("sys") or {}
        node("sw:" + sid, type="switch", managed=True, switch_id=sid, label=s.get("label") or sid,
             sub=" · ".join(x for x in (sysd.get("model"), sysd.get("version") and (sysd["version"] if "RouterOS" in str(
                 sysd["version"]) else "SwOS " + str(sysd["version"]))) if x),
             state=s.get("state", "off"), error=s.get("error", ""), ip=_host_ip(s.get("host", "")),
             mac=sorted(sw_macs[sid])[0] if sw_macs[sid] else "", local_port=uplink[sid],
             table=(s.get("topo") or {}).get("table"))
    for s in switches:
        sid, n = s["id"], nodes["sw:" + s["id"]]
        manual = s.get("uplink") or {}
        if manual.get("parent"):
            parent = "router" if manual["parent"] == "router" else "sw:" + manual["parent"]
            if parent in nodes and parent != n["id"]:
                n.update(parent=parent, port=manual.get("port", ""), how="set in Setup")
                continue
        cands = [(t, p) for m in sw_macs[sid] for t, p in located(m) if t != sid]
        if cands:
            # chained switches: the nearest one is the parent -- the one with no other candidate behind that port
            others = {t for t, _ in cands}
            best = [(t, p) for t, p in cands if not any(m2 in sw_macs.get(o, set()) for o in others if o != t
                                                       for m2, p2 in tables[t] if p2 == p)]
            t, p = (best or cands)[0]
            n.update(parent="sw:" + t, port=p, how="MAC table of {}".format(nodes["sw:" + t]["label"]))
            continue
        nb = sw_nb.get(sid)
        rport = _port_of_neighbor(nb) if nb else next((dev_port[m] for m in sw_macs[sid] if dev_port.get(m)), "")
        n.update(parent="router", port=rport, how="neighbor discovery" if nb else "bridge host table" if rport else "")
        if not rport:
            n["inferred"] = True
            notes.append("{}: MCC can't tell which router port it's on. Set its uplink in Setup › Switches.".format(n["label"]))
    for s in switches:
        if not (s.get("topo") or {}).get("table") and s.get("state") == "ok":
            notes.append("{}: no MAC table from the switch, so devices behind it are placed by router port only."
                         .format(nodes["sw:" + s["id"]]["label"]))

    # -- access points and switches MCC doesn't manage, from the router's neighbor table ------------------------
    infra_macs: Set[str] = set()
    infra_ips: Set[str] = set()
    for nb in infra_nb:
        mac = str(nb.get("mac-address") or "").upper()
        caps = str(nb.get("system-caps-enabled") or nb.get("system-caps") or "").lower()
        nid = "nb:" + (mac or nb.get("identity", "?"))
        kind = "ap" if "wlan-ap" in caps else "router" if "router" in caps and "bridge" not in caps else "switch"
        loc = located(mac) if mac else []
        parent, port = ("sw:" + loc[0][0], loc[0][1]) if loc else ("router", _port_of_neighbor(nb))
        node(nid, type=kind, managed=False, label=nb.get("identity") or mac, ip=nb.get("address", ""), mac=mac,
             sub=" · ".join(x for x in (nb.get("board") or str(nb.get("system-description", "")).split(",")[0],
                                        nb.get("version")) if x),
             parent=parent, port=port, local_port=str(nb.get("interface-name") or ""), how="neighbor discovery")
        infra_macs.add(mac)
        infra_ips.add(nb.get("address", ""))

    # -- devices --------------------------------------------------------------------------------------------------
    trunk: Dict[str, Set[str]] = defaultdict(set)  # parent -> its ports that lead to more infrastructure
    for n in nodes.values():
        if n["type"] in ("switch", "ap", "unknown") and n["parent"]:
            trunk[n["parent"]].add(n["port"])
    sw_ips = {nodes["sw:" + s["id"]]["ip"] for s in switches}
    on_port: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for d in devices:
        mac, ip = str(d.get("mac") or "").upper(), d.get("ip", "")
        if not mac or mac in sw_by_mac or mac in infra_macs or (ip and (ip in sw_ips or ip in infra_ips)):
            continue
        ident = d.get("identity") or {}
        dn = node("dev:" + mac, type="device", label=d.get("name") or d.get("hostname") or (
            ident.get("label") if ident.get("confidence") not in (None, "none") else "") or ip or mac,
                  ip=ip, mac=mac, kind=ident.get("kind", ""), guess=ident.get("label", ""))
        loc = [(sid, p) for sid, p in located(mac) if p not in trunk.get("sw:" + sid, set())]
        if loc:
            sid, p = loc[0]
            dn.update(parent="sw:" + sid, port=p, how="MAC table")
        elif d.get("port"):
            on_port[d["port"]].append(dn)
        else:
            dn.update(parent="router", port="", how="ARP only (no port seen)", inferred=True)
    for rport, devs in on_port.items():
        tops = [n for n in nodes.values() if n["parent"] == "router" and n["port"] == rport and n["type"] != "device"]
        if tops:  # behind a switch or access point on that port, exact port unknown
            for dn in devs:
                dn.update(parent=tops[0]["id"], port="", how="router port {}".format(rport), inferred=True)
        elif len(devs) > 1:  # several devices on one port: something connects them
            ph = node("unknown:" + rport, type="unknown", managed=False, label="Unknown switch / AP",
                      sub="{} devices on {}".format(len(devs), rport), parent="router", port=rport, how="inferred",
                      inferred=True)
            for dn in devs:
                dn.update(parent=ph["id"], port="", how="router port {}".format(rport), inferred=True)
        else:
            devs[0].update(parent="router", port=rport, how="bridge host table")

    # -- links: state and live rate ------------------------------------------------------------------------------
    sw_ports = {s["id"]: {p.get("name"): p for p in s.get("ports") or []} for s in switches}
    kids: Dict[Tuple[str, str], int] = defaultdict(int)
    for n in nodes.values():
        if n["parent"]:
            kids[(n["parent"], n["port"])] += 1
    links = []
    for n in nodes.values():
        if not n["parent"]:
            continue
        link: Dict[str, Any] = {"from": n["parent"], "to": n["id"], "port": n["port"], "local_port": n["local_port"],
                                "up": None, "down_bps": None, "up_bps": None, "speed": "", "how": n["how"],
                                "inferred": n["inferred"]}
        parent = nodes.get(n["parent"], {})
        alone = kids[(n["parent"], n["port"])] == 1 and n["port"]
        if n["id"] == "router":
            link.update(up=any(i.get("running") for i in wans) if wans else None,
                        down_bps=sum(i.get("rx_bps", 0) for i in wans), up_bps=sum(i.get("tx_bps", 0) for i in wans))
        elif parent.get("type") == "router" and n["port"] in ifx:
            i = ifx[n["port"]]
            link["up"] = bool(i.get("running")) and not i.get("disabled")
            if alone:
                link.update(down_bps=i.get("tx_bps"), up_bps=i.get("rx_bps"))
        elif parent.get("managed") and parent.get("switch_id"):
            p = sw_ports.get(parent["switch_id"], {}).get(n["port"])
            if p:
                link.update(up=bool(p.get("link")), speed=p.get("speed") or "")
                if alone:
                    link.update(down_bps=p.get("tx_bps"), up_bps=p.get("rx_bps"))
        if link["down_bps"] is None and n["type"] == "device" and n.get("ip") in host_rates:
            up, down = host_rates[n["ip"]]
            link.update(down_bps=down, up_bps=up)
        if n["type"] == "switch" and n.get("managed") and n.get("local_port"):  # its own end: link and speed
            p = sw_ports.get(n["switch_id"], {}).get(n["local_port"])
            if p:
                link["up"] = bool(p.get("link")) if link["up"] is None else link["up"] and bool(p.get("link"))
                link["speed"] = link["speed"] or p.get("speed") or ""
        links.append(link)
    for n in nodes.values():
        n["children"] = sum(1 for m in nodes.values() if m["parent"] == n["id"])
    order = {"internet": 0, "router": 1, "switch": 2, "ap": 3, "unknown": 4, "device": 5}
    return {"nodes": sorted(nodes.values(), key=lambda n: (order.get(n["type"], 9), n["label"].lower())),
            "links": links, "notes": notes}
