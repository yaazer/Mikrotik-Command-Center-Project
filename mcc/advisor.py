"""Advisor: what to improve, and how, on top of what the threat detector reports.

Two jobs, both read-only until you approve something:

  analyze()    reads the router's configuration and MCC's own measurements and produces *findings* -- a
               security weakness or a traffic problem, with the evidence, why it matters, and either a fix
               MCC can propose or exact manual steps. Nothing here changes the router.
  build_fix()  turns a finding's fix into a proposal for the action engine (mcc/actions.py): the same
               review -> confirm -> undo -> audit-log path every other response uses.

Rules this module keeps to:
  * A fix never touches the way MCC reaches the router (the service it connects through, its own address).
  * Fixes that change a setting remember the old value when they run, so Undo can put it back.
  * Whatever a fix *creates* carries the `mcc:` tag (or the `mcc-` name prefix for queue types, which have
    no comment), so Setup > "Remove everything MCC added" finds it.
  * Findings that pull in opposite directions know about each other: FastTrack skips queues, so while a
    queue shapes the WAN, FastTrack is not offered.
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .actions import TAG, ActionEngine, ActionError
from .routeros import RouterOSError
from .util import now_iso

SEVERITY = {"high": 0, "medium": 1, "low": 2, "info": 3}
REFRESH_S = 300

# Services that send passwords in clear text, and what to do instead.
INSECURE_SERVICES = {
    "telnet": ("Telnet is on", "Telnet sends the router password in clear text to anyone who can see the traffic.",
               "use SSH, or Winbox"),
    "ftp": ("FTP is on", "FTP sends the router password in clear text, and nothing here needs it.",
            "copy files with SFTP (the SSH service) instead"),
    "api": ("The plain API is on", "The unencrypted API (port 8728) sends the router password in clear text.",
            "use api-ssl, or the REST API over HTTPS"),
    "www": ("Unencrypted web access is on", "The router's web interface and REST API over plain HTTP send the "
            "password in clear text.", "use www-ssl (HTTPS)"),
}
# Services someone could reach from the Internet if the firewall let them.
MGMT_SERVICES = ("winbox", "ssh", "www-ssl", "api-ssl", "www", "api", "telnet", "ftp")
# Firewall-rule fields that make a rule specific. A "drop everything from the WAN" rule has none of them.
NARROWING = ("protocol", "dst-port", "src-port", "port", "src-address", "dst-address", "src-address-list",
             "dst-address-list", "connection-state", "connection-nat-state", "tcp-flags", "icmp-options",
             "connection-mark", "packet-mark", "dst-address-type", "src-address-type", "limit", "dscp")
THREAT_RULES = ["bruteforce", "login", "scan", "sweep"]  # detections a hardened router answers
ERR_STEP = 20  # new interface errors/drops between two checks before it's worth a finding
FLAP_STEP = 3  # new link-down events between two checks
LINGER_S = 1800  # a link problem stays listed this long after the last new error
CPU_HIGH = 60.0
DNS_TEST_NAME = "one.one.one.one"  # resolves to 1.1.1.1, which answers pings
PING_COUNT = 3


def _norm(v: Any) -> str:
    s = str(v).strip().lower()
    return {"yes": "true", "no": "false"}.get(s, s)


def _is_true(v: Any) -> bool:
    return _norm(v) == "true"


def _in_net(ip: str, net: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
    except ValueError:
        return False


def _mbps(v: float) -> str:
    return "{}M".format(int(v)) if abs(v - round(v)) < 1e-9 else "{}k".format(int(round(v * 1000)))


class Advisor:
    def __init__(self, hub: Any, data_dir: Path):
        self.hub = hub
        self.path = Path(data_dir) / "advisor.json"
        self.log_path = Path(data_dir) / "advisor.log.jsonl"
        self.lock = threading.RLock()
        self.findings: List[Dict[str, Any]] = []
        self.analyzed_at = 0.0
        self.unreadable: List[str] = []
        self.dismissed: Dict[str, Dict[str, Any]] = self._load()
        self._busy = threading.Lock()
        self._prev: Dict[str, float] = {}  # counters at the last check: errors and flaps are about *new* ones
        self._seen: Dict[str, float] = {}  # finding key -> when its problem was last seen getting worse

    # -- persistence -------------------------------------------------------------------------
    def _load(self) -> Dict[str, Dict[str, Any]]:
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
            return d.get("dismissed", {}) if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"dismissed": self.dismissed}, indent=1), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass

    def _audit(self, event: str, key: str, note: str = "") -> None:
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"at": now_iso(), "event": event, "key": key, "note": note}) + "\n")
        except OSError:
            pass

    # -- dismissing --------------------------------------------------------------------------
    def dismiss(self, key: str, days: float = 0, note: str = "") -> Dict[str, Any]:
        if not any(f["key"] == key for f in self.findings):
            raise ActionError("no such finding {!r}".format(key))
        until = time.time() + days * 86400 if days else 0
        with self.lock:
            self.dismissed[key] = {"at": now_iso(), "until": until, "note": note[:200]}
            self._save()
        self._audit("dismissed", key, note)
        self.hub.publish("advisor", self.view())
        return self.view()

    def restore(self, key: str) -> Dict[str, Any]:
        with self.lock:
            self.dismissed.pop(key, None)
            self._save()
        self._audit("restored", key)
        self.hub.publish("advisor", self.view())
        return self.view()

    def _is_dismissed(self, key: str, now: float) -> bool:
        d = self.dismissed.get(key)
        if not d:
            return False
        if d.get("until") and d["until"] < now:
            self.dismissed.pop(key, None)  # a snooze that ran out
            return False
        return True

    # -- views -------------------------------------------------------------------------------
    def view(self) -> Dict[str, Any]:
        now = time.time()
        with self.lock:
            live = [f for f in self.findings if not self._is_dismissed(f["key"], now)]
            hidden = [dict(f, dismissed=self.dismissed[f["key"]]) for f in self.findings
                      if f["key"] in self.dismissed and self._is_dismissed(f["key"], now)]
            return {"findings": live, "dismissed": hidden, "analyzed_at": self.analyzed_at,
                    "unreadable": list(self.unreadable), "connected": self.hub.ros is not None}

    def counts(self) -> Dict[str, int]:
        v = self.view()
        return {"open": len(v["findings"]), "high": len([f for f in v["findings"] if f["severity"] == "high"])}

    # -- analysis ----------------------------------------------------------------------------
    def refresh_soon(self) -> None:
        threading.Thread(target=self.refresh, daemon=True).start()

    def refresh(self, ros: Any = None, now: Optional[float] = None) -> Dict[str, Any]:
        ros = ros or self.hub._ros_slow or self.hub.ros
        if ros is None:
            return self.view()
        self._busy.acquire()  # a refresh already running may have read the router before your change: wait, re-read
        try:
            ctx = self._gather(ros)
            found: List[Dict[str, Any]] = []
            for check in (self._check_exposure, self._check_upnp, self._check_services, self._check_ssh,
                          self._check_update, self._check_sqm, self._check_fasttrack, self._check_links,
                          self._check_talkers):
                try:
                    found.extend(check(ctx))
                except Exception as e:  # one broken check never hides the rest
                    ctx["unreadable"].append("{}: {}".format(check.__name__.lstrip("_"), e))
            found.sort(key=lambda f: (SEVERITY.get(f["severity"], 9), f["category"], f["title"]))
            with self.lock:
                self.findings = found
                self.analyzed_at = now or time.time()
                self.unreadable = ctx["unreadable"]
            self.hub.publish("advisor", self.view())
        finally:
            self._busy.release()
        return self.view()

    def _gather(self, ros: Any) -> Dict[str, Any]:
        """Everything the checks read, once. A table the router won't give us is noted and skipped."""
        ctx: Dict[str, Any] = {"unreadable": [], "ros": ros}

        def read(name: str, path: str, single: bool = False) -> Any:
            try:
                if single:
                    out = ros.get(path)
                    return out[0] if isinstance(out, list) and out else (out if isinstance(out, dict) else {})
                return ros.get_list(path)
            except RouterOSError as e:
                ctx["unreadable"].append("{} ({})".format(name, e))
                return {} if single else []

        ctx["services"] = read("services", "/ip/service")
        ctx["upnp"] = read("UPnP", "/ip/upnp", True)
        ctx["ssh"] = read("SSH", "/ip/ssh", True)
        ctx["update"] = read("update status", "/system/package/update", True)
        ctx["filter"] = read("firewall filter", "/ip/firewall/filter")
        ctx["filter_ok"] = not any(u.startswith("firewall filter") for u in ctx["unreadable"])
        ctx["queues"] = read("queues", "/queue/simple")
        ctx["qtree"] = read("queue tree", "/queue/tree")
        ctx["nat"] = read("NAT", "/ip/firewall/nat")
        with self.hub.lock:
            ctx["info"] = dict(self.hub.router_info)
            ctx["ifaces"] = {n: dict(i) for n, i in self.hub.ifaces.items()}
            ctx["wan"] = sorted(self.hub.wan_ifaces())
            ctx["hist"] = {n: list(self.hub.iface_hist.get(n, ())) for n in self.hub.wan_ifaces()}
            ctx["cpu"] = [h[1] for h in list(self.hub.health_hist)[-150:]]
            ctx["hosts"] = [dict(h) for h in self.hub.last_hosts]
            ctx["nets"] = [(i, n) for i, n in self.hub.router_nets]
        ctx["switches"] = self.hub.switches_view()
        ctx["now"] = time.time()
        return ctx

    @staticmethod
    def _f(key: str, category: str, severity: str, title: str, why: str, evidence: Optional[List[str]] = None,
           fix: Optional[Dict[str, Any]] = None, manual: Optional[List[str]] = None,
           needs: Optional[List[str]] = None) -> Dict[str, Any]:
        return {"key": key, "category": category, "severity": severity, "title": title, "why": why,
                "evidence": evidence or [], "fix": fix, "manual": manual or [], "needs": needs or []}

    def _flows_live(self) -> bool:
        """MCC's traffic view and detection are fed by Traffic Flow right now (not merely once set up)."""
        try:
            return bool((self.hub.status().get("flows") or {}).get("live"))
        except Exception:
            return False

    # -- how MCC itself connects (a fix must never cut this) ---------------------------------
    def _mcc_service(self) -> str:
        r = self.hub.cfg.get("router") or {}
        scheme = r.get("scheme", "https")
        return "www-ssl" if scheme == "https" else "www"

    # -- firewall reading --------------------------------------------------------------------
    @staticmethod
    def _enabled(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [r for r in rows if not _is_true(r.get("disabled"))]

    def _wan_input_protected(self, ctx: Dict[str, Any]) -> bool:
        """Is there a general "drop what comes in from the Internet" rule on the input chain, with nothing
        before it that accepts everything? (The stock RouterOS config has one.)"""
        wans = set(ctx["wan"])
        for r in self._enabled([r for r in ctx["filter"] if r.get("chain") == "input"]):
            action = r.get("action")
            general = not any(r.get(k) for k in NARROWING)
            on_wan = r.get("in-interface-list") in ("WAN", "!LAN") or r.get("in-interface") in wans
            if action in ("drop", "reject") and general and on_wan:
                return True
            if action == "accept" and general and (not r.get("in-interface") and not r.get("in-interface-list")):
                return False  # accepts everything before any drop is reached
            if action == "accept" and general and (r.get("in-interface-list") == "WAN" or r.get("in-interface") in wans):
                return False
        return False

    def _allowed_nets(self, ctx_nets: List[Any]) -> List[str]:
        wan = self.hub.wan_ifaces()
        nets = sorted({str(n) for i, n in ctx_nets if i not in wan and getattr(n, "version", 4) == 4})
        me = self.hub.mcc_ip()
        if me and not any(_in_net(me, n) for n in nets):
            nets.append(me + "/32")
        return nets

    # -- checks: security --------------------------------------------------------------------
    def _check_exposure(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not ctx["wan"] or not ctx["filter_ok"] or self._wan_input_protected(ctx):
            return []
        out = [self._f(
            "sec.wan.input", "security", "high", "Nothing stops the Internet from reaching the router itself",
            "The router's firewall has no rule that drops traffic arriving from the Internet on the input chain, "
            "so every service on the router (Winbox, SSH, the web interface, DNS) can be tried by anyone. This "
            "is what port scans and password guessing go after.",
            ["Checked the input chain: no general drop for {}.".format(", ".join(ctx["wan"]))],
            manual=["Do this from the router's own console or Winbox, in Safe Mode, so a mistake rolls itself back.",
                    "Keep the order: accept established/related first, then your LAN and this machine, then drop the "
                    "rest from the Internet:",
                    "/ip firewall filter add chain=input action=accept connection-state=established,related,untracked comment=\"accept established\"",
                    "/ip firewall filter add chain=input action=drop connection-state=invalid comment=\"drop invalid\"",
                    "/ip firewall filter add chain=input action=accept src-address={}/32 comment=\"accept MCC\"".format(
                        self.hub.mcc_ip() or "<MCC's address>"),
                    "/ip firewall filter add chain=input action=accept in-interface-list=LAN comment=\"accept from LAN\"",
                    "/ip firewall filter add chain=input action=drop in-interface-list=WAN comment=\"drop from the Internet\"",
                    "Move the new rules above any rule that accepts everything. MCC doesn't add input rules for you: "
                    "one in the wrong place locks you out of the router, and there is no safe mode over REST."],
            needs=[])]
        out[0]["rules"] = THREAT_RULES
        # While that's open, the next best thing: make the management services answer only your own networks.
        for row in ctx["services"]:
            name = row.get("name", "")
            if name not in MGMT_SERVICES or _is_true(row.get("disabled")) or row.get("address"):
                continue
            if name in INSECURE_SERVICES:
                continue  # these get "turn it off", which is better than restricting
            f = self._f(
                "sec.exposed." + name, "security", "high" if name in ("winbox", "ssh") else "medium",
                "{} answers from anywhere".format(name.upper() if name != "www-ssl" else "HTTPS (www-ssl)"),
                "The {} service accepts connections from any address, and the firewall isn't keeping the Internet "
                "away from it.".format(name),
                ["Service {} on port {}, address list empty.".format(name, row.get("port", "?"))],
                fix={"id": "service_restrict:" + name, "label": "Allow only my networks", "inputs": []},
                needs=["write"])
            f["rules"] = THREAT_RULES
            out.append(f)
        return out

    def _check_fasttrack(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        fwd = self._enabled([r for r in ctx["filter"] if r.get("chain") == "forward"])
        cpu = ctx["cpu"]
        if any(r.get("action") == "fasttrack-connection" for r in fwd) or self._has_queues(ctx) or len(cpu) < 30:
            return []
        avg = sum(cpu) / len(cpu)
        if avg < CPU_HIGH:
            return []
        ev = ["Router CPU averaged {:.0f}% over the last {} readings and FastTrack is off.".format(avg, len(cpu))]
        if self._flows_live():
            ev.append("Heads up: MCC's own traffic view and threat detection read the connection table and flow "
                      "export, and FastTrack hides most of a connection's packets from both.")
        return [self._f(
            "perf.fasttrack", "performance", "medium", "Turn on FastTrack to take load off the router's CPU",
            "FastTrack lets the router forward the packets of an established connection without running each one "
            "through the whole firewall. On most routers it's the single biggest throughput gain.", ev,
            fix={"id": "fasttrack_on", "label": "Turn FastTrack on", "inputs": []}, needs=["write"])]

    # -- checks: reliability and traffic -----------------------------------------------------
    def _worse(self, key: str, value: float, step: float, now: float) -> bool:
        """True while `key`'s counter keeps climbing (by at least `step` since the last check) or did lately."""
        prev = self._prev.get(key)
        self._prev[key] = value
        if prev is not None and value - prev >= step:
            self._seen[key] = now
        return now - self._seen.get(key, 0.0) < LINGER_S

    def _check_links(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        out = []
        now = ctx["now"]
        for name, i in sorted(ctx["ifaces"].items()):
            if i.get("type") not in ("ether", "sfp", "wlan", "wifi") and not name.startswith(("ether", "sfp", "wlan")):
                continue
            bad = self._worse("err:" + name, float(i["rx_err"] + i["tx_err"] + i["rx_drop"] + i["tx_drop"]), ERR_STEP, now)
            flaps = self._worse("flap:" + name, float(i["link_downs"]), FLAP_STEP, now)
            if bad:
                out.append(self._f(
                    "rel.errors." + name, "performance", "medium", "{} is dropping packets".format(name),
                    "Errors and drops on a port mean frames are being lost on the way: slow transfers, retries and "
                    "glitchy calls for whatever is plugged into it.",
                    ["{} errors/drops so far on {}; it's still counting up.".format(
                        i["rx_err"] + i["tx_err"] + i["rx_drop"] + i["tx_drop"], name)],
                    manual=["Reseat or replace the cable first; this is the cause far more often than the port.",
                            "Try another port, or the cable on a different device, to see which part is at fault.",
                            "If the port is at 1G over a long or old cable, forcing 100M is a temporary workaround.",
                            "Queue drops (not errors) on a busy port mean the line is full: see the SQM suggestion."]))
            if flaps:
                out.append(self._f(
                    "rel.flap." + name, "performance", "medium", "{} keeps losing its link".format(name),
                    "A port that goes up and down repeatedly drops everything on it each time, and often "
                    "points to a bad cable, a failing device or a power-saving setting.",
                    ["{} link-down events in total; new ones keep arriving.".format(i["link_downs"])],
                    manual=["Replace the cable.", "Turn off Energy-Efficient Ethernet / green mode on the device "
                            "if it has such a setting.", "Check the device at the other end for power problems."]))
        for sw in ctx["switches"]:
            label = sw.get("label") or sw.get("id")
            for p in sw.get("ports") or []:
                if not p.get("link"):
                    continue
                pn = p.get("name") or str(p.get("n"))
                key = "{}.{}".format(sw["id"], pn)
                if p.get("full_duplex") is False or p.get("speed") == "10M":
                    out.append(self._f(
                        "rel.port." + key, "performance", "medium",
                        "{}: {} is running at {}{}".format(label, pn, p.get("speed") or "?",
                                                          " half duplex" if p.get("full_duplex") is False else ""),
                        "A port that settled on 10 Mbps or half duplex is almost always a bad cable or a "
                        "mismatched setting, not what the device can do. It will be slow and collide under load.",
                        ["{} on {} negotiated {}{}.".format(pn, label, p.get("speed") or "an unknown speed",
                                                           ", half duplex" if p.get("full_duplex") is False else "")],
                        manual=["Replace the cable between this port and the device.",
                                "Make sure both ends are set to auto-negotiate (not one forced).",
                                "Try another port to see whether it follows the cable or the port."]))
                errs = p.get("rx_errors")
                if isinstance(errs, (int, float)) and self._worse("perr:" + key, float(errs), ERR_STEP, now):
                    out.append(self._f(
                        "rel.perr." + key, "performance", "medium", "{}: {} is receiving damaged frames".format(label, pn),
                        "Frames arriving with errors (bad checksum) are discarded and resent: a cable or connector "
                        "problem on that port.", ["{} receive errors so far, still increasing.".format(int(errs))],
                        manual=["Replace the cable and re-seat both ends.", "Check for a damaged SFP or a dirty fibre end."]))
        return out

    def _check_talkers(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        sp = self._wan_speeds(ctx)
        hosts = sorted((h for h in ctx["hosts"] if h.get("down", 0) > 0), key=lambda h: -h["down"])
        if not sp["configured"] or not hosts or sp["seen_down"] < 0.6 * sp["down"]:
            return []
        total = sum(h["down"] for h in hosts)
        top = hosts[0]
        top_mbps = top["down"] / 1e6
        if top["down"] < 0.5 * total or top_mbps < 0.2 * sp["down"]:
            return []
        f = self._f(
            "perf.hog", "performance", "low", "{} is using most of your download".format(top.get("name") or top["ip"]),
            "One device is taking the biggest share of your Internet link while the line is busy. If it's a backup, "
            "an update or a download that's fine, but everything else slows down while it runs.",
            ["{} is pulling {:.0f} Mbps, {:.0f}% of what's coming in ({:.0f}% of your {:g} Mbps line).".format(
                top.get("name") or top["ip"], top_mbps, top["down"] * 100 / total, top_mbps * 100 / sp["down"], sp["down"])]
            + ["Next: {} at {:.0f} Mbps".format(h.get("name") or h["ip"], h["down"] / 1e6) for h in hosts[1:3]],
            manual=["Open the device (click its name) to see what it's talking to and when it started.",
                    "If it's a scheduled job, move it to the night.",
                    "SQM (above, if offered) keeps one device from starving the rest while it runs."])
        f["hosts"] = [h["ip"] for h in hosts[:3]]
        return [f]

    def _check_upnp(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not _is_true(ctx["upnp"].get("enabled")):
            return []
        maps = [r for r in ctx["nat"] if "upnp" in str(r.get("comment", "")).lower()]
        ev = ["UPnP is enabled on the router."]
        if maps:
            ev.append("{} port mapping{} opened by devices: {}".format(
                len(maps), "" if len(maps) == 1 else "s",
                ", ".join(sorted({str(m.get("comment")) for m in maps})[:4])))
        return [self._f(
            "sec.upnp", "security", "medium", "UPnP is on",
            "UPnP lets any device on your network open ports to the Internet on its own, without asking you. "
            "Malware and cheap IoT gear use it to make themselves reachable from outside.", ev,
            fix={"id": "upnp_off", "label": "Turn UPnP off", "inputs": []}, needs=["write"])]

    def _check_services(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        out = []
        mine = self._mcc_service()
        for row in ctx["services"]:
            name = row.get("name", "")
            if name not in INSECURE_SERVICES or _is_true(row.get("disabled")):
                continue
            title, why, instead = INSECURE_SERVICES[name]
            ev = ["Service {} listens on port {}{}.".format(
                name, row.get("port", "?"),
                " from anywhere" if not row.get("address") else " for {}".format(row["address"]))]
            if name == mine:
                out.append(self._f(
                    "sec.svc." + name, "security", "medium", title, why, ev,
                    manual=["MCC is connected to the router through this service, so MCC won't turn it off.",
                            "In Setup, reconnect using HTTPS (the www-ssl service) first, then come back: "
                            "this finding will offer to turn {} off.".format(name)]))
                continue
            out.append(self._f(
                "sec.svc." + name, "security", "high" if name in ("telnet", "ftp") else "medium", title, why, ev,
                fix={"id": "service_off:" + name, "label": "Turn {} off".format(name), "inputs": []},
                needs=["write"]))
            out[-1]["instead"] = instead
        return out

    def _check_ssh(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        ssh_on = any(r.get("name") == "ssh" and not _is_true(r.get("disabled")) for r in ctx["services"])
        if not ssh_on or not ctx["ssh"] or _is_true(ctx["ssh"].get("strong-crypto")):
            return []
        return [self._f(
            "sec.ssh.crypto", "security", "low", "SSH accepts weak ciphers",
            "Without strong-crypto the router's SSH server still offers older, weaker ciphers and key "
            "exchange settings. Modern SSH clients don't need them.",
            ["SSH is enabled and strong-crypto is off."],
            fix={"id": "ssh_strong", "label": "Require strong crypto", "inputs": []}, needs=["write"])]

    # -- checks: housekeeping ----------------------------------------------------------------
    def _check_update(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        u = ctx["update"] or {}
        have, latest = str(u.get("installed-version", "")), str(u.get("latest-version", ""))
        if not have or not latest or have == latest:
            return []
        return [self._f(
            "sys.update", "security", "medium", "RouterOS {} is available (you have {})".format(latest, have),
            "Router updates fix security holes. Routers on the Internet are scanned for known ones constantly.",
            ["Channel: {}. Status: {}.".format(u.get("channel", "?"), u.get("status", "?"))],
            manual=["Back up first: /system backup save name=before-update",
                    "Read the release notes for {} (MikroTik's changelog).".format(latest),
                    "Install it: /system package update install  (the router reboots; MCC reconnects on its own).",
                    "MCC doesn't install updates itself: a bad update with nobody at the router can't be undone "
                    "from here."])]

    # -- checks: traffic ---------------------------------------------------------------------
    def _wan_speeds(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Configured line speed if set; otherwise the best the WAN has been seen to do (an estimate)."""
        cfg_down = float(self.hub.cfg.get("wan.down_mbps") or 0)
        cfg_up = float(self.hub.cfg.get("wan.up_mbps") or 0)
        pk_down = pk_up = 0.0
        n = 0
        for rows in ctx["hist"].values():
            n = max(n, len(rows))
            if rows:
                rx = sorted(r[1] for r in rows)
                tx = sorted(r[2] for r in rows)
                pk_down = max(pk_down, rx[int(len(rx) * 0.98) - 1 if len(rx) > 1 else 0] / 1e6)
                pk_up = max(pk_up, tx[int(len(tx) * 0.98) - 1 if len(tx) > 1 else 0] / 1e6)
        return {"down": cfg_down, "up": cfg_up, "seen_down": pk_down, "seen_up": pk_up, "samples": n,
                "configured": cfg_down > 0 and cfg_up > 0}

    def _has_queues(self, ctx: Dict[str, Any]) -> bool:
        return any(not _is_true(q.get("disabled")) for q in ctx["queues"]) or bool(ctx["qtree"])

    def _check_sqm(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        wans = ctx["wan"]
        if len(wans) != 1 or self._has_queues(ctx):
            return []  # several uplinks (or queues already in place) need a hand-made design
        sp = self._wan_speeds(ctx)
        down = sp["down"] or max(5.0, float(-(-sp["seen_down"] // 5) * 5))
        up = sp["up"] or max(1.0, float(-(-sp["seen_up"] // 1)))
        ev = ["No queues are set up on the router, so the WAN link is first-come first-served."]
        sev = "low"
        if sp["configured"]:
            busy = max(sp["seen_down"] / sp["down"], sp["seen_up"] / sp["up"])
            ev.append("Busiest recent moments reached {:.0f}% of the {:g}/{:g} Mbps you set in Settings."
                      .format(busy * 100, sp["down"], sp["up"]))
            if busy > 0.7:
                sev = "medium"
        else:
            ev.append("Seen up to {:.0f} Mbps down / {:.0f} Mbps up lately. Set your real line speed in Settings "
                      "(or in the box when you apply this) for a better result.".format(sp["seen_down"], sp["seen_up"]))
        ft = [r for r in ctx["filter"] if r.get("action") == "fasttrack-connection" and not _is_true(r.get("disabled"))]
        if ft:
            ev.append("FastTrack is on; it skips queues, so applying this turns it off (you'll see that in the "
                      "proposal).")
        return [self._f(
            "perf.sqm", "performance", sev, "Add smart queue management (SQM) on the Internet link",
            "When a download or backup fills the line, every other connection waits in the same queue: video "
            "calls stutter and pages hang (bufferbloat). A fair queue (fq-codel) held just under your line speed "
            "keeps latency low while it's busy.", ev,
            fix={"id": "sqm_enable", "label": "Set up SQM…", "inputs": [
                {"name": "down_mbps", "label": "Download speed (Mbps)", "type": "number", "default": down,
                 "min": 1, "max": 100000, "estimate": not sp["configured"]},
                {"name": "up_mbps", "label": "Upload speed (Mbps)", "type": "number", "default": up,
                 "min": 0.5, "max": 100000, "estimate": not sp["configured"]},
                {"name": "percent", "label": "Shape to this % of it", "type": "number", "default": 95,
                 "min": 50, "max": 100, "hint": "Slightly under the real speed so the queue forms here, not at "
                                                  "your ISP."}]}, needs=["write"])]

    # -- building fixes ----------------------------------------------------------------------
    def build_fix(self, fix_id: str, inputs: Dict[str, Any], ros: Any) -> Dict[str, Any]:
        """The pieces of a proposal for one fix. Raises ActionError when it isn't safe or isn't needed."""
        change = ActionEngine._change
        base, _, arg = fix_id.partition(":")
        if base == "upnp_off":
            cur = ros.get("/ip/upnp") or {}
            if not _is_true(cur.get("enabled")):
                raise ActionError("UPnP is already off.")
            ch = change("POST", "/ip/upnp/set", {"enabled": "no"}, note="Turn UPnP off")
            ch.update(pre={"read": "/ip/upnp", "field": "enabled", "equals": "true"},
                      capture={"read": "/ip/upnp", "fields": ["enabled"]})
            return {"finding_key": "sec.upnp", "title": "Turn UPnP off",
                    "summary": "Stop devices on your network from opening Internet-facing ports by themselves.",
                    "changes": [ch],
                    "warnings": ["Anything that relied on UPnP to get a port forward (game consoles, some torrent "
                                 "clients, video-call apps) will stop being reachable from outside until you add "
                                 "a port forward for it by hand. Games usually still connect out fine."],
                    "undo_why": "puts UPnP back the way it was"}
        if base == "service_off":
            if arg not in INSECURE_SERVICES:
                raise ActionError("MCC only offers to turn off telnet, ftp, api and www.")
            if arg == self._mcc_service():
                raise ActionError("MCC is connected through {}; reconnect over HTTPS first.".format(arg))
            row = next((r for r in ros.get_list("/ip/service") if r.get("name") == arg), None)
            if row is None:
                raise ActionError("the router has no {} service.".format(arg))
            if _is_true(row.get("disabled")):
                raise ActionError("{} is already off.".format(arg))
            path = "/ip/service/{}".format(row[".id"])
            ch = change("PATCH", path, {"disabled": "true"}, target=arg, note="Turn the {} service off".format(arg))
            ch.update(pre={"read": path, "field": "disabled", "equals": "false"},
                      capture={"read": path, "fields": ["disabled"]})
            return {"finding_key": "sec.svc." + arg, "title": "Turn {} off".format(arg),
                    "summary": "{} Disable the {} service. {}".format(
                        INSECURE_SERVICES[arg][1], arg, INSECURE_SERVICES[arg][2].capitalize() + " instead."),
                    "changes": [ch],
                    "warnings": ["Anything still using {} (old scripts, backup tools, other devices) stops "
                                 "working.".format(arg)],
                    "undo_why": "turns the {} service back on".format(arg)}
        if base == "ssh_strong":
            cur = ros.get("/ip/ssh") or {}
            if _is_true(cur.get("strong-crypto")):
                raise ActionError("SSH already requires strong crypto.")
            ch = change("POST", "/ip/ssh/set", {"strong-crypto": "yes"}, note="Require strong SSH crypto")
            ch.update(pre={"read": "/ip/ssh", "field": "strong-crypto", "equals": "false"},
                      capture={"read": "/ip/ssh", "fields": ["strong-crypto"]})
            return {"finding_key": "sec.ssh.crypto", "title": "Require strong SSH crypto",
                    "summary": "Make the router's SSH server refuse older, weaker ciphers.",
                    "changes": [ch],
                    "warnings": ["Very old SSH clients (some embedded devices and scripts) may no longer be able "
                                 "to connect."],
                    "undo_why": "puts the SSH setting back"}
        if base == "sqm_enable":
            return self._build_sqm(inputs, ros)
        if base == "service_restrict":
            return self._build_restrict(arg, ros)
        if base == "fasttrack_on":
            return self._build_fasttrack(ros)
        raise ActionError("unknown fix {!r}".format(fix_id))

    def _build_restrict(self, name: str, ros: Any) -> Dict[str, Any]:
        change = ActionEngine._change
        if name not in MGMT_SERVICES:
            raise ActionError("unknown service {!r}".format(name))
        row = next((r for r in ros.get_list("/ip/service") if r.get("name") == name), None)
        if row is None or _is_true(row.get("disabled")):
            raise ActionError("the router has no running {} service.".format(name))
        if row.get("address"):
            raise ActionError("{} is already limited to {}.".format(name, row["address"]))
        me = self.hub.mcc_ip()
        if name == self._mcc_service() and not me:
            raise ActionError("MCC can't tell its own address, so it can't be sure {} stays reachable for it. "
                              "Set the address in Settings first.".format(name))
        wan = self.hub.wan_ifaces()
        nets = self._allowed_nets(list(self.hub.router_nets))
        if not nets:
            raise ActionError("couldn't work out which networks to allow.")
        if name == self._mcc_service() and not any(_in_net(me, n) for n in nets):
            raise ActionError("the allowed list wouldn't include MCC's own address ({}); not applying.".format(me))
        path = "/ip/service/{}".format(row[".id"])
        warnings = ["Connections to {} from anywhere else (a VPN network the router doesn't have an "
                    "interface on, a remote site, your phone on mobile data) stop working until you "
                    "add that address back.".format(name),
                    "MCC's own address ({}) is always included, so MCC keeps its access.".format(me or "unknown")]
        ch = change("PATCH", path, {"address": ",".join(nets)}, target=name,
                    note="{} answers only to {}".format(name, ", ".join(nets)))
        ch.update(pre={"read": path, "field": "address", "equals": ""}, capture={"read": path, "fields": ["address"]})
        own = name == self._mcc_service()
        if own:
            warnings.insert(0, "DANGER: MCC reaches the router through {n}. If the router sees MCC at a different "
                               "address than {me} (MCC in a VM or container behind NAT), this cuts MCC off, and Undo "
                               "can't reach the router either: you would have to undo it from the router's console."
                               .format(n=name, me=me))
        return {"finding_key": "sec.exposed." + name, "title": "Limit {} to your networks".format(name),
                "summary": "Make the {} service answer only to {}; the Internet and any other address are refused."
                           .format(name, ", ".join(nets)),
                "changes": [ch], "warnings": warnings,
                "undo_why": "puts the service's address list back (open to all)",
                "risky": name == self._mcc_service()}

    def _build_fasttrack(self, ros: Any) -> Dict[str, Any]:
        change = ActionEngine._change
        rules = ros.get_list("/ip/firewall/filter")
        fwd = [r for r in rules if r.get("chain") == "forward"]
        if any(r.get("action") == "fasttrack-connection" and not _is_true(r.get("disabled")) for r in fwd):
            raise ActionError("FastTrack is already on.")
        if any(not _is_true(q.get("disabled")) for q in ros.get_list("/queue/simple")) or ros.get_list("/queue/tree"):
            raise ActionError("There are queues on this router, and FastTrack would make them do nothing.")
        changes: List[Dict[str, Any]] = []
        body = {"chain": "forward", "action": "fasttrack-connection", "connection-state": "established,related",
                "comment": "{} FastTrack".format(TAG)}
        first = next((r for r in fwd if not _is_true(r.get("disabled")) and r.get(".id")), None)
        if first:
            body["place-before"] = first[".id"]
        changes.append(change("PUT", "/ip/firewall/filter", body, note="send established connections the fast path"))
        warnings = ["FastTrack skips the firewall (beyond the first packets), mangle rules and queues for the "
                    "connections it takes. Anything that needs to see every packet of a connection stops seeing it."]
        if not any(r.get("action") == "accept" and "established" in str(r.get("connection-state", ""))
                   and not _is_true(r.get("disabled")) for r in fwd):
            warnings.append("There is no rule accepting established connections in the forward chain, which "
                            "FastTrack relies on: add one right after this rule.")
        if self._flows_live():
            warnings.append("MCC's traffic view, flow export and threat detection will see only the start of "
                            "fast-tracked connections: rates and the device-to-device view get less accurate.")
        return {"finding_key": "perf.fasttrack", "title": "Turn FastTrack on",
                "summary": "Add a forward rule so established connections skip the full firewall path.",
                "changes": changes, "warnings": warnings, "undo_why": "removes the FastTrack rule"}

    def _num(self, inputs: Dict[str, Any], name: str, lo: float, hi: float) -> float:
        try:
            v = float(inputs.get(name))
        except (TypeError, ValueError):
            raise ActionError("{} must be a number".format(name.replace("_", " ")))
        if not lo <= v <= hi:
            raise ActionError("{} must be between {:g} and {:g}".format(name.replace("_", " "), lo, hi))
        return v

    def _build_sqm(self, inputs: Dict[str, Any], ros: Any) -> Dict[str, Any]:
        change = ActionEngine._change
        down = self._num(inputs, "down_mbps", 1, 100000)
        up = self._num(inputs, "up_mbps", 0.5, 100000)
        pct = self._num(inputs, "percent", 50, 100)
        wans = sorted(self.hub.wan_ifaces())
        if len(wans) != 1:
            raise ActionError("SQM here is for one Internet link; with several, shape each by hand.")
        wan = wans[0]
        if any(not _is_true(q.get("disabled")) for q in ros.get_list("/queue/simple")) or ros.get_list("/queue/tree"):
            raise ActionError("The router already has queues; MCC won't stack another set on top.")
        nets = sorted({str(net) for iface, net in self.hub.router_nets
                       if iface not in self.hub.wan_ifaces() and getattr(net, "version", 4) == 4})
        if not nets:
            raise ActionError("couldn't work out which networks sit behind the router.")
        warnings: List[str] = []
        changes: List[Dict[str, Any]] = []
        ft = [r for r in ros.get_list("/ip/firewall/filter")
              if r.get("action") == "fasttrack-connection" and not _is_true(r.get("disabled"))]
        if ft:
            cpus = self.hub.router_info.get("cpu_count") or 1
            warnings.append("FastTrack is turned off so the queue can see this traffic. That costs router CPU at "
                            "high speeds ({} on this router: {}). Watch the CPU after applying; Undo turns FastTrack "
                            "back on.".format("board " + str(self.hub.router_info.get("board", "?")),
                                              "{} core{}".format(cpus, "" if cpus == 1 else "s")))
        warnings.append("Only traffic between your networks and the Internet link {} is shaped; traffic between "
                        "your own networks is untouched.".format(wan))
        changes.append(change("PUT", "/queue/type", {"name": "mcc-fqcodel", "kind": "fq-codel"},
                              note="a fair queue (fq-codel) type for MCC to use"))
        changes.append(change("PUT", "/queue/simple", {
            "name": "mcc-sqm", "target": ",".join(nets), "dst": wan,
            "max-limit": "{}/{}".format(_mbps(up * pct / 100), _mbps(down * pct / 100)),
            "queue": "mcc-fqcodel/mcc-fqcodel", "comment": "{} SQM on {}".format(TAG, wan)},
            note="hold the Internet link at {:g}% of {:g}/{:g} Mbps with a fair queue".format(pct, down, up)))
        # last, so a queue that the router refuses never leaves FastTrack switched off
        for r in ft:
            path = "/ip/firewall/filter/{}".format(r[".id"])
            ch = change("PATCH", path, {"disabled": "true"}, target='[find comment="{}"]'.format(r.get("comment", "")),
                        note="Turn FastTrack off: it skips queues, so SQM would do nothing while it's on")
            ch.update(pre={"read": path, "field": "disabled", "equals": "false"},
                      capture={"read": path, "fields": ["disabled"]})
            changes.append(ch)
        return {"finding_key": "perf.sqm", "title": "Set up SQM on {}".format(wan),
                "summary": "Keep latency low when the line is full: shape {} to {:g}% of {:g} Mbps down / {:g} Mbps "
                           "up with fq-codel.".format(wan, pct, down, up),
                "changes": changes, "warnings": warnings,
                "undo_why": "removes the queue and its type" + (", and turns FastTrack back on" if ft else "")}

    # -- diagnostics -------------------------------------------------------------------------
    def diagnose(self) -> Dict[str, Any]:
        """Is the Internet link healthy? Pings from the router itself: gateway, then addresses, then a name."""
        ros = self.hub.ros
        if ros is None:
            raise ActionError("not connected to the router")
        gws = sorted(self.hub.gateways)
        probes: List[Dict[str, str]] = []
        for g in gws[:2]:
            probes.append({"id": "gateway:" + g, "label": "Your Internet gateway ({})".format(g), "address": g})
        probes += [{"id": "internet:1.1.1.1", "label": "The Internet by address (1.1.1.1)", "address": "1.1.1.1"},
                   {"id": "internet:8.8.8.8", "label": "The Internet by address (8.8.8.8)", "address": "8.8.8.8"},
                   {"id": "dns", "label": "A name lookup ({})".format(DNS_TEST_NAME), "address": DNS_TEST_NAME}]

        def run(p: Dict[str, str]) -> Dict[str, Any]:
            res = {"id": p["id"], "label": p["label"], "address": p["address"], "ok": False, "loss": None,
                   "ms": None, "detail": ""}
            try:
                # /ping is the documented REST path (the CLI's /tool/ping is its long form)
                rows = ros.clone().request("POST", "/ping", {"address": p["address"], "count": str(PING_COUNT)})
            except RouterOSError as e:
                msg = str(e)
                low = msg.lower()
                if e.status in (401, 403) or "permission" in low or "not allowed" in low:
                    res["detail"] = "The router refused: MCC's user needs the `test` policy to ping."
                    res["policy"] = True
                elif "resolve" in low or "dns name" in low or "no such host" in low:
                    res["detail"] = "The router couldn't look the name up."  # a real answer: DNS is what's broken
                else:
                    # 404 (no such command), a timeout, a dropped connection: the test didn't run, which says
                    # nothing about the Internet
                    res["detail"] = "The test couldn't run: {}".format(msg or "no reply from the router")
                    res["unavailable"] = True
                return res
            last = (rows or [{}])[-1] if isinstance(rows, list) else {}
            try:
                res["loss"] = float(str(last.get("packet-loss", "100")).rstrip("%"))
            except ValueError:
                res["loss"] = 100.0
            avg = str(last.get("avg-rtt", ""))
            try:
                res["ms"] = float(avg.rstrip("ms")) if avg else None
            except ValueError:
                res["ms"] = None
            # for a name, "ok" means it resolved (the request ran); replies are the addresses' business
            res["ok"] = res["loss"] < 100 or p["id"] == "dns"
            res["detail"] = ("{:g}% lost".format(res["loss"]) if res["loss"] else "no loss") + \
                ("" if res["ms"] is None else ", {:g} ms".format(res["ms"]))
            if p["id"] == "dns" and res["loss"] >= 100:
                res["detail"] = "the name resolved, but the host didn't answer a ping"
            return res

        with ThreadPoolExecutor(max_workers=len(probes)) as pool:
            results = list(pool.map(run, probes))
        return {"at": time.time(), "results": results, "verdict": self._verdict(results, bool(gws))}

    @staticmethod
    def _verdict(results: List[Dict[str, Any]], have_gw: bool) -> Dict[str, Any]:
        if any(r.get("policy") for r in results):
            return {"level": "warn", "title": "The router wouldn't run the test",
                    "text": "Give MCC's RouterOS user the `test` policy (/user group set mcc policy=+test), then "
                            "run this again."}
        if any(r.get("unavailable") for r in results):
            bad = next(r for r in results if r.get("unavailable"))
            return {"level": "warn", "title": "The test couldn't run",
                    "text": "{} This says nothing about your Internet link either way.".format(bad["detail"])}
        by = {r["id"].split(":")[0]: [x for x in results if x["id"].split(":")[0] == r["id"].split(":")[0]]
              for r in results}
        gw, net, dns = by.get("gateway", []), by.get("internet", []), by.get("dns", [])
        if gw and not any(r["ok"] for r in gw):
            return {"level": "bad", "title": "The router can't reach your Internet gateway",
                    "text": "Check the cable or modem/ONT between the router and your ISP, and that the WAN port "
                            "has an address (DHCP lease or PPPoE session)."}
        if net and not any(r["ok"] for r in net):
            return {"level": "bad", "title": "The gateway answers but the Internet doesn't",
                    "text": "The problem is past your router: your ISP, or the modem. Restart the modem; if it "
                            "persists, call the ISP."}
        if dns and not dns[0]["ok"]:
            return {"level": "bad", "title": "The Internet works but names don't resolve",
                    "text": "DNS is broken. Check Setup > the router's /ip dns servers; try 1.1.1.1 or 9.9.9.9."}
        slow = [r for r in net + gw if r["ok"] and ((r["loss"] or 0) >= 5 or (r["ms"] or 0) > 150)]
        if slow:
            return {"level": "warn", "title": "The link is up but it's struggling",
                    "text": "Loss or high latency to {}. If it only happens when the line is busy, SQM (see the "
                            "Advisor) is the usual fix.".format(slow[0]["address"])}
        return {"level": "ok", "title": "The Internet link looks healthy",
                "text": "The gateway, the Internet and DNS all answer quickly with no loss."}
