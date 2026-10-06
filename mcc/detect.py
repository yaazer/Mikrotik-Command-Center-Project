"""Threat detection.

Rules look at firewall log lines (syslog or the router's memory log), login failures, flow
records, new rows in the connection table, interface state, router health and the device list.
A threat is keyed by (rule, subject) so a scan that lasts ten minutes is one threat whose count
and evidence grow, not a thousand alerts. Each threat carries *suggested* responses; nothing is
done until you pick one and confirm it (see actions.py).
"""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Set, Tuple

from .traffic import service_label
from .util import ip_obj, now_iso

# How far an "ignore" reaches. Narrowest first; the console offers them in this order.
IGNORE_SCOPES = {
    "exact": "this rule, this exact case",
    "subject": "this rule, anything involving this address",
    "subject_any": "every rule, for this address",
}
IGNORE_DURATIONS = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "0": 0}

MITIGATION_GRACE_S = 120  # > the router's 1 min active-flow timeout

SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

RULES: Dict[str, Dict[str, str]] = {
    "scan": {"name": "Port scan", "why": "One outside address probed many different ports on your network. "
             "Scanners look for open services to attack next."},
    "sweep": {"name": "Network sweep", "why": "One outside address probed the same port on many of your addresses, "
              "looking for every machine that answers on it."},
    "bruteforce": {"name": "Service brute force", "why": "Many new connections to a login service (SSH, RDP, "
                   "Winbox...) from one address in a short time: password guessing."},
    "login": {"name": "Router login failures", "why": "The router itself logged repeated failed logins from one "
              "address."},
    "flood": {"name": "Flood", "why": "One address is sending packets far faster than normal traffic: a "
              "denial-of-service attempt or a broken client."},
    "blocklist": {"name": "Blocklisted address", "why": "Traffic to or from an address on your blocklist "
                  "(data/blocklist.txt). A LAN host talking *to* one may be compromised."},
    "fanout": {"name": "Host fan-out", "why": "A LAN host opened connections to an unusual number of different "
               "Internet addresses in a minute: typical of malware scanning or spamming outward."},
    "worm": {"name": "Worm-like spreading", "why": "A LAN host is connecting to many addresses on a port worms "
             "spread over (SMB, Telnet, SMTP, RDP)."},
    "watchport": {"name": "Suspicious outbound port", "why": "A LAN host is talking to a port commonly used for "
                  "backdoors, botnet control (IRC), Tor or ADB."},
    "vpn_leak": {"name": "VPN leak", "why": "A firewall rule you set up as a VPN kill switch (logged with a VPN "
                 "leak prefix, VPN-LEAK by default) caught a device sending traffic outside its VPN. The VPN on "
                 "that device is probably down or misrouted; anything that got past the rule showed your real "
                 "address."},
    "exfil": {"name": "Unusual upload", "why": "A LAN host has been uploading far above its own normal rate for a "
              "while. Could be a backup -- or data leaving."},
    "new_device": {"name": "New device", "why": "A MAC address never seen before joined the network."},
    "link_down": {"name": "Link down", "why": "A port that was up lost its link."},
    "cpu": {"name": "Router CPU high", "why": "The router's CPU has stayed above the threshold. Under attack, "
            "packets may be dropped."},
    "temp": {"name": "Router temperature", "why": "The router is running hot."},
}


class Window:
    """Per-key sliding window of (timestamp, item)."""

    def __init__(self, span: float):
        self.span = span
        self.d: Dict[Any, Deque[Tuple[float, Any]]] = defaultdict(deque)

    def add(self, key: Any, ts: float, item: Any = None) -> None:
        dq = self.d[key]
        dq.append((ts, item))
        self._trim(dq, ts)

    def _trim(self, dq: Deque[Tuple[float, Any]], now: float) -> None:
        cutoff = now - self.span
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def count(self, key: Any, now: float) -> int:
        dq = self.d.get(key)
        if not dq:
            return 0
        self._trim(dq, now)
        return len(dq)

    def distinct(self, key: Any, now: float) -> Set[Any]:
        dq = self.d.get(key)
        if not dq:
            return set()
        self._trim(dq, now)
        return {i for _, i in dq}

    def prune(self, now: float) -> None:
        for k in list(self.d):
            self._trim(self.d[k], now)
            if not self.d[k]:
                del self.d[k]


class Blocklist:
    """IPs and CIDRs, one per line, '#' comments. Re-read when the file changes."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.mtime = -1.0
        self.exact: Set[str] = set()
        self.nets: Dict[Tuple[int, int], Set[int]] = {}
        self.count = 0

    def _load(self) -> None:
        try:
            mt = self.path.stat().st_mtime
        except OSError:
            self.exact, self.nets, self.count, self.mtime = set(), {}, 0, -1.0
            return
        if mt == self.mtime:
            return
        self.mtime = mt
        exact, nets, n = set(), {}, 0
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        for line in lines:
            item = line.split("#", 1)[0].split(";", 1)[0].strip()
            if not item:
                continue
            try:
                net = ipaddress.ip_network(item.split()[0], strict=False)
            except ValueError:
                continue
            n += 1
            if net.num_addresses == 1:
                exact.add(str(net.network_address))
            else:
                nets.setdefault((net.version, net.prefixlen), set()).add(int(net.network_address))
        self.exact, self.nets, self.count = exact, nets, n

    def contains(self, ip: str) -> bool:
        self._load()
        if ip in self.exact:
            return True
        o = ip_obj(ip)
        if o is None:
            return False
        bits = 32 if o.version == 4 else 128
        val = int(o)
        for (ver, plen), addrs in self.nets.items():
            if ver == o.version and (val >> (bits - plen) << (bits - plen)) in addrs:
                return True
        return False


class Detector:
    def __init__(self, cfg: Any, is_lan: Callable[[str], bool], data_dir: Path,
                 on_change: Callable[[Dict[str, Any]], None], blocklist: Optional[Blocklist] = None):
        self.cfg = cfg
        self.is_lan = is_lan
        self.data_dir = Path(data_dir)
        self.on_change = on_change
        self.blocklist = blocklist or Blocklist(cfg.resolve(cfg.get("blocklist_file", "data/blocklist.txt")))
        self.lock = threading.RLock()
        self.threats: Dict[str, Dict[str, Any]] = {}
        self.by_key: Dict[Tuple[str, str], str] = {}
        self.win: Dict[str, Window] = {}
        self.recent: Dict[str, Deque[Tuple[float, str]]] = {}
        self._seq = 0
        self._seen_conns: Set[str] = set()
        self._iface_state: Dict[str, bool] = {}
        self._port_state: Dict[str, bool] = {}
        self._cpu_since = 0.0
        self._exfil_since: Dict[str, float] = {}
        self._known: Optional[Dict[str, Any]] = None
        self._log_path = self.data_dir / "threats.jsonl"
        self._sup_path = self.data_dir / "ignore.json"
        self.suppressions: List[Dict[str, Any]] = []
        self._sup_seq = 0
        self._sup_dirty = False
        self.on_suppressions: Callable[[List[Dict[str, Any]]], None] = lambda lst: None
        self._load_history()
        self._load_suppressions()

    # -- plumbing ----------------------------------------------------------------------------
    def d(self, key: str) -> Any:
        return self.cfg.get("detect." + key)

    def w(self, name: str, span: float) -> Window:
        win = self.win.get(name)
        if win is None:
            win = self.win[name] = Window(span)
        win.span = float(span)
        return win

    def _note(self, subject: str, ts: float, text: str) -> None:
        dq = self.recent.get(subject)
        if dq is None:
            dq = self.recent[subject] = deque(maxlen=25)
        dq.append((ts, text))

    def _persist(self, t: Dict[str, Any]) -> None:
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({k: v for k, v in t.items() if k != "evidence"}) + "\n")
        except OSError:
            pass

    def _load_history(self) -> None:
        if not self._log_path.exists():
            return
        try:
            lines = self._log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-2000:]
        except OSError:
            return
        for line in lines:
            try:
                t = json.loads(line)
            except ValueError:
                continue
            if not isinstance(t, dict) or "id" not in t:
                continue
            t["evidence"] = []
            if t.get("status") in ("open", "acknowledged"):
                t["status"] = "quiet"  # whatever it was, MCC wasn't watching while it was off
            self.threats[t["id"]] = t
            self.by_key[(t["rule"], t["key"])] = t["id"]
            try:
                self._seq = max(self._seq, int(str(t["id"]).lstrip("T"), 16))
            except ValueError:
                pass
        # keep the newest few hundred
        if len(self.threats) > 400:
            for tid in sorted(self.threats, key=lambda i: self.threats[i].get("last_ts", 0))[:-400]:
                t = self.threats.pop(tid)
                self.by_key.pop((t["rule"], t["key"]), None)

    # -- ignore rules (confirmed false positives) ---------------------------------------------
    def _load_suppressions(self) -> None:
        try:
            data = json.loads(self._sup_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        self.suppressions = [x for x in data.get("rules", []) if isinstance(x, dict) and x.get("id")]
        for x in self.suppressions:
            try:
                self._sup_seq = max(self._sup_seq, int(x["id"].lstrip("I")))
            except ValueError:
                pass

    def _save_suppressions(self) -> None:
        self._sup_dirty = False
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            tmp = self._sup_path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"rules": self.suppressions}, indent=1), encoding="utf-8")
            tmp.replace(self._sup_path)
        except OSError:
            pass

    def _sup_log(self, event: str, sup: Dict[str, Any]) -> None:
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            with open(self.data_dir / "ignore.log.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps({"at": now_iso(), "event": event, "rule": sup}) + "\n")
        except OSError:
            pass

    @staticmethod
    def _addr_match(pattern: str, ip: str) -> bool:
        if not pattern or not ip:
            return False
        if pattern == ip:
            return True
        if "/" in pattern:
            o = ip_obj(ip)
            try:
                net = ipaddress.ip_network(pattern, strict=False)
            except ValueError:
                return False
            return o is not None and o.version == net.version and o in net
        return False

    def _suppressed(self, rule: str, key: str, subject: str, now: float) -> Optional[Dict[str, Any]]:
        for x in self.suppressions:
            if x.get("expires") and x["expires"] <= now:
                continue
            scope = x["scope"]
            if scope == "exact" and x["rule"] == rule and x["key"] == key:
                return x
            if scope == "subject" and x["rule"] == rule and self._addr_match(x["subject"], subject):
                return x
            if scope == "subject_any" and self._addr_match(x["subject"], subject):
                return x
        return None

    def suppress(self, *, rule: str, scope: str, key: str = "", subject: str = "", note: str = "",
                 duration: str = "0", threat_id: str = "", title: str = "") -> Dict[str, Any]:
        """Stop raising a confirmed false positive. Returns the new ignore rule."""
        if scope not in IGNORE_SCOPES:
            raise ValueError("scope must be one of {}".format(", ".join(IGNORE_SCOPES)))
        if duration not in IGNORE_DURATIONS:
            raise ValueError("duration must be 24h, 7d, 30d or 0 (forever)")
        if scope == "exact" and not (rule in RULES and key):
            raise ValueError("an exact ignore needs a rule and a key")
        if scope in ("subject", "subject_any"):
            subject = (subject or "").strip()
            try:
                ipaddress.ip_network(subject, strict=False)
            except ValueError:
                raise ValueError("{!r} is not an IP address or network".format(subject))
            if scope == "subject" and rule not in RULES:
                raise ValueError("unknown rule {!r}".format(rule))
        now = time.time()
        with self.lock:
            self._sup_seq += 1
            every = scope == "subject_any"
            sup = {"id": "I{:04d}".format(self._sup_seq), "rule": "*" if every else rule,
                   "rule_name": "all rules" if every else RULES.get(rule, {}).get("name", rule),
                   "scope": scope, "key": key if scope == "exact" else "", "subject": subject,
                   "note": (note or "").strip()[:300], "title": (title or "")[:200], "threat_id": threat_id,
                   "created": now_iso(), "created_ts": now,
                   "expires": now + IGNORE_DURATIONS[duration] if IGNORE_DURATIONS[duration] else 0,
                   "hits": 0, "last_hit": 0}
            self.suppressions.append(sup)
            self._save_suppressions()
            self._sup_log("added", sup)
            # anything already raised that this covers is set aside too
            for t in list(self.threats.values()):
                if t["status"] in ("open", "acknowledged", "quiet") and \
                        self._suppressed(t["rule"], t["key"], t.get("subject", ""), now) is sup:
                    t["ignored_by"] = sup["id"]
                    self.set_status(t["id"], "ignored", "ignored as a false positive ({}){}".format(
                        sup["id"], ": " + sup["note"] if sup["note"] else ""))
            self.on_suppressions(self.suppressions_list())
            return dict(sup)

    def unsuppress(self, sid: str, reason: str = "removed from the console") -> Dict[str, Any]:
        with self.lock:
            sup = next((x for x in self.suppressions if x["id"] == sid), None)
            if sup is None:
                raise KeyError(sid)
            self.suppressions.remove(sup)
            self._save_suppressions()
            self._sup_log("expired" if reason == "expired" else "removed", dict(sup, reason=reason))
            for t in list(self.threats.values()):
                if t["status"] == "ignored" and t.get("ignored_by") == sid:
                    self.set_status(t["id"], "resolved", "no longer ignored ({}, {}); it alerts again if it recurs"
                                    .format(sid, reason))
            self.on_suppressions(self.suppressions_list())
            return sup

    def suppressions_list(self) -> List[Dict[str, Any]]:
        with self.lock:
            return sorted((dict(x) for x in self.suppressions), key=lambda x: -x.get("created_ts", 0))

    def raise_threat(self, rule: str, key: str, severity: str, title: str, summary: str, ts: float, *,
                     subject: str = "", role: str = "", target: str = "", evidence: Iterable[Tuple[float, str]] = (),
                     proposals: Optional[List[Dict[str, Any]]] = None, count: int = 1) -> Optional[Dict[str, Any]]:
        with self.lock:
            sup = self._suppressed(rule, key, subject, time.time())
            if sup is not None:
                # a confirmed false positive: count it against the ignore rule, raise nothing
                sup["hits"] = sup.get("hits", 0) + 1
                sup["last_hit"] = time.time()
                self._sup_dirty = True
                return None
            tid = self.by_key.get((rule, key))
            t = self.threats.get(tid) if tid else None
            if t is not None and t["status"] == "mitigated" and time.time() - t.get("mitigated_at", 0) < MITIGATION_GRACE_S:
                # Flow records and log lines describing traffic from *before* the block keep arriving
                # for a while (IPFIX reports active flows once a minute). That isn't a recurrence.
                return t
            fresh = t is None or t["status"] in ("resolved", "quiet", "mitigated", "ignored")
            if t is None:
                self._seq += 1
                tid = "T{:05x}".format(self._seq)
                t = {"id": tid, "rule": rule, "rule_name": RULES.get(rule, {}).get("name", rule), "key": key,
                     "first_seen": now_iso(), "first_ts": ts, "count": 0, "evidence": [], "status": "open",
                     "mitigated_by": [], "reopened": 0}
                self.threats[tid] = t
                self.by_key[(rule, key)] = tid
            elif fresh:
                if t["status"] == "mitigated":
                    t["reopened"] = t.get("reopened", 0) + 1
                t["status"] = "open"
                t["first_seen"], t["first_ts"], t["count"] = now_iso(), ts, 0
            if SEVERITY.get(severity, 0) >= SEVERITY.get(t.get("severity", "info"), 0) or fresh:
                t["severity"] = severity
            t.update({"title": title, "summary": summary, "subject": subject, "role": role, "target": target,
                      "last_seen": now_iso(), "last_ts": ts})
            t["count"] = max(t["count"] + 1, count) if count > 1 else t["count"] + 1
            if proposals is not None:
                t["proposals"] = proposals
            ev = t["evidence"]
            have = {(e["ts"], e["text"]) for e in ev}
            for ets, text in evidence:
                if (ets, text) not in have:
                    ev.append({"ts": ets, "text": text})
            del ev[:-25]
            if fresh:
                self._persist(t)
            self.on_change(t)
            return t

    def set_status(self, tid: str, status: str, note: str = "", action_id: str = "") -> Optional[Dict[str, Any]]:
        with self.lock:
            t = self.threats.get(tid)
            if t is None:
                return None
            t["status"] = status
            if status == "mitigated":
                t["mitigated_at"] = time.time()
            if action_id and action_id not in t["mitigated_by"]:
                t["mitigated_by"].append(action_id)
            if note:
                t["evidence"].append({"ts": time.time(), "text": note})
                del t["evidence"][:-25]
            self._persist(t)
            self.on_change(t)
            return t

    def mitigate_subject(self, ip: str, action_id: str, note: str) -> List[str]:
        hit = []
        with self.lock:
            for t in self.threats.values():
                if t.get("subject") == ip and t["status"] in ("open", "acknowledged", "quiet"):
                    self.set_status(t["id"], "mitigated", note, action_id)
                    hit.append(t["id"])
        return hit

    def list(self) -> List[Dict[str, Any]]:
        with self.lock:
            return sorted((dict(t) for t in self.threats.values()), key=lambda t: -t.get("last_ts", 0))

    def level(self, now: float) -> str:
        worst = -1
        with self.lock:
            for t in self.threats.values():
                if t["status"] == "open" and now - t.get("last_ts", 0) < 900:
                    worst = max(worst, SEVERITY.get(t.get("severity", "info"), 0))
        return {-1: "calm", 0: "calm", 1: "watch", 2: "elevated", 3: "high", 4: "critical"}[worst]

    def subject_threats(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        with self.lock:
            for t in self.threats.values():
                if t["status"] in ("open", "acknowledged") and t.get("subject"):
                    cur = out.get(t["subject"])
                    if cur is None or SEVERITY[t["severity"]] > SEVERITY[cur]:
                        out[t["subject"]] = t["severity"]
        return out

    # -- suggestions -------------------------------------------------------------------------
    def _block(self, ip: str, timeout: str = "24h") -> Dict[str, Any]:
        return {"kind": "block_ip", "params": {"ip": ip, "timeout": timeout},
                "label": "Block {} ({})".format(ip, "permanent" if timeout in ("", "0") else timeout)}

    def _quarantine(self, ip: str) -> Dict[str, Any]:
        return {"kind": "quarantine_host", "params": {"ip": ip, "timeout": "1h"},
                "label": "Quarantine {} (cut it off from the Internet)".format(ip)}

    def _kill(self, ip: str) -> Dict[str, Any]:
        return {"kind": "kill_connections", "params": {"ip": ip}, "label": "Drop {}'s open connections".format(ip)}

    # -- inputs ------------------------------------------------------------------------------
    def _inbound_attempt(self, src: str, dst: str, dport: int, proto: str, ts: float, text: str) -> None:
        self._note(src, ts, text)
        span = self.d("scan_window_s")
        ports = self.w("scan_ports", span)
        ports.add(src, ts, dport)
        n_ports = len(ports.distinct(src, ts))
        if n_ports >= self.d("scan_ports"):
            sev = "high" if n_ports >= 3 * self.d("scan_ports") else "medium"
            self.raise_threat("scan", src, sev, "Port scan from {}".format(src),
                              "{} different ports probed in the last {}s".format(n_ports, int(span)), ts,
                              subject=src, role="attacker", target=dst, evidence=self.recent[src],
                              proposals=[self._block(src)], count=n_ports)
        if dport:
            hosts = self.w("scan_hosts", span)
            hosts.add((src, dport), ts, dst)
            n_hosts = len(hosts.distinct((src, dport), ts))
            if n_hosts >= self.d("scan_hosts"):
                self.raise_threat("sweep", src, "high", "Network sweep from {}".format(src),
                                  "{} of your addresses probed on {}".format(n_hosts, service_label(proto, dport)),
                                  ts, subject=src, role="attacker", evidence=self.recent[src],
                                  proposals=[self._block(src)], count=n_hosts)
        if dport in self.d("auth_ports"):
            self._service_attempt(src, dst, dport, proto, ts, text, noted=True)
        flood = self.w("flood_logs", 60)
        flood.add(src, ts)
        n = flood.count(src, ts)
        if n >= self.d("flood_logs_per_min"):
            self.raise_threat("flood", src, "high", "Flood from {}".format(src),
                              "{} logged packets in the last minute".format(n), ts, subject=src, role="attacker",
                              target=dst, evidence=self.recent[src], proposals=[self._block(src)], count=n)

    def _service_attempt(self, src: str, dst: str, dport: int, proto: str, ts: float, text: str,
                         noted: bool = False) -> None:
        if not noted:
            self._note(src, ts, text)
        span = self.d("service_window_s")
        win = self.w("service", span)
        win.add((src, dport), ts)
        n = win.count((src, dport), ts)
        if n >= self.d("service_conns"):
            ext = not self.is_lan(src)
            self.raise_threat("bruteforce", "{}:{}".format(src, dport), "high" if ext else "medium",
                              "{} brute force from {}".format(service_label(proto, dport).split(" ")[0], src),
                              "{} connection attempts to {} in {}s".format(n, service_label(proto, dport), int(span)),
                              ts, subject=src, role="attacker" if ext else "host", target=dst,
                              evidence=self.recent[src],
                              proposals=[self._block(src)] if ext else [self._quarantine(src), self._kill(src)],
                              count=n)

    def _blocklisted(self, local: str, remote: str, outbound: bool, ts: float, text: str) -> None:
        if not self.blocklist.contains(remote):
            return
        self._note(remote, ts, text)
        if outbound:
            self.raise_threat("blocklist", "{}>{}".format(local, remote), "critical",
                              "{} is talking to blocklisted {}".format(local, remote),
                              "A LAN host contacted an address on your blocklist -- it may be compromised.", ts,
                              subject=local, role="host", target=remote, evidence=self.recent[remote],
                              proposals=[self._block(remote, "0"), self._quarantine(local), self._kill(local)])
        else:
            self.raise_threat("blocklist", remote, "high", "Blocklisted {} reached your network".format(remote),
                              "Inbound traffic from an address on your blocklist.", ts, subject=remote,
                              role="attacker", target=local, evidence=self.recent[remote],
                              proposals=[self._block(remote, "0")])

    def _outbound(self, local: str, remote: str, dport: int, proto: str, ts: float, text: str) -> None:
        self._note(local, ts, text)
        fan = self.w("fanout", self.d("fanout_window_s"))
        fan.add(local, ts, remote)
        n = len(fan.distinct(local, ts))
        if n >= self.d("fanout_peers"):
            self.raise_threat("fanout", local, "high" if n >= 2 * self.d("fanout_peers") else "medium",
                              "{} is contacting {} Internet addresses".format(local, n),
                              "Fan-out in the last {}s".format(int(self.d("fanout_window_s"))), ts, subject=local,
                              role="host", evidence=self.recent[local],
                              proposals=[self._quarantine(local), self._kill(local)], count=n)
        if dport in self.d("worm_ports"):
            worm = self.w("worm", self.d("fanout_window_s"))
            worm.add((local, dport), ts, remote)
            m = len(worm.distinct((local, dport), ts))
            if m >= self.d("worm_dsts"):
                self.raise_threat("worm", "{}:{}".format(local, dport), "high",
                                  "{} spreading on {}".format(local, service_label(proto, dport)),
                                  "{} different addresses contacted on {} in a minute".format(
                                      m, service_label(proto, dport)), ts, subject=local, role="host",
                                  evidence=self.recent[local], proposals=[self._quarantine(local), self._kill(local)],
                                  count=m)
        if dport in self.d("watch_ports"):
            self.raise_threat("watchport", "{}:{}".format(local, dport), "medium",
                              "{} connected out on {}".format(local, service_label(proto, dport)),
                              "Outbound to {} port {}".format(remote, dport), ts, subject=local, role="host",
                              target=remote, evidence=[(ts, text)],
                              proposals=[self._block(remote), self._kill(local), self._quarantine(local)])

    def on_fw(self, e: Dict[str, Any], ts: Optional[float] = None) -> None:
        ts = ts or time.time()
        src, dst = e.get("src", ""), e.get("dst", "")
        if not src or ip_obj(src) is None:
            return
        text = "{} {} {}{} -> {}{} ({}{} in:{})".format(
            "log" if not e.get("prefix") else e["prefix"], e.get("proto", ""), src,
            ":{}".format(e["sport"]) if e.get("sport") else "", dst,
            ":{}".format(e["dport"]) if e.get("dport") else "", e.get("chain", ""),
            " " + e["flags"] if e.get("flags") else "", e.get("in_if", ""))
        with self.lock:
            if self._is_leak_prefix(e.get("prefix") or ""):
                self._vpn_leak(e, ts, text)
            if not self.is_lan(src):
                self._inbound_attempt(src, dst, int(e.get("dport") or 0), e.get("proto", ""), ts, text)
                self._blocklisted(dst, src, False, ts, text)
            elif dst and not self.is_lan(dst):
                self._blocklisted(src, dst, True, ts, text)

    def _is_leak_prefix(self, prefix: str) -> bool:
        p = prefix.strip().rstrip(":").upper()
        return bool(p) and any(p == str(x).strip().rstrip(":").upper() for x in self.d("leak_prefixes") or [])

    def _vpn_leak(self, e: Dict[str, Any], ts: float, text: str) -> None:
        """A VPN kill-switch rule fired: one threat per device, its count and destinations growing."""
        src, dst = e["src"], e.get("dst", "")
        out_if = (e.get("out_if") or "").strip() or "?"
        self._note(src, ts, text)
        win = self.w("leak", 600)
        win.add(src, ts, dst)
        n, dsts = win.count(src, ts), win.distinct(src, ts)
        self.raise_threat("vpn_leak", src, "high",
                          "VPN leak: {} tried to go out {} instead of its VPN".format(src, out_if),
                          "{} attempt{} to {} address{} outside the VPN in the last 10 min, caught by your {} rule "
                          "({} chain, out {}). The VPN on {} is probably down.".format(
                              n, "" if n == 1 else "s", len(dsts), "" if len(dsts) == 1 else "es",
                              e.get("prefix", "").strip(), e.get("chain", ""), out_if, src),
                          ts, subject=src, role="host", target=dst, evidence=self.recent[src],
                          proposals=[self._kill(src), self._quarantine(src)], count=n)

    def on_login(self, src: str, user: str, via: str, ok: bool, ts: Optional[float] = None) -> None:
        ts = ts or time.time()
        if ok or ip_obj(src) is None:
            return
        text = "login failure for {} via {}".format(user, via)
        with self.lock:
            self._note(src, ts, text)
            span = self.d("login_window_s")
            win = self.w("login", span)
            win.add(src, ts, user)
            n = win.count(src, ts)
            if n >= self.d("login_failures"):
                ext = not self.is_lan(src)
                users = sorted(u for u in win.distinct(src, ts) if u)
                self.raise_threat("login", src, "critical" if ext else "high",
                                  "Router login brute force from {} via {}".format(src, via),
                                  "{} failed logins in {} min (users: {})".format(n, int(span // 60),
                                                                                    ", ".join(users[:6])),
                                  ts, subject=src, role="attacker" if ext else "host", evidence=self.recent[src],
                                  proposals=[self._block(src)] if ext else [self._quarantine(src)], count=n)

    def on_flow(self, g: Dict[str, Any], ts: Optional[float] = None) -> None:
        ts = ts or time.time()
        proto = g.get("proto_name", "")
        text = "flow {} {}:{} -> {}:{} {}B/{}p{}".format(proto, g["src"], g["sport"], g["dst"], g["dport"],
                                                          g["bytes"], g["packets"],
                                                          " flags=0x{:02x}".format(g["flags"]) if g["flags"] else "")
        with self.lock:
            if g["dir"] == "in":
                src, dst = g["src"], g["dst"]
                syn_only = proto == "TCP" and (g["flags"] & 0x12) == 0x02
                udp_probe = proto == "UDP" and g["sport"] >= 1024 and g["dport"] < 1024 and g["packets"] <= 2
                if syn_only or udp_probe:
                    self._inbound_attempt(src, dst, g["dport"], proto, ts, text)
                elif g["dport"] in self.d("auth_ports") and g["sport"] >= 1024:
                    self._service_attempt(src, dst, g["dport"], proto, ts, text)
                if g["duration"] >= 1 and g["packets"] / g["duration"] >= self.d("flood_pps"):
                    self._note(src, ts, text)
                    self.raise_threat("flood", src, "high", "Flood from {}".format(src),
                                      "{:.0f} packets/s in one flow".format(g["packets"] / g["duration"]), ts,
                                      subject=src, role="attacker", target=dst, evidence=self.recent[src],
                                      proposals=[self._block(src)])
                self._blocklisted(g["local"], src, False, ts, text)
            elif g["dir"] == "out" and g["src"] == g["local"]:
                if g["sport"] > g["dport"]:  # the local side initiated it
                    self._outbound(g["local"], g["remote"], g["dport"], proto, ts, text)
                self._blocklisted(g["local"], g["remote"], True, ts, text)

    def on_conns(self, conns: List[Dict[str, Any]], ts: Optional[float] = None) -> None:
        """New rows in the connection table since the last poll."""
        ts = ts or time.time()
        seen = set()
        with self.lock:
            first = not self._seen_conns
            for c in conns:
                cid = c.get("id") or "{}|{}|{}|{}".format(c["src"], c["sport"], c["dst"], c["dport"])
                seen.add(cid)
                if first or cid in self._seen_conns:
                    continue
                text = "conn {} {}:{} -> {}:{} {}".format(c["proto"], c["src"], c["sport"], c["dst"], c["dport"],
                                                          c.get("tcp_state", ""))
                if c["dir"] == "out":
                    self._outbound(c["local"], c["remote"], c["dport"], c["proto"], ts, text)
                    self._blocklisted(c["local"], c["remote"], True, ts, text)
                elif c["dir"] == "in":
                    if c["port"] in self.d("auth_ports"):
                        self._service_attempt(c["remote"], c["local"], c["port"], c["proto"], ts, text)
                    self._blocklisted(c["local"], c["remote"], False, ts, text)
            self._seen_conns = seen

    def on_health(self, cpu: Optional[float], temp: Optional[float], ts: Optional[float] = None) -> None:
        ts = ts or time.time()
        with self.lock:
            if cpu is not None:
                if cpu >= self.d("cpu_pct"):
                    self._cpu_since = self._cpu_since or ts
                    if ts - self._cpu_since >= self.d("cpu_s"):
                        self.raise_threat("cpu", "router", "medium", "Router CPU at {:.0f}%".format(cpu),
                                          "Above {}% for {}s".format(self.d("cpu_pct"), int(ts - self._cpu_since)),
                                          ts, subject="", role="router", evidence=[(ts, "cpu {:.0f}%".format(cpu))])
                else:
                    self._cpu_since = 0.0
                    self._auto_resolve("cpu", "router", "CPU back to {:.0f}%".format(cpu))
            if temp is not None:
                if temp >= self.d("temp_c"):
                    self.raise_threat("temp", "router", "medium", "Router at {:.0f} °C".format(temp),
                                      "Threshold {} °C".format(self.d("temp_c")), ts, role="router",
                                      evidence=[(ts, "temperature {:.0f} °C".format(temp))])
                elif temp < self.d("temp_c") - 5:
                    self._auto_resolve("temp", "router", "temperature back to {:.0f} °C".format(temp))

    def _auto_resolve(self, rule: str, key: str, note: str) -> None:
        tid = self.by_key.get((rule, key))
        t = self.threats.get(tid) if tid else None
        if t and t["status"] in ("open", "acknowledged"):
            self.set_status(tid, "resolved", note)

    def on_links(self, kind: str, states: Dict[str, Dict[str, Any]], ts: Optional[float] = None) -> None:
        """kind 'router' or 'switch'; states name -> {up: bool, disabled: bool}."""
        ts = ts or time.time()
        memo = self._iface_state if kind == "router" else self._port_state
        with self.lock:
            for name, st in states.items():
                up = bool(st.get("up"))
                prev = memo.get(name)
                memo[name] = up
                key = "{}:{}".format(kind, name)
                if prev is True and not up and not st.get("disabled"):
                    where = "switch port" if kind == "switch" else "interface"
                    self.raise_threat("link_down", key, "medium", "{} {} lost link".format(where.capitalize(), name),
                                      "It was up on the last poll.", ts, subject="", role=kind, target=name,
                                      evidence=[(ts, "{} {} link down".format(where, name))])
                elif up and prev is False:
                    self._auto_resolve("link_down", key, "link back up")

    def on_devices(self, devices: List[Dict[str, Any]], ts: Optional[float] = None) -> None:
        ts = ts or time.time()
        path = self.data_dir / "devices.json"
        with self.lock:
            if self._known is None:
                try:
                    self._known = json.loads(path.read_text(encoding="utf-8"))
                    baseline = False
                except (OSError, ValueError):
                    self._known = {}
                    baseline = True  # first run: everything present now is "known"
            else:
                baseline = False
            changed = False
            for dev in devices:
                mac = (dev.get("mac") or "").upper()
                if not mac:
                    continue
                k = self._known.get(mac)
                if k is None:
                    self._known[mac] = {"first_seen": now_iso(), "known": baseline, "name": dev.get("name", ""),
                                        "ip": dev.get("ip", "")}
                    changed = True
                    if not baseline:
                        label = dev.get("name") or dev.get("ip") or mac
                        self.raise_threat("new_device", mac, "low", "New device: {}".format(label),
                                          "{} / {} on {}".format(dev.get("ip", "?"), mac, dev.get("iface") or "?"),
                                          ts, subject=dev.get("ip", ""), role="device", target=mac,
                                          evidence=[(ts, "first seen {} {} {}".format(mac, dev.get("ip", ""),
                                                                                       dev.get("name", "")))],
                                          proposals=[self._quarantine(dev["ip"])] if dev.get("ip") else [])
                elif dev.get("ip") and k.get("ip") != dev.get("ip"):
                    k["ip"] = dev["ip"]
                    changed = True
            if changed:
                self._save_known(path)

    def _save_known(self, path: Path) -> None:
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._known, indent=1), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            pass

    def known_devices(self) -> Dict[str, Any]:
        with self.lock:
            return dict(self._known or {})

    def mark_known(self, mac: str) -> bool:
        mac = mac.upper()
        with self.lock:
            if self._known is None or mac not in self._known:
                return False
            self._known[mac]["known"] = True
            self._save_known(self.data_dir / "devices.json")
            tid = self.by_key.get(("new_device", mac))
            if tid and self.threats[tid]["status"] != "resolved":
                self.set_status(tid, "resolved", "marked as a known device")
            return True

    def on_hosts(self, hosts: List[Dict[str, Any]], ts: Optional[float] = None) -> None:
        """Traffic snapshot hosts -> sustained upload check."""
        ts = ts or time.time()
        floor = self.d("exfil_mbps") * 1e6
        with self.lock:
            live = set()
            for h in hosts:
                ip, up, base = h["ip"], h.get("up", 0.0), max(h.get("baseline_up", 0.0), 1e6)
                if up >= floor and up >= self.d("exfil_factor") * base:
                    live.add(ip)
                    since = self._exfil_since.setdefault(ip, ts)
                    if ts - since >= self.d("exfil_s"):
                        self.raise_threat("exfil", ip, "medium", "{} uploading {:.0f} Mbps".format(
                            h.get("name") or ip, up / 1e6),
                            "Sustained {}s, about {:.0f}x its usual rate".format(int(ts - since), up / base), ts,
                            subject=ip, role="host", evidence=[(ts, "upload {:.1f} Mbps to {} peers".format(
                                up / 1e6, h.get("peers", 0)))],
                            proposals=[self._kill(ip), self._quarantine(ip)])
            for ip in list(self._exfil_since):
                if ip not in live:
                    del self._exfil_since[ip]

    def tick(self, now: Optional[float] = None) -> None:
        now = now or time.time()
        quiet = self.d("quiet_s")
        with self.lock:
            for x in [x for x in self.suppressions if x.get("expires") and x["expires"] <= now]:
                self.unsuppress(x["id"], reason="expired")
            if self._sup_dirty:  # hit counters, saved at most once a second
                self._save_suppressions()
                self.on_suppressions(self.suppressions_list())
            for t in list(self.threats.values()):
                if t["status"] in ("open", "acknowledged") and t["rule"] not in ("link_down", "new_device") \
                        and now - t.get("last_ts", now) > quiet:
                    self.set_status(t["id"], "quiet", "no activity for {} min".format(int(quiet // 60)))
            for win in self.win.values():
                win.prune(now)
            for k in list(self.recent):
                if self.recent[k] and now - self.recent[k][-1][0] > 900:
                    del self.recent[k]
