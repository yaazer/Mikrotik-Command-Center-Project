"""Responses: proposed, shown exactly, run only on your confirmation, logged, and undoable.

Lifecycle of an action:
    propose()  -> status 'pending'. MCC reads the router to work out the exact REST calls (and the
                  equivalent terminal commands) and any warnings. Nothing on the router changes.
    confirm()  -> runs those calls in order. 'done' or 'failed' (a failure stops at that step and
                  keeps what was created, so it can still be undone).
    undo()     -> reverses what the action created or changed. 'undone'.
    dismiss()  -> a pending proposal you decided against.
Every transition is appended to data/actions.jsonl.

Firewall pieces MCC needs (the drop rules that make its address lists bite) are added by the first
action that needs them -- shown as separate lines in that proposal -- and are left in place by undo;
Setup > "Remove everything MCC added" takes them out.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .routeros import RouterOSError, cli_line
from .util import in_networks, ip_obj, now_iso, parse_duration, split_hostport

BLOCK_LIST = "mcc-blocked"
QUARANTINE_LIST = "mcc-quarantine"
TAG = "mcc:"

TIMEOUTS = {"15m": "15m", "1h": "1h", "24h": "1d", "7d": "7d", "0": "", "": ""}


class ActionError(Exception):
    pass


def base_for(ip: str) -> str:
    o = ip_obj(ip)
    return "/ipv6" if o is not None and o.version == 6 else "/ip"


def _addr_of(entry_addr: str) -> str:
    return (entry_addr or "").split("/")[0]


class ActionEngine:
    def __init__(self, hub: Any, data_dir: Path):
        self.hub = hub
        self.path = Path(data_dir) / "actions.jsonl"
        self.lock = threading.RLock()
        self.items: Dict[str, Dict[str, Any]] = {}
        self._seq = 0
        self._load()

    # -- persistence -------------------------------------------------------------------------
    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        for line in lines:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict) and rec.get("id"):
                self.items[rec["id"]] = rec
                try:
                    self._seq = max(self._seq, int(rec["id"].lstrip("A")))
                except ValueError:
                    pass
        for rec in self.items.values():
            if rec.get("status") == "pending":
                rec["status"] = "expired"  # proposals don't survive a restart; the router may have moved on
            if rec.get("status") == "running":
                rec["status"] = "failed"
                rec["error"] = "MCC stopped while this was running; check the router"

    def _log(self, rec: Dict[str, Any], event: str) -> None:
        rec.setdefault("history", []).append({"at": now_iso(), "event": event})
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError:
            pass
        self.hub.publish("action", rec)

    def list(self) -> List[Dict[str, Any]]:
        with self.lock:
            return sorted((dict(r) for r in self.items.values()), key=lambda r: r.get("created", ""), reverse=True)

    def get(self, aid: str) -> Dict[str, Any]:
        rec = self.items.get(aid)
        if rec is None:
            raise ActionError("no such action {}".format(aid))
        return rec

    # -- helpers -----------------------------------------------------------------------------
    def _ros(self) -> Any:
        ros = self.hub.ros
        if ros is None:
            raise ActionError("not connected to the router")
        return ros

    @staticmethod
    def _change(method: str, path: str, body: Optional[Dict[str, Any]] = None, note: str = "", target: str = "",
                keep: bool = False, op: str = "") -> Dict[str, Any]:
        return {"op": op or method, "method": method, "path": path, "body": body or {}, "note": note,
                "cli": cli_line(method, path, body, target), "keep": keep}

    def _guard(self, ip: str, verb: str) -> None:
        o = ip_obj(ip)
        if o is None:
            raise ActionError("{!r} is not an IP address".format(ip))
        prot = self.hub.protected_ips()
        if ip in prot:
            raise ActionError("Refusing to {} {}: {}.".format(verb, ip, prot[ip]))
        if in_networks(o, self.hub.never_block_nets()):
            raise ActionError("Refusing to {} {}: it is in your never-block list (Setup > Settings).".format(verb, ip))

    def _drop_rules(self, ros: Any, base: str, list_name: str) -> List[Dict[str, Any]]:
        """Changes needed so that membership of list_name actually drops traffic."""
        changes = []
        if list_name == BLOCK_LIST:
            rules = ros.get_list(base + "/firewall/raw")
            for field in ("src-address-list", "dst-address-list"):
                if not any(r.get(field) == BLOCK_LIST and r.get("action") == "drop" and r.get("chain") == "prerouting"
                           for r in rules):
                    body = {"chain": "prerouting", "action": "drop", field: BLOCK_LIST,
                            "comment": "{} drop {} {}".format(TAG, "from" if field.startswith("src") else "to",
                                                             BLOCK_LIST)}
                    first = rules[0][".id"] if rules and rules[0].get(".id") else None
                    if first:
                        body["place-before"] = first
                    changes.append(self._change("PUT", base + "/firewall/raw", body, keep=True,
                                                note="one-time: makes the {} list drop traffic".format(BLOCK_LIST)))
        else:
            rules = ros.get_list(base + "/firewall/filter")
            fwd = [r for r in rules if r.get("chain") == "forward"]
            for field in ("src-address-list", "dst-address-list"):
                if not any(r.get(field) == list_name and r.get("action") in ("drop", "reject") for r in fwd):
                    body = {"chain": "forward", "action": "drop", field: list_name,
                            "comment": "{} quarantine {}".format(TAG, "from" if field.startswith("src") else "to")}
                    if fwd and fwd[0].get(".id"):
                        body["place-before"] = fwd[0][".id"]
                    changes.append(self._change("PUT", base + "/firewall/filter", body, keep=True,
                                                note="one-time: makes the {} list cut hosts off".format(list_name)))
        return changes

    def _conns_of(self, ros: Any, ip: str) -> List[Dict[str, Any]]:
        rows = ros.get_list(base_for(ip) + "/firewall/connection",
                            {".proplist": ".id,src-address,dst-address,reply-src-address,reply-dst-address,protocol"})
        out = []
        for r in rows:
            addrs = {split_hostport(r.get(k, ""))[0] for k in
                     ("src-address", "dst-address", "reply-src-address", "reply-dst-address")}
            if ip in addrs:
                out.append(r)
        return out

    def _kill_change(self, ip: str, n: int) -> Dict[str, Any]:
        c = self._change("KILL", base_for(ip) + "/firewall/connection", {"ip": ip},
                         note="{} open connection{} right now".format(n, "" if n == 1 else "s"), op="KILL")
        e = ip.replace(".", "\\.")
        c["cli"] = ('{b} firewall connection remove [find where src-address~"^{e}(:|\\$)" or '
                    'dst-address~"^{e}(:|\\$)" or reply-src-address~"^{e}(:|\\$)" or '
                    'reply-dst-address~"^{e}(:|\\$)"]').format(b=base_for(ip), e=e)
        return c

    def _iface(self, ros: Any, name: str) -> Dict[str, Any]:
        for r in ros.get_list("/interface"):
            if r.get("name") == name:
                return r
        raise ActionError("the router has no interface named {!r}".format(name))

    # -- proposals ---------------------------------------------------------------------------
    def propose(self, kind: str, params: Dict[str, Any], reason: str = "", threat_id: str = "") -> Dict[str, Any]:
        ros = self._ros()
        params = dict(params or {})
        warnings: List[str] = []
        changes: List[Dict[str, Any]] = []
        undo = {"possible": True, "why": ""}
        try:
            if kind in ("block_ip", "quarantine_host"):
                ip = str(params.get("ip", "")).strip()
                lst = BLOCK_LIST if kind == "block_ip" else QUARANTINE_LIST
                verb = "block" if kind == "block_ip" else "quarantine"
                self._guard(ip, verb)
                if kind == "quarantine_host" and not self.hub.is_lan(ip):
                    raise ActionError("{} isn't on your LAN; quarantine is for your own hosts -- block it instead."
                                      .format(ip))
                timeout = str(params.get("timeout", self.hub.cfg.get("actions.default_block", "1h")))
                if timeout not in TIMEOUTS:
                    raise ActionError("timeout must be one of 15m, 1h, 24h, 7d or 0 (permanent)")
                params["timeout"] = timeout
                base = base_for(ip)
                existing = [e for e in ros.get_list(base + "/firewall/address-list", {"list": lst})
                            if _addr_of(e.get("address", "")) == ip]
                if existing:
                    raise ActionError("{} is already on {} (entry {}).".format(ip, lst, existing[0].get(".id")))
                changes.extend(self._drop_rules(ros, base, lst))
                body = {"list": lst, "address": ip,
                        "comment": "{} {} ({})".format(TAG, (reason or verb)[:60], "#pending")}
                if TIMEOUTS[timeout]:
                    body["timeout"] = TIMEOUTS[timeout]
                changes.append(self._change("PUT", base + "/firewall/address-list", body,
                                            note="{} {} {}".format(
                                                verb.capitalize(), ip,
                                                "permanently" if not TIMEOUTS[timeout] else "for " + timeout)))
                n = len(self._conns_of(ros, ip))
                if n:
                    changes.append(self._kill_change(ip, n))
                    warnings.append("Its {} open connection{} will be dropped too -- the firewall only stops new "
                                    "packets, and fast-tracked connections would otherwise keep going."
                                    .format(n, "" if n == 1 else "s"))
                if kind == "quarantine_host":
                    warnings.append("The host keeps reaching the router (DHCP, DNS) but nothing beyond it, "
                                    "including other LAN subnets routed through the router.")
                title = "{} {}".format("Block" if kind == "block_ip" else "Quarantine", ip)
                summary = "{} {} {}".format(
                    "Drop all traffic to and from" if kind == "block_ip" else "Cut off", ip,
                    "permanently" if not TIMEOUTS[timeout] else "for " + timeout)
                undo["why"] = "removes the address-list entry"
            elif kind == "kill_connections":
                ip = str(params.get("ip", "")).strip()
                if ip_obj(ip) is None:
                    raise ActionError("{!r} is not an IP address".format(ip))
                prot = self.hub.protected_ips()
                if ip in prot:
                    raise ActionError("Refusing to cut {}'s connections: {}.".format(ip, prot[ip]))
                n = len(self._conns_of(ros, ip))
                if not n:
                    raise ActionError("{} has no open connections right now.".format(ip))
                changes.append(self._kill_change(ip, n))
                title, summary = "Drop {}'s connections".format(ip), "Remove {} connection{} from the router's " \
                    "table; applications will reconnect unless something else blocks them.".format(n, "" if n == 1 else "s")
                undo = {"possible": False, "why": "dropped connections can't be restored (they simply reconnect)"}
            elif kind in ("disable_interface", "enable_interface"):
                name = str(params.get("name", "")).strip()
                iface = self._iface(ros, name)
                disable = kind == "disable_interface"
                currently = str(iface.get("disabled", "false")) == "true"
                if currently == disable:
                    raise ActionError("{} is already {}.".format(name, "disabled" if disable else "enabled"))
                if disable:
                    if name in self.hub.wan_ifaces():
                        warnings.append("{} is your Internet uplink: the whole network goes offline until this is "
                                        "undone.".format(name))
                    mgmt = self.hub.mgmt_ifaces()
                    if name in mgmt:
                        warnings.append("DANGER: {} -- disabling it will cut MCC off from the router; you would "
                                        "have to undo this from the router's console.".format(mgmt[name]))
                        params["acknowledge_risk"] = bool(params.get("acknowledge_risk"))
                changes.append(self._change("PATCH", "/interface/{}".format(iface[".id"]),
                                            {"disabled": "true" if disable else "false"}, target=name,
                                            note="{} {}".format("Disable" if disable else "Enable", name)))
                params["id"] = iface[".id"]
                title = "{} {}".format("Disable" if disable else "Enable", name)
                summary = "{} the router interface {}.".format("Shut down" if disable else "Bring back up", name)
                undo["why"] = "{}s it again".format("enable" if disable else "disable")
            elif kind == "remove_entry":
                lst, ip = str(params.get("list", "")), str(params.get("ip", ""))
                if lst not in (BLOCK_LIST, QUARANTINE_LIST):
                    raise ActionError("MCC only removes entries from its own lists")
                base = base_for(ip)
                rows = [e for e in ros.get_list(base + "/firewall/address-list", {"list": lst})
                        if _addr_of(e.get("address", "")) == ip]
                if not rows:
                    raise ActionError("{} is not on {}".format(ip, lst))
                e = rows[0]
                params["entry"] = {k: e.get(k) for k in ("list", "address", "comment", "timeout") if e.get(k)}
                changes.append(self._change("DELETE", "{}/firewall/address-list/{}".format(base, e[".id"]),
                                            target='[find list={} address={}]'.format(lst, ip),
                                            note="Remove {} from {}".format(ip, lst)))
                title, summary = "Unblock {}".format(ip) if lst == BLOCK_LIST else "Release {}".format(ip), \
                    "Take {} off {}.".format(ip, lst)
                undo["why"] = "puts it back on the list"
            else:
                raise ActionError("unknown action {!r}".format(kind))
        except RouterOSError as e:
            raise ActionError("couldn't read the router to prepare this: {}".format(e))
        with self.lock:
            self._seq += 1
            aid = "A{:04d}".format(self._seq)
            for c in changes:
                if c["method"] == "PUT" and "#pending" in str(c["body"].get("comment", "")):
                    c["body"]["comment"] = c["body"]["comment"].replace("#pending", aid)
                    c["cli"] = cli_line("PUT", c["path"], c["body"])
            rec = {"id": aid, "kind": kind, "params": params, "reason": reason, "threat_id": threat_id,
                   "title": title, "summary": summary, "changes": changes, "warnings": warnings, "undo": undo,
                   "status": "pending", "created": now_iso(), "created_ids": [], "steps": []}
            self.items[aid] = rec
            self._log(rec, "proposed")
            return rec

    # -- execution ---------------------------------------------------------------------------
    def confirm(self, aid: str, acknowledge_risk: bool = False) -> Dict[str, Any]:
        with self.lock:
            rec = self.get(aid)
            if rec["status"] != "pending":
                raise ActionError("{} is {}, not pending".format(aid, rec["status"]))
            if rec["params"].get("acknowledge_risk") is False and not acknowledge_risk:
                raise ActionError("This change can cut MCC off from the router. Tick the acknowledgement to go ahead.")
            rec["status"] = "running"
        ros = self._ros()
        error = ""
        for c in rec["changes"]:
            step = {"cli": c["cli"], "at": now_iso()}
            try:
                if c["op"] == "KILL":
                    ip = c["body"]["ip"]
                    killed = 0
                    for row in self._conns_of(ros, ip):
                        try:
                            ros.remove(c["path"], row[".id"])
                            killed += 1
                        except RouterOSError as e:
                            if e.status != 404:  # it closed by itself in the meantime
                                raise
                    step["result"] = "{} connection{} dropped".format(killed, "" if killed == 1 else "s")
                elif c["method"] == "PUT":
                    created = ros.add(c["path"], c["body"])
                    cid = (created or {}).get(".id", "")
                    rec["created_ids"].append({"path": c["path"], "id": cid, "keep": c.get("keep", False),
                                               "body": c["body"]})
                    step["result"] = "created {}".format(cid or "(no id returned)")
                elif c["method"] == "PATCH":
                    ros.request("PATCH", c["path"], c["body"])
                    step["result"] = "updated"
                elif c["method"] == "DELETE":
                    ros.request("DELETE", c["path"])
                    step["result"] = "removed"
                step["ok"] = True
            except RouterOSError as e:
                step["ok"] = False
                step["result"] = str(e)
                error = "step failed: {} -> {}".format(c["cli"], e)
            rec["steps"].append(step)
            if error:
                break
        with self.lock:
            rec["executed_at"] = now_iso()
            if error:
                rec["status"], rec["error"] = "failed", error
                self._log(rec, "failed")
            else:
                rec["status"] = "done"
                self._log(rec, "executed")
                ip = rec["params"].get("ip")
                if rec["kind"] in ("block_ip", "quarantine_host") and ip:
                    self.hub.detector.mitigate_subject(ip, aid, "{} by {}".format(
                        "blocked" if rec["kind"] == "block_ip" else "quarantined", aid))
                if rec.get("threat_id"):
                    t = self.hub.detector.threats.get(rec["threat_id"])
                    if t and t["status"] != "mitigated":
                        self.hub.detector.set_status(rec["threat_id"], "mitigated", "{} by {}".format(
                            rec["title"], aid), aid)
            self.hub.refresh_soon()
            return rec

    def dismiss(self, aid: str) -> Dict[str, Any]:
        with self.lock:
            rec = self.get(aid)
            if rec["status"] != "pending":
                raise ActionError("{} is {}, not pending".format(aid, rec["status"]))
            rec["status"] = "dismissed"
            self._log(rec, "dismissed")
            return rec

    def undo(self, aid: str) -> Dict[str, Any]:
        with self.lock:
            rec = self.get(aid)
            if rec["status"] not in ("done", "failed"):
                raise ActionError("{} is {}; only done or failed actions can be undone".format(aid, rec["status"]))
            if not rec.get("undo", {}).get("possible"):
                raise ActionError("{} can't be undone: {}".format(aid, rec["undo"].get("why", "")))
        ros = self._ros()
        steps = []
        error = ""
        try:
            if rec["kind"] in ("disable_interface", "enable_interface"):
                back = "false" if rec["kind"] == "disable_interface" else "true"
                ros.set("/interface", rec["params"]["id"], {"disabled": back})
                steps.append({"cli": cli_line("PATCH", "/interface/" + rec["params"]["id"], {"disabled": back},
                                              rec["params"]["name"]), "ok": True, "result": "updated"})
            elif rec["kind"] == "remove_entry":
                entry = rec["params"]["entry"]
                body = {k: v for k, v in entry.items() if k != "timeout"}
                body["comment"] = "{} restored by undo of {}".format(TAG, aid)
                path = base_for(rec["params"]["ip"]) + "/firewall/address-list"
                created = ros.add(path, body)
                steps.append({"cli": cli_line("PUT", path, body), "ok": True,
                              "result": "created {}".format((created or {}).get(".id", ""))})
            else:
                for c in reversed(rec.get("created_ids", [])):
                    if c.get("keep") or not c.get("id"):
                        continue
                    line = cli_line("DELETE", "{}/{}".format(c["path"], c["id"]))
                    try:
                        ros.remove(c["path"], c["id"])
                        steps.append({"cli": line, "ok": True, "result": "removed"})
                    except RouterOSError as e:
                        if e.status == 404:
                            steps.append({"cli": line, "ok": True, "result": "already gone (expired)"})
                        else:
                            raise
        except RouterOSError as e:
            error = str(e)
            steps.append({"cli": "", "ok": False, "result": error})
        with self.lock:
            rec["undo_steps"] = steps
            rec["undone_at"] = now_iso()
            if error:
                rec["undo_error"] = error
                self._log(rec, "undo failed")
            else:
                rec["status"] = "undone"
                self._log(rec, "undone")
            self.hub.refresh_soon()
            return rec

    # -- what's in force now -----------------------------------------------------------------
    def entries(self) -> List[Dict[str, Any]]:
        ros = self.hub.ros
        if ros is None:
            return []
        out = []
        for base in ("/ip", "/ipv6"):
            for lst in (BLOCK_LIST, QUARANTINE_LIST):
                try:
                    rows = ros.get_list(base + "/firewall/address-list", {"list": lst})
                except RouterOSError:
                    continue
                for r in rows:
                    out.append({"id": r.get(".id"), "list": lst, "ip": _addr_of(r.get("address", "")),
                                "timeout": r.get("timeout", ""), "timeout_s": parse_duration(r.get("timeout", "")),
                                "comment": r.get("comment", ""), "created": r.get("creation-time", ""),
                                "dynamic": r.get("dynamic", "")})
        return out
