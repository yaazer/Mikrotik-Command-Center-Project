"""Telemetry setup: show the exact router configuration MCC wants, apply it only when approved.

plan() reads the router and returns items, each with the precise REST calls and the equivalent
terminal commands. apply(plan_id, items) runs *that* plan -- the one you looked at -- not a fresh
one, and refuses if it is stale. Everything created is recorded in data/setup_state.json so
removal can take exactly that back out (removal is planned and approved the same way).
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .actions import BLOCK_LIST, QUARANTINE_LIST, TAG
from .routeros import RouterOSError, cli_line

PLAN_TTL = 600


def _ch(method: str, path: str, body: Optional[Dict[str, Any]] = None, target: str = "",
        note: str = "") -> Dict[str, Any]:
    return {"method": method, "path": path, "body": body or {}, "cli": cli_line(method, path, body, target),
            "note": note}


class SetupPlanner:
    def __init__(self, hub: Any, data_dir: Path):
        self.hub = hub
        self.path = Path(data_dir) / "setup_state.json"
        self.lock = threading.Lock()
        self.plans: Dict[str, Dict[str, Any]] = {}
        self.state = self._load()

    def _load(self) -> Dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"created": [], "flow_prev": None, "applied": []}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.state, indent=1), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass

    # -- reading the router ------------------------------------------------------------------
    def _wan_match(self, ros: Any) -> Dict[str, Any]:
        lists = [r.get("name") for r in ros.get_list("/interface/list")]
        if "WAN" in lists:
            return {"in-interface-list": "WAN"}
        configured = self.hub.cfg.get("wan.interfaces") or []
        if configured:
            return {"in-interface": configured[0]}
        wans = self.hub.wan_ifaces()
        if wans:
            return {"in-interface": sorted(wans)[0]}
        return {}

    def plan(self) -> Dict[str, Any]:
        ros = self.hub.ros
        if ros is None:
            raise RouterOSError("not connected to the router")
        mcc_ip = self.hub.mcc_ip()
        flow_port = int(self.hub.collector_port("flow"))
        syslog_port = int(self.hub.collector_port("syslog"))
        items = []

        # 1. Traffic Flow -> MCC
        tf = ros.get("/ip/traffic-flow") or {}
        if isinstance(tf, list):
            tf = tf[0] if tf else {}
        targets = ros.get_list("/ip/traffic-flow/target")
        ours = [t for t in targets if t.get("dst-address") == mcc_ip and str(t.get("port")) == str(flow_port)]
        ch = []
        want = {"enabled": "yes", "active-flow-timeout": "1m", "inactive-flow-timeout": "15s"}
        if str(tf.get("enabled")) != "true" or tf.get("active-flow-timeout") not in ("1m", "00:01:00", "1m0s") \
                or tf.get("inactive-flow-timeout") not in ("15s", "00:00:15"):
            ch.append(_ch("POST", "/ip/traffic-flow/set", want,
                          note="turn on flow export; report long flows every minute, idle ones after 15 s"))
        if not ours:
            ch.append(_ch("PUT", "/ip/traffic-flow/target",
                          {"dst-address": mcc_ip, "port": str(flow_port), "version": "ipfix"},
                          note="send the flow records to this machine"))
        others = [t for t in targets if t not in ours]
        items.append({
            "id": "flows", "title": "Traffic Flow (IPFIX) export to MCC",
            "why": "Complete per-flow accounting of what crosses the router -- the traffic view, scans of "
                   "closed ports, fan-out and blocklist detection. Costs a little router CPU.",
            "status": "installed" if not ch else ("partial" if ours or str(tf.get("enabled")) == "true" else "missing"),
            "detail": "existing targets left alone: {}".format(", ".join(
                "{}:{}".format(t.get("dst-address"), t.get("port")) for t in others)) if others else "",
            "changes": ch, "current": {k: tf.get(k) for k in ("enabled", "interfaces", "active-flow-timeout",
                                                               "inactive-flow-timeout")}})

        # 2. syslog -> MCC
        actions = ros.get_list("/system/logging/action")
        act = next((a for a in actions if a.get("name") == "mcc"), None)
        ch = []
        if act is None:
            ch.append(_ch("PUT", "/system/logging/action",
                          {"name": "mcc", "target": "remote", "remote": mcc_ip, "remote-port": str(syslog_port)},
                          note="a log destination pointing at this machine"))
        elif act.get("remote") != mcc_ip or str(act.get("remote-port")) != str(syslog_port):
            ch.append(_ch("PATCH", "/system/logging/action/{}".format(act[".id"]),
                          {"remote": mcc_ip, "remote-port": str(syslog_port)}, target="mcc",
                          note="point the existing 'mcc' destination at this machine"))
        rules = ros.get_list("/system/logging")
        for topics, why in (("firewall", "firewall log lines (blocked and logged packets)"),
                            ("critical", "login failures and other critical events"),
                            ("interface", "link up / down")):
            if not any(r.get("action") == "mcc" and r.get("topics") == topics for r in rules):
                ch.append(_ch("PUT", "/system/logging", {"topics": topics, "action": "mcc"}, note=why))
        items.append({
            "id": "syslog", "title": "Send firewall, login and link logs to MCC",
            "why": "Real-time feed for scan, brute-force and link-down detection. Without it MCC reads the "
                   "router's in-memory log every few seconds, which can miss lines when it is busy.",
            "status": "installed" if not ch else ("partial" if act else "missing"), "detail": "", "changes": ch})

        # 3. log new inbound attempts
        wan = self._wan_match(ros)
        filt = ros.get_list("/ip/firewall/filter")
        ch = []
        detail = ""
        if not wan:
            detail = "MCC couldn't tell which interface faces the Internet. Set it in Settings > WAN interface."
        else:
            first = filt[0].get(".id") if filt else None
            for chain, prefix, extra, why in (
                    ("input", "MCC-IN", {}, "new connection attempts to the router itself"),
                    ("forward", "MCC-FWD", {"connection-nat-state": "!dstnat"},
                     "unsolicited attempts to reach your LAN")):
                if not any(r.get("action") == "log" and r.get("log-prefix") == prefix for r in filt):
                    body = {"chain": chain, "action": "log", "log-prefix": prefix, "connection-state": "new"}
                    body.update(wan)
                    body.update(extra)
                    body["limit"] = "50/1s,100:packet"
                    body["comment"] = "{} log {}".format(TAG, why)
                    if first:
                        body["place-before"] = first
                    ch.append(_ch("PUT", "/ip/firewall/filter", body,
                                  note="log (not drop) {}, at most 50/s".format(why)))
        items.append({
            "id": "logrules", "title": "Log new inbound connection attempts",
            "why": "Two non-blocking 'log' rules at the top of the filter so every attempt from the Internet "
                   "is seen, whatever your later rules do with it. They don't change what is allowed.",
            "status": "unavailable" if not wan else ("installed" if not ch else "missing"),
            "detail": detail, "changes": ch, "wan": wan})

        # 4. drop rules for MCC's address lists
        ch = []
        for base in ("/ip",):
            for lst in (BLOCK_LIST, QUARANTINE_LIST):
                for c in self.hub.actions._drop_rules(ros, base, lst):
                    ch.append({k: c[k] for k in ("method", "path", "body", "cli", "note")})
        items.append({
            "id": "droprules", "title": "Rules that make MCC's block and quarantine lists work",
            "why": "Raw-table drops for the {} list and forward-chain drops for {}. Both lists start empty, "
                   "so these change nothing until you confirm a block. (Your first block adds them anyway.)"
                   .format(BLOCK_LIST, QUARANTINE_LIST),
            "status": "installed" if not ch else "missing", "detail": "", "changes": ch})

        pid = uuid.uuid4().hex[:12]
        plan = {"id": pid, "kind": "apply", "made_at": time.time(), "mcc_ip": mcc_ip, "flow_port": flow_port,
                "syslog_port": syslog_port, "items": items, "flow_prev": items[0]["current"]}
        with self.lock:
            self.plans = {k: v for k, v in self.plans.items() if time.time() - v["made_at"] < PLAN_TTL}
            self.plans[pid] = plan
        return plan

    def removal_plan(self, include_lists: bool = False) -> Dict[str, Any]:
        ros = self.hub.ros
        if ros is None:
            raise RouterOSError("not connected to the router")
        mcc_ip = self.hub.mcc_ip()
        ch: List[Dict[str, Any]] = []
        for base in ("/ip", "/ipv6"):
            for table in ("raw", "filter"):
                try:
                    rows = ros.get_list("{}/firewall/{}".format(base, table))
                except RouterOSError:
                    continue
                for r in rows:
                    if str(r.get("comment", "")).startswith(TAG):
                        ch.append(_ch("DELETE", "{}/firewall/{}/{}".format(base, table, r[".id"]),
                                      target='[find comment="{}"]'.format(r.get("comment")),
                                      note=r.get("comment", "")))
            if include_lists:
                for lst in (BLOCK_LIST, QUARANTINE_LIST):
                    try:
                        rows = ros.get_list(base + "/firewall/address-list", {"list": lst})
                    except RouterOSError:
                        continue
                    for r in rows:
                        ch.append(_ch("DELETE", "{}/firewall/address-list/{}".format(base, r[".id"]),
                                      target="[find list={} address={}]".format(lst, r.get("address")),
                                      note="{} {}".format(lst, r.get("address"))))
        for r in ros.get_list("/system/logging"):
            if r.get("action") == "mcc":
                ch.append(_ch("DELETE", "/system/logging/{}".format(r[".id"]),
                              target="[find action=mcc topics={}]".format(r.get("topics")),
                              note="send {} to MCC".format(r.get("topics"))))
        for a in ros.get_list("/system/logging/action"):
            if a.get("name") == "mcc":
                ch.append(_ch("DELETE", "/system/logging/action/{}".format(a[".id"]), target="mcc",
                              note="the 'mcc' log destination"))
        flow_port = str(self.hub.collector_port("flow"))
        for t in ros.get_list("/ip/traffic-flow/target"):
            if t.get("dst-address") == mcc_ip and str(t.get("port")) == flow_port:
                ch.append(_ch("DELETE", "/ip/traffic-flow/target/{}".format(t[".id"]),
                              target="[find dst-address={}]".format(mcc_ip), note="flow export to MCC"))
        prev = self.state.get("flow_prev")
        if prev and str(prev.get("enabled")) != "true":
            ch.append(_ch("POST", "/ip/traffic-flow/set", {"enabled": "no"},
                          note="Traffic Flow was off before MCC turned it on"))
        pid = uuid.uuid4().hex[:12]
        plan = {"id": pid, "kind": "remove", "made_at": time.time(), "items": [
            {"id": "remove", "title": "Remove everything MCC added", "status": "present" if ch else "clean",
             "why": "Takes out the rules, log destinations and flow target MCC created{}. Your own "
                    "configuration is not touched.".format(", and empties MCC's block lists" if include_lists else ""),
             "changes": ch}]}
        with self.lock:
            self.plans[pid] = plan
        return plan

    # -- applying ----------------------------------------------------------------------------
    def apply(self, plan_id: str, item_ids: List[str]) -> Dict[str, Any]:
        with self.lock:
            plan = self.plans.pop(plan_id, None)
        if plan is None or time.time() - plan["made_at"] > PLAN_TTL:
            raise RouterOSError("that plan is out of date -- review the current one and approve again")
        ros = self.hub.ros
        if ros is None:
            raise RouterOSError("not connected to the router")
        results = []
        for item in plan["items"]:
            if item["id"] not in item_ids or not item["changes"]:
                continue
            steps = []
            if item["id"] == "flows" and self.state.get("flow_prev") is None:
                self.state["flow_prev"] = plan.get("flow_prev")
            for c in item["changes"]:
                try:
                    if c["method"] == "PUT":
                        out = ros.add(c["path"], c["body"]) or {}
                        self.state["created"].append({"path": c["path"], "id": out.get(".id", ""), "item": item["id"],
                                                      "at": time.time()})
                        res = "created {}".format(out.get(".id", ""))
                    elif c["method"] == "DELETE":
                        try:
                            ros.request("DELETE", c["path"])
                            res = "removed"
                        except RouterOSError as e:
                            if e.status != 404:
                                raise
                            res = "already gone"
                    else:
                        ros.request(c["method"], c["path"], c["body"])
                        res = "done"
                    steps.append({"cli": c["cli"], "ok": True, "result": res})
                except RouterOSError as e:
                    steps.append({"cli": c["cli"], "ok": False, "result": str(e)})
                    break
            ok = all(s["ok"] for s in steps)
            results.append({"id": item["id"], "title": item["title"], "ok": ok, "steps": steps})
            self.state.setdefault("applied", []).append({"at": time.time(), "plan": plan["kind"], "item": item["id"],
                                                         "ok": ok, "steps": steps})
            self.state["applied"] = self.state["applied"][-100:]
        if plan["kind"] == "remove" and all(r["ok"] for r in results):
            self.state["created"] = []
            self.state["flow_prev"] = None
        self._save()
        self.hub.publish("setup", {"results": results})
        return {"plan": plan["kind"], "results": results}
