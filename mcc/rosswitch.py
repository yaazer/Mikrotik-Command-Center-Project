"""Switches running RouterOS (CRS3xx/5xx can boot RouterOS or SwOS), read over the same REST API
as the router -- plus detection of which OS a switch is running.

Read-only: MCC polls /interface counters, /interface/ethernet/monitor (link rate) and system
resource/health. The output matches swos.SwOS.read() so the rest of MCC treats both alike.
"""

from __future__ import annotations

import http.client
import re
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple

from .routeros import RouterOS, RouterOSError
from .util import to_bool, to_float, to_int


def split_host(host: str, default_port: int) -> Tuple[str, int]:
    host = host.strip()
    if host.startswith("[") and "]" in host:  # [v6]:port
        h, _, rest = host[1:].partition("]")
        return h, int(rest.lstrip(":") or default_port)
    if host.count(":") == 1:
        h, p = host.split(":")
        return h, int(p)
    return host, default_port


def detect_os(host: str, scheme: str = "http", timeout: float = 6.0) -> str:
    """'routeros' | 'swos' | 'unknown', from how an unauthenticated request is refused.
    RouterOS REST says 401 with a JSON body; SwOS asks for HTTP digest auth."""
    h, port = split_host(host, 443 if scheme == "https" else 80)
    try:
        if scheme == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(h, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(h, port, timeout=timeout)
        conn.request("GET", "/rest/system/resource", headers={"Accept": "application/json"})
        r = conn.getresponse()
        body = r.read(2048).decode("utf-8", "replace")
        auth = r.getheader("WWW-Authenticate", "") or ""
        conn.close()
    except (OSError, http.client.HTTPException, ssl.SSLError):
        return "unknown"
    if "digest" in auth.lower():
        return "swos"
    if r.status in (401, 200) and ('"error"' in body or body.lstrip().startswith(("{", "["))):
        return "routeros"
    return "unknown"


_RATE = re.compile(r"^([\d.]+)\s*([GM])bps$", re.I)


def rate_label(rate: str) -> str:
    """'10Gbps' -> '10G', '100Mbps' -> '100M'."""
    m = _RATE.match(str(rate or "").strip())
    if not m:
        return ""
    num = m.group(1).rstrip("0").rstrip(".") if "." in m.group(1) else m.group(1)
    return "{}{}".format(num, m.group(2).upper())


class RouterOSSwitch:
    kind = "routeros"
    SPEED_EVERY = 30.0

    def __init__(self, host: str, user: str, password: str, scheme: str = "http", verify_tls: bool = False,
                 pinned_sha256: str = ""):
        h, port = split_host(host, 443 if scheme == "https" else 80)
        self.host = host
        self.ros = RouterOS(h, user, password, scheme, port, verify_tls, pinned_sha256, timeout=8.0)
        self._speeds: Dict[str, Dict[str, Any]] = {}
        self._speeds_at = 0.0
        self._sys: Dict[str, Any] = {}
        self._sys_at = 0.0

    def _ports(self) -> List[Dict[str, Any]]:
        rows = self.ros.get_list("/interface", {".proplist": ".id,name,default-name,type,running,disabled,rx-byte,"
                                                              "tx-byte,rx-error,tx-error,comment,link-downs"})
        return [r for r in rows if r.get("type") == "ether"]

    def _refresh_speeds(self, names: List[str]) -> None:
        if not names or time.time() - self._speeds_at < self.SPEED_EVERY:
            return
        self._speeds_at = time.time()
        try:
            out = self.ros.command("/interface/ethernet/monitor", {"numbers": ",".join(names), "once": "true"})
        except RouterOSError:
            return  # older builds / restricted users: speeds just stay blank
        for row in out if isinstance(out, list) else [out] if isinstance(out, dict) else []:
            if row.get("name"):
                self._speeds[row["name"]] = row

    def _refresh_sys(self) -> None:
        if time.time() - self._sys_at < 60 and self._sys:
            return
        self._sys_at = time.time()
        res = self.ros.get("/system/resource") or {}
        ident = self.ros.get("/system/identity") or {}
        temp = None
        try:
            h = self.ros.get("/system/health")
            vals = {r.get("name"): to_float(r.get("value")) for r in h if isinstance(r, dict)} if isinstance(h, list) \
                else {k: to_float(v) for k, v in (h or {}).items()}
            temp = next((vals[k] for k in ("cpu-temperature", "temperature", "switch-temperature", "board-temperature1")
                         if k in vals), None)
        except RouterOSError:
            pass
        self._sys = {"identity": ident.get("name", ""), "model": res.get("board-name", ""),
                     "version": "RouterOS " + str(res.get("version", "")).split(" ")[0], "temp": temp,
                     "cpu": to_float(res.get("cpu-load")), "uptime": res.get("uptime", ""), "os": "routeros"}

    def read(self) -> Dict[str, Any]:
        rows = self._ports()
        self._refresh_speeds([r["name"] for r in rows if not to_bool(r.get("disabled"))])
        self._refresh_sys()
        ports = []
        for i, r in enumerate(rows):
            mon = self._speeds.get(r["name"], {})
            up = to_bool(r.get("running"))
            ports.append({
                "n": i + 1, "name": r["name"], "id": r.get(".id"), "comment": r.get("comment", ""),
                "enabled": not to_bool(r.get("disabled")), "link": up, "full_duplex": to_bool(mon.get("full-duplex", "true")),
                "speed": rate_label(mon.get("rate", "")) if up else "",
                "rx_bytes": float(to_int(r.get("rx-byte"))), "tx_bytes": float(to_int(r.get("tx-byte"))),
                "rx_rate_bps": None, "tx_rate_bps": None,
                "rx_errors": float(to_int(r.get("rx-error"))),
                "sfp": r["name"].startswith(("sfp", "qsfp")) or "sfp" in str(r.get("default-name", "")),
            })
        return {"ports": ports, "sys": dict(self._sys)}

    def probe(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"os": "routeros"}
        for path in ("/system/resource", "/interface"):
            try:
                out[path] = self.ros.get(path)
            except RouterOSError as e:
                out[path] = {"error": str(e)}
        try:
            names = [r["name"] for r in self._ports()]
            out["/interface/ethernet/monitor"] = self.ros.command("/interface/ethernet/monitor",
                                                                  {"numbers": ",".join(names), "once": "true"})
        except RouterOSError as e:
            out["/interface/ethernet/monitor"] = {"error": str(e)}
        return out

    def close(self) -> None:
        self.ros.close()
