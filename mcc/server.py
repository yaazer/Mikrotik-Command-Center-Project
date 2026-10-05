"""HTTP server: the console's static files, a JSON API, and a server-sent-events stream.

Browser-side protection, because this server can change your router:
  * Host header must be this server (stops DNS-rebinding pages from talking to it);
  * every POST needs the X-MCC header (a cross-site page can't add one without a CORS preflight,
    which this server never grants) and a matching Origin when the browser sends one;
  * bound to anything but loopback, a per-run access token is required (printed at startup).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import mimetypes
import os
import queue
import secrets
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from .actions import ActionError
from .config import DEFAULTS
from .routeros import RouterOSError
from .swos import SwOSError
from .util import parse_networks

WEB = Path(__file__).resolve().parent / "web"


_DISK = {"sig": None, "build": ""}


def disk_build_id() -> str:
    """build_id() of the files on disk *now* -- re-hashed only when a file's size or mtime changed.
    Differs from the running build when MCC was updated but not restarted."""
    files = sorted(p for p in list(WEB.rglob("*")) + list(WEB.parent.glob("*.py")) if p.is_file())
    sig = tuple((str(p), p.stat().st_mtime_ns, p.stat().st_size) for p in files)
    if sig != _DISK["sig"]:
        _DISK.update(sig=sig, build=build_id())
    return _DISK["build"]


def build_id() -> str:
    """A fingerprint of the code this server runs (console files + Python modules). An open console
    tab compares it on every (re)connect and reloads itself when MCC was restarted on new code --
    otherwise a tab opened before the restart keeps running the old JavaScript."""
    h = hashlib.sha256()
    for p in sorted(list(WEB.rglob("*")) + list(WEB.parent.glob("*.py"))):
        if p.is_file():
            h.update(p.name.encode())
            h.update(p.read_bytes())
    return h.hexdigest()[:16]
MAX_BODY = 64 * 1024


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def handle_error(self, request: Any, client_address: Any) -> None:
        if not isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            super().handle_error(request, client_address)

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):  # Windows: never share the port with a stale copy
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def make_server(hub: Any, bind: str = "127.0.0.1", port: int = 8840) -> Tuple[Server, str]:
    token = "" if _is_loopback(bind) else secrets.token_urlsafe(18)
    build = build_id()

    class Handler(BaseHTTPRequestHandler):
        server_version = "MCC/0.1"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet
            pass

        # -- guards --------------------------------------------------------------------------
        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").strip()
            if token:
                return True  # the token is the guard when exposed on the network
            name = host.rsplit(":", 1)[0].strip("[]") if host.count(":") <= 1 or host.startswith("[") else host
            return name in ("127.0.0.1", "localhost", "::1")

        def _token_ok(self, q: Dict[str, str]) -> bool:
            if not token:
                return True
            if secrets.compare_digest(q.get("token", ""), token):
                return True
            cookie = self.headers.get("Cookie") or ""
            for part in cookie.split(";"):
                k, _, v = part.strip().partition("=")
                if k == "mcc_token" and secrets.compare_digest(v, token):
                    return True
            return False

        def _origin_ok(self) -> bool:
            origin = self.headers.get("Origin")
            if not origin:
                return True
            return urllib.parse.urlparse(origin).netloc == (self.headers.get("Host") or "")

        # -- responses -----------------------------------------------------------------------
        def _send(self, status: int, body: bytes, ctype: str, extra: Optional[Dict[str, str]] = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                             "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, obj: Any) -> None:
            self._send(status, json.dumps(obj, default=str).encode("utf-8"), "application/json; charset=utf-8")

        def _body(self) -> Dict[str, Any]:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise ApiError(413, "request too large")
            raw = self.rfile.read(n) if n else b"{}"
            try:
                data = json.loads(raw.decode("utf-8") or "{}")
            except ValueError:
                raise ApiError(400, "body is not JSON")
            if not isinstance(data, dict):
                raise ApiError(400, "body must be a JSON object")
            return data

        # -- dispatch ------------------------------------------------------------------------
        def do_HEAD(self) -> None:
            self.do_GET()

        def do_GET(self) -> None:
            url = urllib.parse.urlparse(self.path)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
            if not self._host_ok():
                return self._json(403, {"error": "unexpected Host header"})
            if not self._token_ok(q):
                return self._send(401, b"MCC needs its access token: open the URL printed in the terminal.",
                                  "text/plain; charset=utf-8")
            extra = {}
            if token and q.get("token"):
                extra["Set-Cookie"] = "mcc_token={}; HttpOnly; SameSite=Strict; Path=/".format(token)
            path = url.path
            try:
                if path == "/api/stream":
                    return self._stream()
                if path.startswith("/api/"):
                    return self._json(200, api_get(path, q))
                return self._static(path, extra)
            except ApiError as e:
                self._json(e.status, {"error": e.message})
            except (RouterOSError, SwOSError, ActionError) as e:
                self._json(409, {"error": str(e)})

        def do_POST(self) -> None:
            url = urllib.parse.urlparse(self.path)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
            if not self._host_ok() or not self._origin_ok():
                return self._json(403, {"error": "cross-site request refused"})
            if self.headers.get("X-MCC") != "1":
                return self._json(403, {"error": "missing X-MCC header"})
            if url.path == "/api/admin/shutdown":
                # only `mcc.py --replace` on this machine knows the per-run secret (temp run file)
                secret = getattr(hub, "admin_secret", "")
                given = self.headers.get("X-MCC-Secret") or ""
                if not secret or not secrets.compare_digest(given, secret) or not _is_loopback(self.client_address[0]):
                    return self._json(403, {"error": "shutdown refused"})
                self._json(200, {"ok": True})
                hook = getattr(hub, "shutdown_hook", None)
                if hook:
                    hook()
                return None
            if not self._token_ok(q):
                return self._json(401, {"error": "access token required"})
            try:
                body = self._body()
                return self._json(200, api_post(url.path, body))
            except ApiError as e:
                self._json(e.status, {"error": e.message})
            except (RouterOSError, SwOSError, ActionError) as e:
                self._json(409, {"error": str(e)})
            except (KeyError, TypeError, ValueError) as e:
                self._json(400, {"error": "bad request: {}".format(e)})

        def _static(self, path: str, extra: Dict[str, str]) -> None:
            if path in ("", "/"):
                path = "/index.html"
            target = (WEB / path.lstrip("/")).resolve()
            if WEB not in target.parents or not target.is_file():
                return self._send(404, b"not found", "text/plain")
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            self._send(200, target.read_bytes(), ctype, extra)

        def _stream(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.close_connection = True
            q = hub.bus.subscribe()
            try:
                self._event("state", dict(hub.full_state(), build=build, build_disk=disk_build_id()))
                last = time.time()
                while True:
                    try:
                        event, data = q.get(timeout=15)
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                        continue
                    self._event(event, data)
                    if event == "resync":
                        break
                    last = time.time()
            except (OSError, ValueError):
                pass
            finally:
                hub.bus.unsubscribe(q)

        def _event(self, name: str, data: Any) -> None:
            payload = json.dumps(data, default=str, separators=(",", ":"))
            self.wfile.write("event: {}\ndata: {}\n\n".format(name, payload).encode("utf-8"))
            self.wfile.flush()

    # -- API ---------------------------------------------------------------------------------
    def api_get(path: str, q: Dict[str, str]) -> Any:
        if path == "/api/state":
            return dict(hub.full_state(), build=build, build_disk=disk_build_id())
        if path == "/api/devices":
            return {"devices": hub.devices_view()}
        if path == "/api/host":
            ip = q.get("ip", "")
            return hub.host_view(ip)
        if path == "/api/entries":
            hub._refresh_entries()
            return {"entries": hub.entries}
        if path == "/api/setup/plan":
            return hub.setup.plan()
        if path == "/api/setup/removal":
            return hub.setup.removal_plan(include_lists=q.get("lists") == "1")
        if path == "/api/switch/probe":
            if hub.swos is None:
                raise ApiError(409, "no switch connected")
            return hub.swos.probe()
        if path == "/api/ignore":
            return {"rules": hub.detector.suppressions_list()}
        if path == "/api/geo":
            return dict(hub.geo.info(), home=hub.geo.home(hub.public_addrs()))
        if path == "/api/build":
            return {"build": build, "build_disk": disk_build_id()}
        if path == "/api/status":
            return hub.status()
        raise ApiError(404, "no such endpoint")

    def api_post(path: str, b: Dict[str, Any]) -> Any:
        parts = path.strip("/").split("/")
        if path == "/api/connect":
            r = b.get("router") or {}
            return hub.connect_router(str(r.get("host", "")), str(r.get("user", "")), str(r.get("password", "")),
                                      str(r.get("scheme") or "https"), int(r.get("port") or 0),
                                      bool(r.get("verify_tls")), bool(r.get("pin", True)), bool(r.get("repin")))
        if path == "/api/connect/switch":
            s = b.get("switch") or {}
            if not s.get("host"):
                raise ApiError(400, "switch address required")
            return hub.connect_switch(str(s["host"]), str(s.get("user") or "admin"), str(s.get("password") or ""),
                                      str(s.get("scheme") or "http"), str(s.get("kind") or "auto"))
        if path == "/api/disconnect":
            if b.get("what") == "switch":
                hub.disconnect_switch()
            else:
                hub.disconnect_router()
            return {"ok": True}
        if path == "/api/setup/apply":
            if b.get("approve") is not True:
                raise ApiError(400, "approve must be true")
            return hub.setup.apply(str(b.get("plan_id", "")), [str(i) for i in b.get("items") or []])
        if path == "/api/actions/propose":
            return hub.actions.propose(str(b.get("kind", "")), b.get("params") or {}, str(b.get("reason", ""))[:200],
                                       str(b.get("threat_id", "")))
        if len(parts) == 4 and parts[:2] == ["api", "actions"]:
            aid, verb = parts[2], parts[3]
            if verb == "confirm":
                if b.get("confirm") is not True:
                    raise ApiError(400, "confirm must be true")
                return hub.actions.confirm(aid, bool(b.get("acknowledge_risk")))
            if verb == "dismiss":
                return hub.actions.dismiss(aid)
            if verb == "undo":
                if b.get("confirm") is not True:
                    raise ApiError(400, "confirm must be true")
                return hub.actions.undo(aid)
        if len(parts) == 4 and parts[:2] == ["api", "threats"] and parts[3] == "status":
            status = b.get("status")
            if status not in ("acknowledged", "resolved", "open"):
                raise ApiError(400, "status must be acknowledged, resolved or open")
            t = hub.detector.set_status(parts[2], status, b.get("note", "") or "{} from the console".format(status))
            if t is None:
                raise ApiError(404, "no such threat")
            return t
        if len(parts) == 4 and parts[:2] == ["api", "threats"] and parts[3] == "ignore":
            t = hub.detector.threats.get(parts[2])
            if t is None:
                raise ApiError(404, "no such threat")
            scope = str(b.get("scope") or "exact")
            if scope != "exact" and not t.get("subject"):
                raise ApiError(400, "this threat has no address to ignore by; use scope 'exact'")
            try:
                sup = hub.detector.suppress(rule=t["rule"], scope=scope, key=t["key"], subject=t.get("subject", ""),
                                            note=str(b.get("note") or ""), duration=str(b.get("duration") or "0"),
                                            threat_id=t["id"], title=t.get("title", ""))
            except ValueError as e:
                raise ApiError(400, str(e))
            return {"ignore": sup, "threat": hub.detector.threats[t["id"]]}
        if path == "/api/ignore":
            try:
                return hub.detector.suppress(rule=str(b.get("rule") or "*"), scope=str(b.get("scope") or "subject"),
                                             subject=str(b.get("subject") or ""), note=str(b.get("note") or ""),
                                             duration=str(b.get("duration") or "0"))
            except ValueError as e:
                raise ApiError(400, str(e))
        if len(parts) == 4 and parts[:2] == ["api", "ignore"] and parts[3] == "remove":
            try:
                return hub.detector.unsuppress(parts[2])
            except KeyError:
                raise ApiError(404, "no such ignore rule")
        if path == "/api/devices/known":
            if not hub.detector.mark_known(str(b.get("mac", ""))):
                raise ApiError(404, "unknown MAC")
            return {"ok": True}
        if path == "/api/geo/download":
            if b.get("confirm") is not True:
                raise ApiError(400, "confirm must be true")
            try:
                return hub.geo.start_download(str(b.get("edition") or "country"),
                                              on_done=lambda: hub.publish("geo", hub.geo.info()))
            except ValueError as e:
                raise ApiError(409, str(e))
        if path == "/api/settings":
            cleaned = clean_settings(b)
            hub.cfg.update(cleaned)
            if "geo" in cleaned:
                hub.geo.load()
            hub.refresh_soon("meta")
            return hub.cfg.public()
        raise ApiError(404, "no such endpoint")

    httpd = Server((bind, port), Handler)
    return httpd, token


def clean_settings(b: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in ("lan_networks", "never_block"):
        if key in b:
            items = [str(x).strip() for x in b[key] if str(x).strip()]
            bad = [x for x in items if not parse_networks([x])]
            if bad:
                raise ApiError(400, "not an address or network: {}".format(", ".join(bad)))
            out[key] = items
    if "wan" in b:
        w = b["wan"] or {}
        out["wan"] = {"interfaces": [str(x) for x in w.get("interfaces") or []],
                      "down_mbps": max(0.0, float(w.get("down_mbps") or 0)),
                      "up_mbps": max(0.0, float(w.get("up_mbps") or 0))}
    for section in ("detect", "poll"):
        if section in b:
            out[section] = {}
            for k, v in (b[section] or {}).items():
                if k not in DEFAULTS[section]:
                    raise ApiError(400, "unknown setting {}.{}".format(section, k))
                d = DEFAULTS[section][k]
                if isinstance(d, list):
                    out[section][k] = sorted({int(x) for x in v if 0 < int(x) < 65536})
                else:
                    num = float(v)
                    if num <= 0:
                        raise ApiError(400, "{}.{} must be positive".format(section, k))
                    out[section][k] = int(num) if isinstance(d, int) else num
    if "collectors" in b:
        c = b["collectors"] or {}
        out["collectors"] = {}
        if "advertise_ip" in c:
            ip = str(c["advertise_ip"]).strip()
            if ip and not parse_networks([ip]):
                raise ApiError(400, "advertise_ip must be an IP address")
            out["collectors"]["advertise_ip"] = ip
        if "accept_from" in c:
            items = [str(x).strip() for x in c["accept_from"] if str(x).strip()]
            out["collectors"]["accept_from"] = items
    if "actions" in b and "default_block" in (b["actions"] or {}):
        v = str(b["actions"]["default_block"])
        if v not in ("15m", "1h", "24h", "7d", "0"):
            raise ApiError(400, "default_block must be 15m, 1h, 24h, 7d or 0")
        out["actions"] = {"default_block": v}
    if "geo" in b:
        g = b["geo"] or {}
        out["geo"] = {}
        if "db" in g:
            path = str(g["db"] or "").strip()
            if path and not path.lower().endswith(".mmdb"):
                raise ApiError(400, "the geolocation database must be an .mmdb file")
            out["geo"]["db"] = path
        if "home" in g:
            h = g["home"] or {}
            lat, lon = h.get("lat"), h.get("lon")
            if lat in (None, "") or lon in (None, ""):
                out["geo"]["home"] = {"lat": "", "lon": "", "label": ""}
            else:
                lat, lon = float(lat), float(lon)
                if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                    raise ApiError(400, "home latitude/longitude out of range")
                out["geo"]["home"] = {"lat": lat, "lon": lon, "label": str(h.get("label") or "Home")[:60]}
    if "switch_fields" in b:
        out["switch"] = {"fields": {str(k): v for k, v in (b["switch_fields"] or {}).items()}}
    return out
