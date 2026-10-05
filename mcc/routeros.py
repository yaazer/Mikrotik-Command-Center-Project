"""RouterOS 7 REST client (stdlib only).

The password is turned into a Basic auth header held on this object and nowhere else. HTTPS
certificates on RouterOS are usually self-signed, so instead of CA validation the client pins the
certificate's SHA-256 fingerprint on first use; if it changes later every call is refused.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import http.client
import json
import socket
import ssl
import threading
import urllib.parse
from typing import Any, Dict, List, Optional


class RouterOSError(Exception):
    def __init__(self, message: str, status: int = 0, detail: str = ""):
        super().__init__(message)
        self.message = message
        self.status = status
        self.detail = detail

    def __str__(self) -> str:
        return "{}: {}".format(self.message, self.detail) if self.detail else self.message


class CertificateChanged(RouterOSError):
    pass


def fingerprint(der: bytes) -> str:
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def local_ip_toward(host: str, port: int = 9) -> str:
    """The source address this machine uses to reach `host` (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, port))
            return s.getsockname()[0]
    except OSError:
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
                s.connect((host, port))
                return s.getsockname()[0]
        except OSError:
            return ""


def _cli_value(v: Any) -> str:
    if isinstance(v, bool):
        return "yes" if v else "no"
    s = str(v)
    if s == "true":
        return "yes"
    if s == "false":
        return "no"
    if s == "" or any(c in s for c in ' "\\;$[]{}=#'):
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def cli_line(method: str, path: str, body: Optional[Dict[str, Any]] = None, target: str = "") -> str:
    """The terminal command equivalent to a REST call, for showing people exactly what will change."""
    parts = [p for p in path.strip("/").split("/") if p]
    kv = " ".join("{}={}".format(k, _cli_value(v)) for k, v in (body or {}).items() if not k.startswith("."))
    if method == "PUT":
        return "/{} add {}".format(" ".join(parts), kv).rstrip()
    if method in ("PATCH", "DELETE"):
        item = parts.pop() if parts and parts[-1].startswith("*") else ""
        ref = target or "[find .id={}]".format(item)
        if method == "PATCH":
            return "/{} set {} {}".format(" ".join(parts), ref, kv).rstrip()
        return "/{} remove {}".format(" ".join(parts), ref)
    if method == "POST":
        return "/{} {}".format(" ".join(parts), kv).rstrip()
    return "/{} print".format(" ".join(parts))


class RouterOS:
    def __init__(self, host: str, user: str, password: str, scheme: str = "https", port: Optional[int] = None,
                 verify_tls: bool = False, pinned_sha256: str = "", timeout: float = 8.0):
        self.host = host.strip()
        self.scheme = (scheme or "https").lower()
        self.port = int(port or (443 if self.scheme == "https" else 80))
        self.user = user
        self.verify_tls = bool(verify_tls)
        self.pinned = (pinned_sha256 or "").upper()
        self.timeout = timeout
        self.fingerprint = ""
        self._auth = "Basic " + base64.b64encode("{}:{}".format(user, password).encode("utf-8")).decode("ascii")
        self._lock = threading.Lock()
        self._conn: Optional[http.client.HTTPConnection] = None

    def clone(self) -> "RouterOS":
        """Same credentials, its own connection -- so slow table reads don't hold up fast polls."""
        c = copy.copy(self)
        c._lock = threading.Lock()
        c._conn = None
        return c

    # -- transport ---------------------------------------------------------------------------
    def _connect(self) -> http.client.HTTPConnection:
        if self.scheme == "https":
            if self.verify_tls:
                ctx = ssl.create_default_context()
            else:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout, context=ctx)
            conn.connect()
            der = conn.sock.getpeercert(binary_form=True) or b""  # type: ignore[union-attr]
            self.fingerprint = fingerprint(der) if der else ""
            if self.pinned and self.fingerprint != self.pinned:
                conn.close()
                raise CertificateChanged(
                    "router certificate changed", 0,
                    "pinned {}, router now presents {}. If you replaced the certificate, re-pin it in Setup."
                    .format(self.pinned, self.fingerprint))
        else:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            conn.connect()
        return conn

    def _close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
        self._conn = None

    def close(self) -> None:
        with self._lock:
            self._close()

    def request(self, method: str, path: str, body: Any = None, params: Optional[Dict[str, Any]] = None) -> Any:
        url = "/rest" + (path if path.startswith("/") else "/" + path)
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}, safe=",.*")
        headers = {"Authorization": self._auth, "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        # GETs reuse a kept-alive connection and retry once if the router closed it. Anything that
        # changes state gets a fresh connection and is never retried, so it can't run twice.
        idempotent = method == "GET"
        with self._lock:
            for attempt in (0, 1):
                try:
                    if not idempotent:
                        self._close()
                    if self._conn is None:
                        self._conn = self._connect()
                    self._conn.request(method, url, body=data, headers=headers)
                    resp = self._conn.getresponse()
                    raw = resp.read()
                    status = resp.status
                    if resp.getheader("Connection", "").lower() == "close" or not idempotent:
                        self._close()
                    break
                except CertificateChanged:
                    self._close()
                    raise
                except (OSError, http.client.HTTPException, ssl.SSLError) as e:
                    self._close()
                    if attempt or not idempotent:
                        raise RouterOSError("cannot reach the router at {}:{}".format(self.host, self.port), 0, str(e))
        if status == 401:
            raise RouterOSError("the router refused the user name or password", 401)
        payload: Any = None
        if raw:
            try:
                payload = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                payload = raw.decode("utf-8", "replace")
        if status >= 400:
            msg, detail = "router said {}".format(status), ""
            if isinstance(payload, dict):
                msg = str(payload.get("message") or msg)
                detail = str(payload.get("detail") or "")
            raise RouterOSError(msg, status, detail)
        return payload

    # -- verbs -------------------------------------------------------------------------------
    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return self.request("GET", path, params=params)

    def get_list(self, path: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        out = self.get(path, params)
        if isinstance(out, dict):
            return [out]
        return [x for x in (out or []) if isinstance(x, dict)]

    def add(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("PUT", path, body) or {}

    def set(self, path: str, item_id: str, body: Dict[str, Any]) -> Any:
        return self.request("PATCH", "{}/{}".format(path, item_id), body)

    def remove(self, path: str, item_id: str) -> Any:
        return self.request("DELETE", "{}/{}".format(path, item_id))

    def command(self, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        return self.request("POST", path, body or {})
