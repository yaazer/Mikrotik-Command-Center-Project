"""qBittorrent WebUI API v2 client (stdlib only).

The password is used once, at login, to get a session cookie -- whatever name and value the
server's Set-Cookie actually gives (usually SID) -- held on this object and nowhere else. A
build with "Bypass authentication for clients on localhost" needs no cookie at all; that's fine
too, every request just goes out without one.

qBittorrent 5.0 renamed torrents/pause and torrents/resume to torrents/stop and torrents/start.
set_state() tries the new names first and remembers, for the rest of this object's life, whether
it had to fall back to the old ones.
"""

from __future__ import annotations

import http.client
import json
import ssl
import threading
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

INFINITE_ETA = 8640000  # qBittorrent's "no estimate" sentinel (100 days)


class QbtError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.message = message
        self.status = status

    def __str__(self) -> str:
        return self.message


class Qbt:
    def __init__(self, host: str, user: str, password: str, scheme: str = "http",
                 port: Optional[int] = None, timeout: float = 6.0):
        self.host = host.strip()
        self.scheme = (scheme or "http").lower()
        self.port = int(port or (443 if self.scheme == "https" else 8080))
        self.user = user
        self.password = password
        self.timeout = timeout
        self.base = "{}://{}:{}".format(self.scheme, self.host, self.port)
        self._cookie = ""  # "name=value", exactly as Set-Cookie gave it, echoed back as-is
        self._stop_api: Optional[bool] = None  # None: unknown yet; True: stop/start; False: pause/resume
        self._lock = threading.Lock()
        self._conn: Optional[http.client.HTTPConnection] = None

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
            self._conn = None

    # -- transport ---------------------------------------------------------------------------
    def _connect(self) -> http.client.HTTPConnection:
        if self.scheme == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        conn.connect()
        return conn

    def _raw(self, method: str, path: str, body: Optional[bytes] = None,
             headers: Optional[Dict[str, str]] = None) -> Tuple[int, bytes, str]:
        headers = dict(headers or {})
        headers.setdefault("Referer", self.base)
        headers.setdefault("Origin", self.base)
        if self._cookie:
            headers["Cookie"] = self._cookie
        with self._lock:
            for attempt in (0, 1):
                try:
                    if self._conn is None:
                        self._conn = self._connect()
                    self._conn.request(method, path, body=body, headers=headers)
                    resp = self._conn.getresponse()
                    raw = resp.read()
                    status = resp.status
                    set_cookie = resp.getheader("Set-Cookie", "")
                    if resp.getheader("Connection", "").lower() == "close":
                        self._conn.close()
                        self._conn = None
                    return status, raw, set_cookie
                except (OSError, http.client.HTTPException) as e:
                    if self._conn is not None:
                        try:
                            self._conn.close()
                        except Exception:
                            pass
                        self._conn = None
                    if attempt:
                        raise QbtError("cannot reach qBittorrent at {}:{}: {}".format(self.host, self.port, e))
            raise AssertionError("unreachable")

    # -- auth ----------------------------------------------------------------------------------
    def login(self) -> None:
        body = urllib.parse.urlencode({"username": self.user, "password": self.password}).encode("utf-8")
        status, raw, set_cookie = self._raw("POST", "/api/v2/auth/login", body,
                                            {"Content-Type": "application/x-www-form-urlencoded"})
        if status == 403:
            raise QbtError("qBittorrent has temporarily banned this address after too many failed logins "
                           "-- wait a while before trying again", 403)
        text = raw.decode("utf-8", "replace").strip()
        if status != 200 or text != "Ok.":
            raise QbtError("qBittorrent refused the user name or password", 401)
        if set_cookie:
            self._cookie = set_cookie.split(";", 1)[0]

    def _request(self, method: str, path: str, params: Optional[Dict[str, Any]] = None,
                relogin: bool = True) -> Any:
        qs = urllib.parse.urlencode(params) if params else ""
        url = path + ("?" + qs if qs else "")
        # the wiki's own curl examples pass these in the query string even on a POST, but a form
        # body is the REST convention most clients (and qBittorrent's own) would otherwise expect
        # -- send both so either a query-string or a forms-only reader on the other end is satisfied
        body = qs.encode("utf-8") if method == "POST" and qs else None
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if body else None
        status, raw, _ = self._raw(method, url, body, headers)
        if status == 403 and relogin:
            self.login()
            return self._request(method, path, params, relogin=False)
        if status >= 400:
            raise QbtError("qBittorrent said {} for {}".format(status, path), status)
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return raw.decode("utf-8", "replace")

    # -- verbs -------------------------------------------------------------------------------
    def torrents_info(self) -> List[Dict[str, Any]]:
        out = self._request("GET", "/api/v2/torrents/info")
        return [t for t in (out or []) if isinstance(t, dict)]

    def set_state(self, hashes: str, pause: bool) -> None:
        """pause: stop (or the older pause); not pause: start (or resume)."""
        names = ("pause", "resume") if self._stop_api is False else ("stop", "start")
        verb = names[0] if pause else names[1]
        try:
            self._request("POST", "/api/v2/torrents/{}".format(verb), {"hashes": hashes})
            if self._stop_api is None:
                self._stop_api = True
        except QbtError as e:
            if e.status == 404 and self._stop_api is None:
                self._stop_api = False
                other = "pause" if pause else "resume"
                self._request("POST", "/api/v2/torrents/{}".format(other), {"hashes": hashes})
            else:
                raise


LIST_CAP = 150  # keeps every tick small; a long list is truncated at the least interesting end


def rows(raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The fields the console shows: active torrents first (fastest first), then other unfinished
    ones, then finished/seeding ones last -- so a cap at the end never hides an active or paused
    download behind a pile of idle seeds."""
    out = []
    for t in raw:
        h = t.get("hash")
        if not h:
            continue
        eta = t.get("eta")
        dlspeed, upspeed = int(t.get("dlspeed") or 0), int(t.get("upspeed") or 0)
        out.append({
            "hash": h, "name": t.get("name", ""), "state": t.get("state", ""),
            "progress": round(float(t.get("progress") or 0), 4),
            "dlspeed": dlspeed, "upspeed": upspeed,
            "eta": None if eta is None or eta < 0 or eta >= INFINITE_ETA else int(eta),
            "size": int(t.get("size") or 0), "downloaded": int(t.get("downloaded") or 0),
            "uploaded": int(t.get("uploaded") or 0), "ratio": round(float(t.get("ratio") or 0), 2),
            "num_seeds": int(t.get("num_seeds") or 0), "num_leechs": int(t.get("num_leechs") or 0),
            "category": t.get("category", ""),
        })

    def key(r: Dict[str, Any]) -> Tuple[int, Any]:
        if r["dlspeed"] or r["upspeed"]:
            return (0, -(r["dlspeed"] + r["upspeed"]))
        if r["progress"] < 1:
            return (1, r["name"].lower())
        return (2, r["name"].lower())

    out.sort(key=key)
    return out
