"""Minimal Chrome DevTools Protocol driver (stdlib only) for the UI checks.

    with Browser(width=1600, height=1000) as b:
        b.nav(url); b.wait(3); b.eval("document.title"); b.shot("out.png")
Collects console errors and uncaught exceptions in b.errors. Real time, not virtual time, so
requestAnimationFrame-driven drawing (the traffic map) actually runs.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.request
from typing import Any, List, Optional

CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def find_browser() -> Optional[str]:
    env = os.environ.get("MCC_BROWSER")
    if env and os.path.exists(env):
        return env
    for c in CANDIDATES:
        if os.path.exists(c):
            return c
    for name in ("google-chrome", "chromium", "chrome", "msedge"):
        p = shutil.which(name)
        if p:
            return p
    return None


class Browser:
    def __init__(self, width: int = 1600, height: int = 1000, mobile: bool = False, port: int = 0):
        self.width, self.height, self.mobile = width, height, mobile
        self.port = port or self._free_port()
        self.errors: List[str] = []
        self._id = 0
        self._rest = b""

    @staticmethod
    def _free_port() -> int:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def __enter__(self) -> "Browser":
        exe = find_browser()
        if not exe:
            raise RuntimeError("no Chrome/Edge found (set MCC_BROWSER)")
        self.profile = tempfile.mkdtemp(prefix="mcc-cdp-")
        self.proc = subprocess.Popen(
            [exe, "--headless=new", "--no-first-run", "--hide-scrollbars", "--disable-gpu-sandbox",
             "--window-size={},{}".format(max(self.width, 500), self.height),
             "--remote-debugging-port={}".format(self.port), "--user-data-dir=" + self.profile, "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        targets = None
        for _ in range(100):
            try:
                targets = json.load(urllib.request.urlopen("http://127.0.0.1:{}/json".format(self.port), timeout=2))
                if any(t["type"] == "page" for t in targets):
                    break
            except Exception:
                pass
            time.sleep(0.15)
        ws = next(t for t in targets if t["type"] == "page")["webSocketDebuggerUrl"]
        host, path = ws[len("ws://"):].split("/", 1)
        h, p = host.split(":")
        self.sock = socket.create_connection((h, int(p)))
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(("GET /{} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                           "Sec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n").format(path, host, key).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self.sock.recv(4096)
        self._rest = buf.split(b"\r\n\r\n", 1)[1]
        self.call("Page.enable")
        self.call("Runtime.enable")
        if self.mobile:
            self.call("Emulation.setDeviceMetricsOverride", width=self.width, height=self.height, deviceScaleFactor=2,
                      mobile=True)
        return self

    def __exit__(self, *a: Any) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.profile, ignore_errors=True)

    # -- websocket framing ---------------------------------------------------------------------
    def _exact(self, n: int) -> bytes:
        while len(self._rest) < n:
            chunk = self.sock.recv(1 << 16)
            if not chunk:
                raise ConnectionError("browser closed the connection")
            self._rest += chunk
        out, self._rest = self._rest[:n], self._rest[n:]
        return out

    def _recv(self) -> dict:
        data = b""
        while True:
            b1, b2 = self._exact(2)
            ln = b2 & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", self._exact(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", self._exact(8))[0]
            data += self._exact(ln)
            if b1 & 0x80:
                return json.loads(data)

    def _send(self, obj: dict) -> None:
        payload = json.dumps(obj).encode()
        mask = os.urandom(4)
        n = len(payload)
        hdr = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else
                               bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536 else
                               bytes([0x80 | 127]) + struct.pack(">Q", n))
        self.sock.sendall(hdr + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(payload)))

    def _event(self, m: dict) -> None:
        if m.get("method") == "Runtime.exceptionThrown":
            d = m["params"]["exceptionDetails"]
            self.errors.append("exception: " + (d.get("exception", {}).get("description") or d.get("text", "")))
        elif m.get("method") == "Runtime.consoleAPICalled" and m["params"].get("type") == "error":
            self.errors.append("console.error: " + " ".join(str(a.get("value", a.get("description", "")))
                                                             for a in m["params"].get("args", [])))

    def call(self, method: str, **params: Any) -> dict:
        self._id += 1
        my = self._id
        self._send({"id": my, "method": method, "params": params})
        while True:
            m = self._recv()
            if m.get("id") == my:
                if "error" in m:
                    raise RuntimeError("{}: {}".format(method, m["error"]))
                return m.get("result", {})
            self._event(m)

    # -- conveniences --------------------------------------------------------------------------
    def nav(self, url: str) -> None:
        self.call("Page.navigate", url=url)

    def wait(self, secs: float) -> None:
        end = time.time() + secs
        while time.time() < end:  # keep draining events (console errors) while we wait
            self.eval("0")
            time.sleep(min(0.25, max(0.0, end - time.time())))

    def eval(self, js: str) -> Any:
        r = self.call("Runtime.evaluate", expression=js, returnByValue=True, awaitPromise=True)
        if r.get("exceptionDetails"):
            raise RuntimeError("eval failed: {} -> {}".format(js[:80], r["exceptionDetails"].get("exception", {})
                                                              .get("description", r["exceptionDetails"].get("text"))))
        return r.get("result", {}).get("value")

    def until(self, js: str, timeout: float = 10.0) -> Any:
        end = time.time() + timeout
        while time.time() < end:
            v = self.eval(js)
            if v:
                return v
            time.sleep(0.2)
        return None

    def shot(self, path: str) -> str:
        data = self.call("Page.captureScreenshot", format="png")["data"]
        with open(path, "wb") as f:
            f.write(base64.b64decode(data))
        return path
