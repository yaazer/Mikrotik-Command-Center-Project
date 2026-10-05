"""Stopping a running MCC so a new one can take its place (`python mcc.py --replace`).

Every MCC writes a small run file (temp dir, keyed by UI port) with its PID and a random
per-run secret. --replace asks that instance to shut down cleanly through
/api/admin/shutdown (loopback only, secret required) and waits for the port to free.
An instance that predates this (no run file), or one that doesn't answer, is found by the
process listening on the port -- confirmed to be MCC by its web server -- and terminated.
Nothing that isn't MCC is ever touched.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional


def run_file(port: int) -> Path:
    return Path(tempfile.gettempdir()) / "mcc-{}.run.json".format(port)


def write_run_file(port: int) -> str:
    secret = secrets.token_hex(16)
    p = run_file(port)
    try:
        p.write_text(json.dumps({"pid": os.getpid(), "port": port, "secret": secret, "started": time.time()}),
                     encoding="utf-8")
        if os.name != "nt":
            os.chmod(p, 0o600)
    except OSError:
        pass
    return secret


def remove_run_file(port: int) -> None:
    p = run_file(port)
    try:
        if json.loads(p.read_text(encoding="utf-8")).get("pid") == os.getpid():
            p.unlink()
    except (OSError, ValueError):
        pass


def port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False


def is_mcc(port: int) -> bool:
    """Is whatever listens on this port an MCC console?"""
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        c.request("GET", "/", headers={"Host": "127.0.0.1:{}".format(port)})
        r = c.getresponse()
        body = r.read(4096).decode("utf-8", "replace")
        server = r.getheader("Server", "") or ""
        c.close()
    except (OSError, http.client.HTTPException):
        return False
    return server.startswith("MCC/") or "Mikrotik Command Center" in body


def listener_pid(port: int) -> Optional[int]:
    """PID of the process listening on a TCP port (Windows netstat, else lsof / ss)."""
    try:
        if os.name == "nt":
            out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True, timeout=15).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[3].upper() == "LISTENING" and parts[1].rsplit(":", 1)[-1] == str(port):
                    return int(parts[4])
            return None
        if shutil.which("lsof"):
            out = subprocess.run(["lsof", "-nP", "-iTCP:{}".format(port), "-sTCP:LISTEN", "-t"],
                                 capture_output=True, text=True, timeout=15).stdout.split()
            return int(out[0]) if out else None
        if shutil.which("ss"):
            out = subprocess.run(["ss", "-ltnpH", "sport = :{}".format(port)], capture_output=True, text=True,
                                 timeout=15).stdout
            m = re.search(r"pid=(\d+)", out)
            return int(m.group(1)) if m else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return None


def _wait_free(port: int, timeout: float) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if not port_in_use(port):
            return True
        time.sleep(0.2)
    return not port_in_use(port)


def _ask_shutdown(port: int, secret: str) -> bool:
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/api/admin/shutdown", body=b"{}",
                  headers={"Host": "127.0.0.1:{}".format(port), "X-MCC": "1", "X-MCC-Secret": secret,
                           "Content-Type": "application/json"})
        ok = c.getresponse().status == 200
        c.close()
        return ok
    except (OSError, http.client.HTTPException):
        return False


def _terminate(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)  # on Windows this is TerminateProcess
    except OSError:
        pass


def stop_existing(port: int, log=print) -> bool:
    """Stop an MCC on this port. True when the port is free afterwards (or was already)."""
    if not port_in_use(port):
        return True
    info = {}
    try:
        info = json.loads(run_file(port).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    if info.get("secret") and _ask_shutdown(port, info["secret"]):
        log("  stopping the running MCC (pid {})...".format(info.get("pid", "?")))
        if _wait_free(port, 10):
            time.sleep(0.5)  # let it release its UDP collectors too
            return True
    if not is_mcc(port):
        log("  ! port {} is used by something that isn't MCC; not touching it. Use --port.".format(port))
        return False
    pid = listener_pid(port)
    if pid is None or pid == os.getpid():
        log("  ! couldn't find the process holding port {}. Stop it from its own window (Ctrl+C).".format(port))
        return False
    log("  stopping the running MCC (pid {})...".format(pid))
    _terminate(pid)
    if _wait_free(port, 10):
        time.sleep(0.5)
        return True
    log("  ! pid {} didn't stop. Close it from Task Manager, then start MCC again.".format(pid))
    return False
