"""Durable memory for the stability feature: the router log lines worth keeping after a restart,
and the router's last known boot time.

self.logs (hub.py) is in-memory only (deque(maxlen=3000)), so a line showing *why* the router
failed is gone the moment MCC itself restarts -- exactly the moment someone goes looking for it.
Warning, error and critical lines are appended here as they arrive and reloaded on startup, so the
existing Logs page's "Warnings+" filter keeps working across restarts without any UI change.

The last known boot time (now - uptime) is kept the same way, so hub.py can tell a genuine reboot
apart from the router simply having been unreachable, even right after MCC itself restarts, when
there is no previous uptime in memory to compare against.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

MAX_LINES = 5000
TRIM_CHECK_EVERY = 200


class StabilityLog:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.path = data_dir / "router_log.jsonl"
        self.state_path = data_dir / "stability_state.json"
        self.lock = threading.Lock()
        self._writes = 0
        self.last_boot: Optional[float] = None  # compared every poll; never written back by itself
        self._saved_boot: Optional[float] = None  # what's actually on disk right now
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("last_boot"), (int, float)):
                self.last_boot = self._saved_boot = float(data["last_boot"])
        except (OSError, ValueError, AttributeError):
            pass

    def tail(self, limit: int = 2000) -> List[Dict[str, Any]]:
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
        except OSError:
            return []
        out = []
        for line in lines:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict):
                out.append(entry)
        return out

    def append(self, entry: Dict[str, Any]) -> None:
        with self.lock:
            try:
                self.data_dir.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
                self._writes += 1
                if self._writes % TRIM_CHECK_EVERY == 0:
                    self._trim()
            except OSError:
                pass

    def _trim(self) -> None:
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
            if len(lines) > MAX_LINES:
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text("\n".join(lines[-MAX_LINES:]) + "\n", encoding="utf-8")
                tmp.replace(self.path)
        except OSError:
            pass

    def set_last_boot(self, boot: float) -> None:
        """Forces an immediate write, syncing both the comparison baseline and the saved value."""
        with self.lock:
            self.last_boot = self._saved_boot = boot
            try:
                self.data_dir.mkdir(parents=True, exist_ok=True)
                tmp = self.state_path.with_suffix(".tmp")
                tmp.write_text(json.dumps({"last_boot": boot}), encoding="utf-8")
                tmp.replace(self.state_path)
            except OSError:
                pass

    def update_boot(self, boot: float) -> bool:
        """Called every poll. The comparison baseline (`last_boot`) updates every call, so ordinary
        clock drift between MCC's (NTP-disciplined) clock and the router's own uptime counter is
        compared against the previous POLL -- seconds away -- never against a saved value that
        could be days old, where even a few tens of seconds of accumulated drift would look like a
        reboot. The saved value only has to track `last_boot` loosely, so it's only written once it
        has drifted more than 5s from what's on disk -- not on every poll -- which also keeps it
        fresh enough that reloading it after an MCC restart doesn't reintroduce that same risk.
        Returns True for a reboot-sized jump (> 30s) since the previous poll."""
        with self.lock:
            prev = self.last_boot
            self.last_boot = boot
            stale = self._saved_boot is None or abs(boot - self._saved_boot) > 5
        if stale:
            self.set_last_boot(boot)
        return prev is not None and abs(boot - prev) > 30
