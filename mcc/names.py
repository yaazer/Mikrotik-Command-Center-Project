"""Remembered names for addresses, so a restart (or the router's DNS cache expiring an entry) doesn't turn
every device back into a bare IP.

Names come from the router: DHCP lease / ARP comments and host names for LAN devices, and its DNS cache for
Internet hosts. The live tables always win; this memory only fills the gaps. Kept in data/names.json:
device names for 30 days, DNS names for 6 hours (an address behind a CDN can change hands).
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

KEEP_S = {"device": 30 * 86400, "dns": 6 * 3600}
SAVE_EVERY_S = 60.0
MAX_DNS = 20000


class NameMemory:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.path = data_dir / "names.json"
        self.lock = threading.Lock()
        self.tables: Dict[str, Dict[str, Tuple[str, float]]] = {"device": {}, "dns": {}}
        self._dirty = False
        self._saved_at = 0.0
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            now = time.time()
            for kind in self.tables:
                for ip, v in (data.get(kind) or {}).items():
                    if isinstance(v, list) and len(v) == 2 and now - float(v[1]) < KEEP_S[kind]:
                        self.tables[kind][ip] = (str(v[0]), float(v[1]))
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def remember(self, kind: str, names: Dict[str, str], now: Optional[float] = None) -> None:
        now = now or time.time()
        with self.lock:
            t = self.tables[kind]
            for ip, name in names.items():
                if name:
                    t[ip] = (name, now)
            for ip in [ip for ip, (_, ts) in t.items() if now - ts >= KEEP_S[kind]]:
                del t[ip]
            if kind == "dns" and len(t) > MAX_DNS:  # a busy network's cache: keep the most recent
                for ip, _ in sorted(t.items(), key=lambda kv: kv[1][1])[:len(t) - MAX_DNS]:
                    del t[ip]
            self._dirty = True
        if now - self._saved_at >= SAVE_EVERY_S:
            self.save()

    def get(self, ip: str) -> str:
        with self.lock:
            v = self.tables["device"].get(ip) or self.tables["dns"].get(ip)
        return v[0] if v else ""

    def save(self) -> None:
        with self.lock:
            if not self._dirty:
                return
            data = {kind: {ip: [n, round(ts)] for ip, (n, ts) in t.items()} for kind, t in self.tables.items()}
            self._dirty = False
            self._saved_at = time.time()
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass
