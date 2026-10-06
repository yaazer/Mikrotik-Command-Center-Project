"""Pinned devices: always on the traffic map and at the top of the lists, busy or not.

Kept in data/pins.json. A LAN device is remembered by its MAC as well as its address, so a pin
follows it when DHCP hands it a new one.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

MAX_PINS = 50


class Pins:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.path = data_dir / "pins.json"
        self.lock = threading.Lock()
        self.items: List[Dict[str, Any]] = []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.items = [x for x in data.get("pins", []) if isinstance(x, dict) and _valid_ip(x.get("ip"))]
        except (OSError, ValueError, AttributeError):
            pass

    def _save(self) -> None:
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"pins": self.items}, indent=1), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass

    def resolve(self, mac_ip: Callable[[str], Optional[str]]) -> Dict[str, Dict[str, Any]]:
        """Current address -> pin. mac_ip(mac) gives a LAN device's address now (None if unseen)."""
        with self.lock:
            items = [dict(x) for x in self.items]
        out: Dict[str, Dict[str, Any]] = {}
        for x in items:
            ip = (mac_ip(x["mac"]) if x.get("mac") else None) or x["ip"]
            out[ip] = dict(x, ip=ip)
        return out

    def set(self, ip: str, pinned: bool, mac: str = "", name: str = "", lan: bool = False) -> bool:
        """Pin or unpin an address. Returns whether anything changed."""
        if not _valid_ip(ip):
            raise ValueError("not an IP address: {!r}".format(ip))
        mac = mac.upper()
        with self.lock:
            hit = [x for x in self.items if x["ip"] == ip or (mac and x.get("mac") == mac)]
            if pinned:
                if hit:
                    for x in hit:  # refresh what we know (a new address for the same MAC)
                        x.update(ip=ip, mac=mac or x.get("mac", ""), name=name or x.get("name", ""))
                    self._save()
                    return False
                if len(self.items) >= MAX_PINS:
                    raise ValueError("at most {} pinned devices".format(MAX_PINS))
                self.items.append({"ip": ip, "mac": mac, "name": name, "lan": lan, "added": time.time()})
            else:
                if not hit:
                    return False
                self.items = [x for x in self.items if x not in hit]
            self._save()
            return True


def _valid_ip(ip: Any) -> bool:
    try:
        ipaddress.ip_address(str(ip))
        return True
    except ValueError:
        return False
