"""Settings. Saved to data/config.json -- never with a password in it; credentials live in memory only."""

from __future__ import annotations

import copy
import json
import threading
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"

DEFAULTS: Dict[str, Any] = {
    "router": {"host": "", "scheme": "https", "port": 0, "user": "", "verify_tls": False, "pinned_sha256": ""},
    # kind: auto (detect) | swos | routeros -- CRS switches can boot either OS
    "switch": {"host": "", "scheme": "http", "user": "admin", "kind": "auto", "fields": {}},
    "ui": {"bind": "127.0.0.1", "port": 8840},
    "collectors": {
        "bind": "0.0.0.0",
        "flow_port": 2055,
        "syslog_port": 5514,
        # The address the router should send flows/syslog to. Blank = the address this machine
        # uses to reach the router.
        "advertise_ip": "",
        # Extra senders accepted besides the router itself (a router can source packets from
        # any of its addresses).
        "accept_from": [],
    },
    "lan_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"],
    # Addresses MCC will refuse to block or quarantine, whatever a threat says.
    "never_block": [],
    "wan": {"interfaces": [], "down_mbps": 0, "up_mbps": 0},
    "poll": {"router_s": 2, "conns_s": 4, "devices_s": 15, "log_s": 3, "dns_s": 30, "switch_s": 5},
    "detect": {
        "scan_ports": 15,
        "scan_hosts": 10,
        "scan_window_s": 60,
        "login_failures": 5,
        "login_window_s": 300,
        "service_conns": 20,
        "service_window_s": 60,
        "auth_ports": [21, 22, 23, 445, 3389, 5900, 8291, 8728, 8729],
        "flood_pps": 5000,
        "flood_logs_per_min": 300,
        "fanout_peers": 150,
        "fanout_window_s": 60,
        "worm_ports": [23, 25, 445, 2323, 3389],
        "worm_dsts": 30,
        "watch_ports": [23, 1337, 2323, 4444, 5555, 6667, 6697, 9001, 31337],
        # firewall rules you log with one of these prefixes are VPN kill switches: a hit is a VPN leak
        "leak_prefixes": ["VPN-LEAK"],
        "exfil_mbps": 50,
        "exfil_s": 120,
        "exfil_factor": 4,
        "cpu_pct": 90,
        "cpu_s": 30,
        "temp_c": 75,
        "quiet_s": 600,
    },
    "actions": {"default_block": "1h"},
    "blocklist_file": "data/blocklist.txt",
    # IP geolocation: a local .mmdb (blank = newest in data/geo). Home blank = locate the router's public IP.
    "geo": {"db": "", "home": {"lat": "", "lon": "", "label": ""}},
}

_SECRET = {"password", "secret", "token"}


def _merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def strip_secrets(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: strip_secrets(v) for k, v in obj.items() if k.lower() not in _SECRET}
    if isinstance(obj, list):
        return [strip_secrets(v) for v in obj]
    return obj


class Config:
    def __init__(self, data_dir: Path = DATA_DIR, persist: bool = True):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "config.json"
        self.persist = persist
        self._lock = threading.RLock()
        self.data: Dict[str, Any] = copy.deepcopy(DEFAULTS)
        if persist and self.path.exists():
            try:
                self.data = _merge(DEFAULTS, json.loads(self.path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass

    def get(self, dotted: str, default: Any = None) -> Any:
        with self._lock:
            node: Any = self.data
            for part in dotted.split("."):
                if not isinstance(node, dict) or part not in node:
                    return default
                node = node[part]
            return copy.deepcopy(node)

    def update(self, patch: Dict[str, Any]) -> None:
        with self._lock:
            self.data = _merge(self.data, strip_secrets(patch))
            self.save()

    def save(self) -> None:
        if not self.persist:
            return
        with self._lock:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(strip_secrets(self.data), indent=2), encoding="utf-8")
            tmp.replace(self.path)

    def public(self) -> Dict[str, Any]:
        with self._lock:
            return strip_secrets(copy.deepcopy(self.data))

    def resolve(self, rel: str) -> Path:
        """'data/x' means x in the data directory, wherever that is (--data /var/lib/mcc on a server);
        other relative paths are relative to the program folder."""
        p = Path(rel)
        if p.is_absolute():
            return p
        if p.parts and p.parts[0] == "data":
            return self.data_dir.joinpath(*p.parts[1:])
        return ROOT / p
