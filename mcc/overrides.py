"""What you say a device is: overrides for MCC's guess (mcc/identify.py), kept by MAC in data/identity_overrides.json.

A guess from names and traffic can be wrong (a "Pixel-9-Pro-Fold" that is really a tablet, a Linux box MCC calls a
phone). An override wins over every clue, follows the device when DHCP hands it a new address, and stays until you
reset it. The original guess stays visible next to it.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .identify import KIND_LABEL

MAX_OVERRIDES = 500


class Overrides:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "identity_overrides.json"
        self.lock = threading.Lock()
        self.items: Dict[str, Dict[str, Any]] = {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.items = {str(m).upper(): v for m, v in (data.get("overrides") or {}).items()
                          if isinstance(v, dict) and v.get("kind") in KIND_LABEL}
        except (OSError, ValueError, AttributeError):
            pass

    def get(self, mac: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            v = self.items.get((mac or "").upper())
            return dict(v) if v else None

    def set(self, mac: str, kind: str, label: str = "", brand: str = "", os: str = "", model: str = "") -> Dict[str, Any]:
        if kind not in KIND_LABEL:
            raise ValueError("unknown device kind: {!r}".format(kind))
        rec = {"kind": kind, "label": label.strip()[:60], "brand": brand.strip()[:40], "os": os.strip()[:40],
               "model": model.strip()[:60], "at": round(time.time())}
        with self.lock:
            if mac.upper() not in self.items and len(self.items) >= MAX_OVERRIDES:
                raise ValueError("at most {} overrides".format(MAX_OVERRIDES))
            self.items[mac.upper()] = rec
            self._save()
        return dict(rec)

    def clear(self, mac: str) -> bool:
        with self.lock:
            if self.items.pop(mac.upper(), None) is None:
                return False
            self._save()
            return True

    def _save(self) -> None:
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"overrides": self.items}, indent=1), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass
