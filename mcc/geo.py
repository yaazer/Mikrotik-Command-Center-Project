"""IP geolocation from a local MaxMind-format (.mmdb) database -- stdlib only.

Works with any .mmdb: DB-IP Lite (free, CC BY 4.0, no account -- Setup can download it),
MaxMind GeoLite2, or IPinfo's free databases. Lookups never leave this machine.
City databases give a city's coordinates; country-only databases are placed at the country's
label point (mcc/geodata.py), so they are an approximation of WHERE, never an address.
"""

from __future__ import annotations

import datetime
import gzip
import ipaddress
import os
import shutil
import struct
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .geodata import CENTROIDS
from .util import ip_obj, is_local_scope

META_MARKER = b"\xab\xcd\xefMaxMind.com"
DBIP_URL = "https://download.db-ip.com/free/dbip-{edition}-lite-{month}.mmdb.gz"
EDITIONS = {
    "country": {"label": "DB-IP Country Lite", "size": "≈4 MB download", "precision": "country"},
    "city": {"label": "DB-IP City Lite", "size": "≈60 MB download, ≈130 MB on disk", "precision": "city"},
}


class MMDBError(Exception):
    pass


class MMDB:
    """Reader for the MaxMind DB format (https://maxmind.github.io/MaxMind-DB/)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.buf = self.path.read_bytes()
        at = self.buf.rfind(META_MARKER, max(0, len(self.buf) - 128 * 1024))
        if at < 0:
            raise MMDBError("not a MaxMind DB file (no metadata marker)")
        self.meta, _ = self._decode(at + len(META_MARKER), at + len(META_MARKER))
        try:
            self.node_count = int(self.meta["node_count"])
            self.record_size = int(self.meta["record_size"])
            self.ip_version = int(self.meta["ip_version"])
        except (KeyError, TypeError, ValueError):
            raise MMDBError("metadata is missing node_count / record_size / ip_version")
        if self.record_size not in (24, 28, 32):
            raise MMDBError("unsupported record size {}".format(self.record_size))
        self.node_bytes = self.record_size * 2 // 8
        self.tree_size = self.node_count * self.node_bytes
        self.data_start = self.tree_size + 16
        self._v4_start = None

    # -- search tree ---------------------------------------------------------------------------
    def _read_node(self, node: int, bit: int) -> int:
        off = node * self.node_bytes
        b = self.buf
        if self.record_size == 24:
            o = off + bit * 3
            return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]
        if self.record_size == 28:
            if bit == 0:
                return ((b[off + 3] & 0xF0) << 20) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]
            return ((b[off + 3] & 0x0F) << 24) | (b[off + 4] << 16) | (b[off + 5] << 8) | b[off + 6]
        o = off + bit * 4
        return struct.unpack(">I", b[o:o + 4])[0]

    def _ipv4_start(self) -> int:
        if self._v4_start is None:
            node = 0
            if self.ip_version == 6:
                for _ in range(96):
                    if node >= self.node_count:
                        break
                    node = self._read_node(node, 0)
            self._v4_start = node
        return self._v4_start

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        o = ipaddress.ip_address(ip)
        if o.version == 6 and self.ip_version == 4:
            return None
        packed = o.packed
        node = self._ipv4_start() if o.version == 4 else 0
        bits = len(packed) * 8
        for i in range(bits):
            if node >= self.node_count:
                break
            bit = (packed[i >> 3] >> (7 - (i & 7))) & 1
            node = self._read_node(node, bit)
        if node == self.node_count:
            return None
        if node < self.node_count:
            raise MMDBError("invalid search tree")
        offset = self.data_start + (node - self.node_count - 16)
        value, _ = self._decode(offset, self.data_start)
        return value if isinstance(value, dict) else None

    # -- data section ----------------------------------------------------------------------------
    def _decode(self, off: int, base: int) -> Tuple[Any, int]:
        b = self.buf
        ctrl = b[off]
        off += 1
        typ = ctrl >> 5
        if typ == 1:  # pointer
            ss = (ctrl >> 3) & 0x3
            vvv = ctrl & 0x7
            if ss == 0:
                ptr = (vvv << 8) | b[off]
                off += 1
            elif ss == 1:
                ptr = ((vvv << 16) | (b[off] << 8) | b[off + 1]) + 2048
                off += 2
            elif ss == 2:
                ptr = ((vvv << 24) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]) + 526336
                off += 3
            else:
                ptr = struct.unpack(">I", b[off:off + 4])[0]
                off += 4
            value, _ = self._decode(base + ptr, base)
            return value, off
        if typ == 0:
            typ = 7 + b[off]
            off += 1
        size = ctrl & 0x1F
        if size == 29:
            size = 29 + b[off]
            off += 1
        elif size == 30:
            size = 285 + ((b[off] << 8) | b[off + 1])
            off += 2
        elif size == 31:
            size = 65821 + ((b[off] << 16) | (b[off + 1] << 8) | b[off + 2])
            off += 3
        if typ == 2:
            return b[off:off + size].decode("utf-8", "replace"), off + size
        if typ == 3:
            return struct.unpack(">d", b[off:off + 8])[0], off + 8
        if typ == 4:
            return bytes(b[off:off + size]), off + size
        if typ in (5, 6, 9, 10):
            return int.from_bytes(b[off:off + size], "big"), off + size
        if typ == 8:
            return int.from_bytes(b[off:off + size], "big", signed=size == 4), off + size
        if typ == 15:
            return struct.unpack(">f", b[off:off + 4])[0], off + 4
        if typ == 14:
            return bool(size), off
        if typ == 7:
            out: Dict[str, Any] = {}
            for _ in range(size):
                k, off = self._decode(off, base)
                v, off = self._decode(off, base)
                out[str(k)] = v
            return out, off
        if typ == 11:
            arr = []
            for _ in range(size):
                v, off = self._decode(off, base)
                arr.append(v)
            return arr, off
        if typ in (12, 13):
            return None, off
        raise MMDBError("unknown data type {} at {}".format(typ, off))


def _name(node: Any) -> str:
    if isinstance(node, dict):
        names = node.get("names")
        if isinstance(names, dict):
            return names.get("en") or next(iter(names.values()), "")
        if isinstance(node.get("name"), str):
            return node["name"]
    return node if isinstance(node, str) else ""


def normalise(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """MaxMind / DB-IP / IPinfo records -> {lat, lon, cc, country, city, precision}."""
    country = rec.get("country") if isinstance(rec.get("country"), dict) else {}
    cc = (country.get("iso_code") or rec.get("country_code") or "") if country else (rec.get("country_code") or "")
    if not cc and isinstance(rec.get("country"), str) and len(rec["country"]) == 2:
        cc = rec["country"]
    cc = str(cc).upper()
    cname = _name(country) if country else (rec.get("country") if isinstance(rec.get("country"), str) and len(rec["country"]) > 2 else "")
    loc = rec.get("location") if isinstance(rec.get("location"), dict) else {}
    lat = loc.get("latitude", rec.get("latitude", rec.get("lat")))
    lon = loc.get("longitude", rec.get("longitude", rec.get("lng", rec.get("lon"))))
    city = _name(rec.get("city"))
    sub = rec.get("subdivisions")
    region = _name(sub[0]) if isinstance(sub, list) and sub else _name(rec.get("region"))
    precision = "city"
    if lat is None or lon is None:
        c = CENTROIDS.get(cc)
        if not c:
            return None
        lat, lon, default_name = c
        cname = cname or default_name
        precision = "country"
        city = ""
    if not cname and cc in CENTROIDS:
        cname = CENTROIDS[cc][2]
    try:
        return {"lat": round(float(lat), 3), "lon": round(float(lon), 3), "cc": cc, "country": cname or cc,
                "city": city, "region": region, "precision": precision}
    except (TypeError, ValueError):
        return None


class Geo:
    CACHE = 20000

    def __init__(self, cfg: Any, data_dir: Path, demo: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None):
        self.cfg = cfg
        self.data_dir = Path(data_dir)
        self.demo = demo
        self.db: Optional[MMDB] = None
        self.db_error = ""
        self.lock = threading.Lock()
        self.cache: "OrderedDict[str, Optional[Dict[str, Any]]]" = OrderedDict()
        self.download: Dict[str, Any] = {"state": "idle"}
        self.load()

    # -- database ------------------------------------------------------------------------------
    def candidates(self) -> List[Path]:
        configured = (self.cfg.get("geo.db") or "").strip()
        if configured:
            return [self.cfg.resolve(configured)]
        d = self.data_dir / "geo"
        found = sorted(d.glob("*.mmdb"), key=lambda p: ("city" not in p.name.lower(), -p.stat().st_mtime)) \
            if d.exists() else []
        return found

    def load(self) -> None:
        self.db, self.db_error = None, ""
        for p in self.candidates():
            try:
                self.db = MMDB(p)
                break
            except (OSError, MMDBError) as e:
                self.db_error = "{}: {}".format(p.name, e)
        with self.lock:
            self.cache.clear()

    def info(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"download": dict(self.download), "error": self.db_error,
                               "source": "database" if self.db else "demo" if self.demo else "none"}
        if self.db:
            m = self.db.meta
            build = m.get("build_epoch")
            desc = m.get("description") or {}
            out.update({"path": str(self.db.path), "file": self.db.path.name, "type": m.get("database_type", ""),
                        "description": desc.get("en", "") if isinstance(desc, dict) else str(desc),
                        "built": datetime.datetime.utcfromtimestamp(build).strftime("%Y-%m-%d") if build else "",
                        "ip_version": self.db.ip_version,
                        "dbip": "dbip" in self.db.path.name.lower() or "db-ip" in str(m.get("database_type", "")).lower()})
        return out

    # -- lookups ---------------------------------------------------------------------------------
    def locate(self, ip: str) -> Optional[Dict[str, Any]]:
        o = ip_obj(ip)
        if o is None or is_local_scope(o) or o.is_multicast or o.is_reserved:
            return None
        with self.lock:
            if ip in self.cache:
                self.cache.move_to_end(ip)
                return self.cache[ip]
        res = None
        if self.db is not None:
            try:
                rec = self.db.lookup(ip)
                res = normalise(rec) if rec else None
            except (MMDBError, IndexError, struct.error, ValueError):
                res = None
        if res is None and self.demo is not None:
            res = self.demo(ip)
        with self.lock:
            self.cache[ip] = res
            if len(self.cache) > self.CACHE:
                self.cache.popitem(last=False)
        return res

    def home(self, public_ips: List[str]) -> Optional[Dict[str, Any]]:
        h = self.cfg.get("geo.home") or {}
        if h.get("lat") not in (None, "") and h.get("lon") not in (None, ""):
            try:
                return {"lat": float(h["lat"]), "lon": float(h["lon"]), "label": h.get("label") or "Home",
                        "source": "settings"}
            except (TypeError, ValueError):
                pass
        for ip in public_ips:
            g = self.locate(ip)
            if g:
                return dict(g, label=g.get("city") or g.get("country") or "Home", source="router's public address")
        return None

    # -- download (only when you click it) -------------------------------------------------------
    def start_download(self, edition: str, on_done: Optional[Callable[[], None]] = None) -> Dict[str, Any]:
        if edition not in EDITIONS:
            raise ValueError("edition must be 'country' or 'city'")
        if self.download.get("state") == "running":
            raise ValueError("a download is already running")
        self.download = {"state": "running", "edition": edition, "bytes": 0, "total": 0, "started": time.time(),
                         "url": "", "error": ""}
        threading.Thread(target=self._download, args=(edition, on_done), name="mcc-geo-dl", daemon=True).start()
        return dict(self.download)

    def _download(self, edition: str, on_done: Optional[Callable[[], None]]) -> None:
        dest_dir = self.data_dir / "geo"
        dest_dir.mkdir(parents=True, exist_ok=True)
        today = datetime.date.today()
        months = [today.strftime("%Y-%m"), (today.replace(day=1) - datetime.timedelta(days=1)).strftime("%Y-%m")]
        gz = dest_dir / "download.mmdb.gz.part"
        last_err = ""
        for month in months:
            url = DBIP_URL.format(edition=edition, month=month)
            self.download["url"] = url
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "MikrotikCommandCenter/0.1"})
                with urllib.request.urlopen(req, timeout=30) as r, open(gz, "wb") as f:
                    self.download["total"] = int(r.headers.get("Content-Length") or 0)
                    while True:
                        chunk = r.read(1 << 16)
                        if not chunk:
                            break
                        f.write(chunk)
                        self.download["bytes"] += len(chunk)
                break
            except urllib.error.HTTPError as e:
                last_err = "{} for {}".format(e.code, url)
                self.download["bytes"] = 0
                continue
            except (urllib.error.URLError, OSError) as e:
                last_err = str(getattr(e, "reason", e))
                break
        else:
            self.download.update({"state": "error", "error": last_err})
            return
        if not gz.exists() or self.download["bytes"] == 0:
            self.download.update({"state": "error", "error": last_err or "nothing downloaded"})
            return
        final = dest_dir / "dbip-{}-lite.mmdb".format(edition)
        tmp = dest_dir / (final.name + ".part")
        try:
            self.download["state"] = "unpacking"
            with gzip.open(gz, "rb") as src, open(tmp, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            MMDB(tmp)  # refuse to install something unreadable
            os.replace(tmp, final)
        except (OSError, EOFError, MMDBError) as e:
            self.download.update({"state": "error", "error": "unpacking failed: {}".format(e)})
            return
        finally:
            for p in (gz, tmp):
                try:
                    p.unlink()
                except OSError:
                    pass
        self.cfg.update({"geo": {"db": ""}})  # auto-pick the newest database in data/geo
        self.load()
        self.download.update({"state": "done", "file": final.name, "finished": time.time()})
        if on_done:
            on_done()
