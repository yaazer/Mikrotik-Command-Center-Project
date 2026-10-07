"""MAC address vendors from the IEEE registry -- stdlib only, lookups never leave this machine.

The first half of a MAC (its OUI) is assigned to a manufacturer by the IEEE. Three registries:
  MA-L  24-bit prefixes  (most vendors: 3C:22:FB = Apple)
  MA-M  28-bit prefixes  (blocks carved out of an MA-L the IEEE keeps for smaller vendors)
  MA-S  36-bit prefixes  (smaller still)
A lookup tries the longest prefix first.

MCC ships a snapshot (mcc/oui.tsv.gz, built by tools/build_oui.py), so identification works offline from the
first run. Setup can refresh it from standards-oui.ieee.org; the refreshed copy goes to data/oui/ and wins.

A MAC with the "locally administered" bit set (the second-lowest bit of the first byte: x2, x6, xA, xE) was
never assigned to anyone: phones, tablets and laptops make one up per Wi-Fi network for privacy, and VMs and
containers use them too. Those have no vendor by design.
"""

from __future__ import annotations

import csv
import datetime
import gzip
import io
import os
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

BUNDLED = Path(__file__).resolve().parent / "oui.tsv.gz"
IEEE = [  # (registry, prefix length in hex digits, url)
    ("MA-L", 6, "https://standards-oui.ieee.org/oui/oui.csv"),
    ("MA-M", 7, "https://standards-oui.ieee.org/oui28/mam.csv"),
    ("MA-S", 9, "https://standards-oui.ieee.org/oui36/oui36.csv"),
]
REGISTRY = {6: "MA-L", 7: "MA-M", 9: "MA-S"}
HEADER = "#mcc-oui 1"

_HEX = re.compile(r"[0-9A-F]")
# legal-form words trimmed from the end of a registered name: "Apple, Inc." -> "Apple"
_SUFFIX = re.compile(
    r"[\s,.]*\b(co|corp|corporation|corporate|company|inc|incorporated|ltd|limited|llc|l\.l\.c|gmbh|ag|sa|sas|"
    r"s\.a|s\.p\.a|spa|srl|s\.r\.l|bv|b\.v|nv|n\.v|oy|ab|as|a/s|kg|plc|pty|pte|kk|k\.k|s\.l|sl|sro|s\.r\.o|zrt|ltda|"
    r"lda|co\.,?\s?ltd)\b\.?\s*$", re.I)


def normalise_mac(text: Any) -> str:
    """'3c-22-fb-00-00-21', '3c22.fb00.0021' ... -> '3C22FB000021' (just the hex digits, upper case)."""
    return "".join(_HEX.findall(str(text or "").upper()))


def is_random(mac: str) -> bool:
    """Locally administered: made up by the device (privacy addresses, VMs), not assigned by the IEEE."""
    h = normalise_mac(mac)
    return len(h) >= 2 and bool(int(h[:2], 16) & 0x02)


def is_multicast(mac: str) -> bool:
    h = normalise_mac(mac)
    return len(h) >= 2 and bool(int(h[:2], 16) & 0x01)


def short_name(name: str) -> str:
    """'HUAWEI TECHNOLOGIES CO.,LTD' -> 'Huawei Technologies'. Brand names are tidied further in identify.py."""
    s = re.sub(r"\s+", " ", (name or "").strip().strip('"')).strip()
    s = re.sub(r"\s*\([^)]*\)", "", s).strip() or s
    for _ in range(4):
        t = _SUFFIX.sub("", s).strip(" ,.-&")
        if t == s or not t:
            break
        s = t
    if s.isupper() and len(s) > 4:  # SHOUTING -> Title Case, keeping short acronyms
        s = " ".join(w if len(w) <= 3 else w.capitalize() for w in s.split())
    return s or name.strip()


def parse_ieee_csv(text: str, digits: int) -> List[Tuple[str, str]]:
    """IEEE registry CSV -> [(hex prefix, vendor)]. Blocks the IEEE subdivided (MA-M / MA-S) are left out of
    MA-L; their pieces come from the other registries."""
    out = []
    for row in csv.DictReader(io.StringIO(text)):
        prefix = normalise_mac(row.get("Assignment"))
        name = (row.get("Organization Name") or "").strip()
        if len(prefix) != digits or not name or name == "IEEE Registration Authority":
            continue
        out.append((prefix, short_name(name)))
    return out


def build(fetch: Callable[[str], bytes], today: Optional[str] = None) -> Tuple[bytes, int]:
    """Download the three IEEE registries with fetch(url) and return (our .tsv.gz file, entries)."""
    entries: Dict[str, str] = {}
    for _reg, digits, url in IEEE:
        for prefix, name in parse_ieee_csv(fetch(url).decode("utf-8", "replace"), digits):
            entries[prefix] = name
    if len(entries) < 10000:
        raise ValueError("the IEEE registry looks incomplete ({} entries)".format(len(entries)))
    head = "{} built={} source=IEEE entries={}".format(HEADER, today or datetime.date.today().isoformat(), len(entries))
    body = "\n".join([head] + ["{}\t{}".format(p, n) for p, n in sorted(entries.items())]) + "\n"
    return gzip.compress(body.encode("utf-8"), 9), len(entries)


def _fetch(url: str, progress: Optional[Callable[[int], None]] = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "MikrotikCommandCenter/0.1"})
    buf = io.BytesIO()
    with urllib.request.urlopen(req, timeout=60) as r:
        while True:
            chunk = r.read(1 << 16)
            if not chunk:
                break
            buf.write(chunk)
            if progress:
                progress(len(chunk))
    return buf.getvalue()


class MacVendors:
    def __init__(self, data_dir: Path, bundled: Path = BUNDLED):
        self.data_dir = Path(data_dir)
        self.bundled = Path(bundled)
        self.lock = threading.Lock()
        self.tables: Dict[int, Dict[str, str]] = {9: {}, 7: {}, 6: {}}
        self.meta: Dict[str, str] = {}
        self.path: Optional[Path] = None
        self.error = ""
        self.download: Dict[str, Any] = {"state": "idle"}
        self.load()

    @property
    def downloaded(self) -> Path:
        return self.data_dir / "oui" / "oui.tsv.gz"

    def load(self) -> None:
        self.error = ""
        for p in (self.downloaded, self.bundled):
            if not p.exists():
                continue
            try:
                tables, meta = self._read(p)
            except (OSError, EOFError, ValueError) as e:
                self.error = "{}: {}".format(p.name, e)
                continue
            with self.lock:
                self.tables, self.meta, self.path = tables, meta, p
            return
        with self.lock:
            self.tables, self.meta, self.path = {9: {}, 7: {}, 6: {}}, {}, None
        self.error = self.error or "no MAC vendor database (mcc/oui.tsv.gz is missing)"

    @staticmethod
    def _read(path: Path) -> Tuple[Dict[int, Dict[str, str]], Dict[str, str]]:
        text = gzip.decompress(path.read_bytes()).decode("utf-8")
        lines = text.split("\n")
        if not lines or not lines[0].startswith(HEADER):
            raise ValueError("not an MCC MAC vendor file")
        meta = dict(kv.split("=", 1) for kv in lines[0].split()[2:] if "=" in kv)
        tables: Dict[int, Dict[str, str]] = {9: {}, 7: {}, 6: {}}
        names: Dict[str, str] = {}  # one string object per vendor name
        for line in lines[1:]:
            prefix, _, name = line.partition("\t")
            t = tables.get(len(prefix))
            if t is not None and name:
                t[prefix] = names.setdefault(name, name)
        if sum(len(t) for t in tables.values()) < 1000:
            raise ValueError("too few entries")
        return tables, meta

    def lookup(self, mac: str) -> Dict[str, Any]:
        """-> {"vendor", "prefix", "registry"} or {"random": True} or {} (unregistered / not a MAC)."""
        h = normalise_mac(mac)
        if len(h) != 12:
            return {}
        if is_random(h):
            return {"random": True}
        with self.lock:
            tables = self.tables
        for digits in (9, 7, 6):
            name = tables[digits].get(h[:digits])
            if name:  # 3C:22:FB, or 70:B3:D5:00:1/36 for the smaller blocks
                prefix = ":".join(h[i:min(i + 2, digits)] for i in range(0, digits, 2))
                return {"vendor": name, "prefix": prefix + ("/{}".format(digits * 4) if digits > 6 else ""),
                        "registry": REGISTRY[digits]}
        return {}

    def info(self) -> Dict[str, Any]:
        with self.lock:
            n = sum(len(t) for t in self.tables.values())
            meta, path = dict(self.meta), self.path
        return {"entries": n, "built": meta.get("built", ""), "source": meta.get("source", ""),
                "origin": "" if path is None else "downloaded" if path == self.downloaded else "bundled",
                "error": self.error, "download": dict(self.download)}

    # -- refresh from the IEEE (only when you click it) ------------------------------------------
    def start_download(self, on_done: Optional[Callable[[], None]] = None) -> Dict[str, Any]:
        if self.download.get("state") == "running":
            raise ValueError("a download is already running")
        self.download = {"state": "running", "bytes": 0, "started": time.time(), "url": "", "error": ""}
        threading.Thread(target=self._download, args=(on_done,), name="mcc-oui-dl", daemon=True).start()
        return dict(self.download)

    def _download(self, on_done: Optional[Callable[[], None]]) -> None:
        def fetch(url: str) -> bytes:
            self.download["url"] = url
            return _fetch(url, lambda n: self.download.__setitem__("bytes", self.download["bytes"] + n))

        dest = self.downloaded
        tmp = dest.with_suffix(".part")
        try:
            blob, n = build(fetch)
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_bytes(blob)
            self._read(tmp)  # refuse to install something unreadable
            os.replace(tmp, dest)
        except urllib.error.HTTPError as e:
            self.download.update({"state": "error", "error": "{} for {}".format(e.code, self.download.get("url"))})
            return
        except (urllib.error.URLError, OSError, ValueError, EOFError) as e:
            self.download.update({"state": "error", "error": str(getattr(e, "reason", e))})
            return
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass
        self.load()
        self.download.update({"state": "done", "entries": n, "finished": time.time()})
        if on_done:
            on_done()
