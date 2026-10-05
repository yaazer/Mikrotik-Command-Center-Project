"""Read-only SwOS reader.

SwOS has no API. Its web UI loads small JavaScript-object files (link.b, stats.b, sys.b) over HTTP
digest auth; MCC reads the same files. They are undocumented and the field names differ a little
between SwOS releases, so the mapping below is a list of candidates, overridable through
config switch.fields, and Setup shows the raw files ("Switch probe") when a column reads blank.
Nothing is ever written to the switch.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


class SwOSError(Exception):
    pass


_TOKEN = re.compile(r"\s*(?:(0x[0-9a-fA-F]+)|(-?\d+(?:\.\d+)?)|'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"|([A-Za-z_][\w]*)|([{}\[\]:,]))")


def parse_js(text: str) -> Any:
    """Parse SwOS's JS literals: {en:0x3ff,nm:['506f727431'],spd:[0x03,0x02]}."""
    tokens: List[Any] = []
    pos = 0
    text = text.strip().rstrip(";")
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            if text[pos:].strip() == "":
                break
            raise SwOSError("cannot parse switch data near {!r}".format(text[pos:pos + 20]))
        pos = m.end()
        hx, num, sq, dq, ident, punct = m.groups()
        if hx is not None:
            tokens.append(("v", int(hx, 16)))
        elif num is not None:
            tokens.append(("v", float(num) if "." in num else int(num)))
        elif sq is not None or dq is not None:
            tokens.append(("v", sq if sq is not None else dq))
        elif ident is not None:
            tokens.append(("id", ident))
        else:
            tokens.append(("p", punct))
    idx = 0

    def value() -> Any:
        nonlocal idx
        kind, tok = tokens[idx]
        idx += 1
        if kind == "p" and tok == "{":
            obj: Dict[str, Any] = {}
            while tokens[idx] != ("p", "}"):
                k_kind, key = tokens[idx]
                idx += 1
                if tokens[idx] != ("p", ":"):
                    raise SwOSError("expected ':' after {}".format(key))
                idx += 1
                obj[str(key)] = value()
                if tokens[idx] == ("p", ","):
                    idx += 1
            idx += 1
            return obj
        if kind == "p" and tok == "[":
            arr = []
            while tokens[idx] != ("p", "]"):
                arr.append(value())
                if tokens[idx] == ("p", ","):
                    idx += 1
            idx += 1
            return arr
        if kind == "id":
            return {"true": True, "false": False, "null": None}.get(tok, tok)
        return tok

    if not tokens:
        return None
    try:
        return value()
    except IndexError:
        raise SwOSError("switch data ended early")


def hexstr(value: Any) -> str:
    """SwOS stores names as hex-encoded bytes: '506f727431' -> 'Port1'."""
    if not isinstance(value, str):
        return "" if value is None else str(value)
    if len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]*", value):
        try:
            out = bytes.fromhex(value).decode("utf-8")
            if out.isprintable():
                return out
        except (ValueError, UnicodeDecodeError):
            pass
    return value


SPEEDS = {0: "10M", 1: "100M", 2: "1G", 3: "10G", 4: "2.5G", 5: "5G", 6: "25G", 7: "40G"}

# candidate keys, first present wins; config switch.fields can override any of these
FIELDS: Dict[str, List[str]] = {
    "enabled": ["en"],
    "link": ["lnk"],
    "names": ["nm"],
    "speed": ["spd"],
    "duplex": ["dpx"],
    "rx_rate": ["rrb"],
    "tx_rate": ["trb"],
    "rx_bytes": ["rb", "rxb"],
    "rx_bytes_hi": ["rbh"],
    "tx_bytes": ["tb", "txb"],
    "tx_bytes_hi": ["tbh"],
    "rx_errors": ["rfcs", "rxe"],
    "identity": ["id", "nm"],
    "model": ["brd", "bld"],
    "version": ["ver"],
    "uptime": ["upt"],
    "temp": ["temp", "tmp"],
}


class SwOS:
    def __init__(self, host: str, user: str = "admin", password: str = "", scheme: str = "http",
                 timeout: float = 6.0, fields: Optional[Dict[str, Any]] = None):
        self.host = host.strip()
        self.base = "{}://{}".format(scheme or "http", self.host)
        self.timeout = timeout
        self.fields = {k: list(v) for k, v in FIELDS.items()}
        for k, v in (fields or {}).items():
            self.fields[k] = [v] if isinstance(v, str) else list(v)
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, self.base + "/", user, password)
        self._opener = urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(mgr))

    def _get(self, name: str) -> Any:
        try:
            with self._opener.open(self.base + "/" + name, timeout=self.timeout) as r:
                return parse_js(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise SwOSError("the switch refused the user name or password")
            if e.code == 404:
                return None
            raise SwOSError("switch said {} for {}".format(e.code, name))
        except (urllib.error.URLError, OSError) as e:
            raise SwOSError("cannot reach the switch at {}: {}".format(self.host, getattr(e, "reason", e)))

    def _pick(self, data: Any, field: str) -> Any:
        if not isinstance(data, dict):
            return None
        for key in self.fields.get(field, []):
            if key in data:
                return data[key]
        return None

    def probe(self) -> Dict[str, Any]:
        out = {}
        for name in ("sys.b", "link.b", "stats.b"):
            try:
                out[name] = self._get(name)
            except SwOSError as e:
                out[name] = {"error": str(e)}
        return out

    def read(self) -> Dict[str, Any]:
        link = self._get("link.b") or {}
        try:
            stats = self._get("stats.b") or {}
        except SwOSError:
            stats = {}
        try:
            sysd = self._get("sys.b") or {}
        except SwOSError:
            sysd = {}
        names = self._pick(link, "names") or []
        speeds = self._pick(link, "speed") or []
        count = max(len(names), len(speeds), int(link.get("prt") or 0) if isinstance(link, dict) else 0)
        en = self._pick(link, "enabled")
        lnk = self._pick(link, "link")
        dpx = self._pick(link, "duplex")

        def bit(mask: Any, i: int) -> Optional[bool]:
            if isinstance(mask, int):
                return bool(mask >> i & 1)
            if isinstance(mask, list) and i < len(mask):
                return bool(mask[i])
            return None

        def arr(field: str, i: int) -> Optional[float]:
            v = self._pick(stats, field)
            if isinstance(v, list) and i < len(v) and isinstance(v[i], (int, float)):
                return float(v[i])
            return None

        ports = []
        for i in range(count):
            rx, tx = arr("rx_bytes", i), arr("tx_bytes", i)
            rxh, txh = arr("rx_bytes_hi", i), arr("tx_bytes_hi", i)
            if rx is not None and rxh is not None:
                rx += rxh * 4294967296.0
            if tx is not None and txh is not None:
                tx += txh * 4294967296.0
            rr, tr = arr("rx_rate", i), arr("tx_rate", i)
            sp = speeds[i] if i < len(speeds) else None
            ports.append({
                "n": i + 1,
                "name": hexstr(names[i]) if i < len(names) else "Port{}".format(i + 1),
                "enabled": bit(en, i),
                "link": bit(lnk, i),
                "full_duplex": bit(dpx, i),
                "speed": SPEEDS.get(sp, "") if isinstance(sp, int) else "",
                "rx_bytes": rx,
                "tx_bytes": tx,
                "rx_rate_bps": rr * 8 if rr is not None else None,
                "tx_rate_bps": tr * 8 if tr is not None else None,
                "rx_errors": arr("rx_errors", i),
            })
        info = {
            "identity": hexstr(self._pick(sysd, "identity")),
            "model": hexstr(self._pick(sysd, "model")),
            "version": hexstr(self._pick(sysd, "version")),
            "temp": self._pick(sysd, "temp"),
        }
        return {"ports": ports, "sys": info}
