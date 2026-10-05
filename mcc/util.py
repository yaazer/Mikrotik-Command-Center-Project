"""Small helpers shared by every module: time, IP classification, RouterOS value parsing."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Iterable, List, Optional, Tuple


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ip_obj(text: Any) -> Optional[Any]:
    try:
        return ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None


def is_ip(text: Any) -> bool:
    return ip_obj(text) is not None


# Address space that is local by definition. Deliberately not ipaddress.is_private, which also
# counts documentation and benchmarking ranges as "private".
LOCAL_SCOPE = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "fc00::/7", "fe80::/10", "::1/128")]


def is_local_scope(ip: Any) -> bool:
    o = ip_obj(ip)
    return o is not None and any(o.version == n.version and o in n for n in LOCAL_SCOPE)


def parse_networks(items: Iterable[str]) -> List[Any]:
    nets = []
    for item in items:
        item = (item or "").strip()
        if not item or item.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(item.split()[0], strict=False))
        except ValueError:
            continue
    return nets


def in_networks(ip: Any, nets: Iterable[Any]) -> bool:
    o = ip_obj(ip)
    if o is None:
        return False
    return any(o.version == n.version and o in n for n in nets)


_DURATION = re.compile(r"(\d+)(w|d|h|ms|m|s)")


def parse_duration(text: Any) -> float:
    """RouterOS durations: '1w2d3h4m5s', '3h12m', or '01:02:03'. Returns seconds."""
    s = str(text or "").strip()
    if not s:
        return 0.0
    if re.fullmatch(r"\d+:\d{2}:\d{2}", s):
        h, m, sec = (int(x) for x in s.split(":"))
        return float(h * 3600 + m * 60 + sec)
    total = 0.0
    unit = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001}
    for num, u in _DURATION.findall(s):
        total += int(num) * unit[u]
    return total


def to_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        try:
            return int(float(str(value).strip()))
        except (TypeError, ValueError):
            return default


def to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def to_bool(value: Any) -> bool:
    return str(value).strip().lower() in ("true", "yes", "1", "on")


def split_hostport(text: str) -> Tuple[str, Optional[int]]:
    """'1.2.3.4:443' -> ('1.2.3.4', 443); '[2001:db8::1]:443' too; a bare address -> (addr, None)."""
    s = (text or "").strip()
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        return host, to_int(rest.lstrip(":"), 0) or None
    if s.count(":") == 1:
        host, port = s.split(":")
        return host, to_int(port, 0) or None
    return s, None


def human_bps(bps: float) -> str:
    for unit in ("bps", "kbps", "Mbps", "Gbps", "Tbps"):
        if abs(bps) < 1000 or unit == "Tbps":
            return "{:.1f} {}".format(bps, unit) if unit != "bps" else "{:.0f} bps".format(bps)
        bps /= 1000.0
    return "{:.1f} Tbps".format(bps)
