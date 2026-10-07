"""Rebuild mcc/oui.tsv.gz, the MAC vendor snapshot MCC ships with, from the IEEE registries.

    python tools/build_oui.py

Downloads MA-L, MA-M and MA-S from standards-oui.ieee.org (about 5 MB). A running MCC can do the same from
Setup › Device identification; that copy goes to data/oui/ instead.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcc.oui import BUNDLED, _fetch, build  # noqa: E402


def main() -> int:
    def fetch(url: str) -> bytes:
        print("fetching", url)
        return _fetch(url)

    blob, n = build(fetch)
    BUNDLED.write_bytes(blob)
    print("wrote {} ({} prefixes, {:.0f} KB)".format(BUNDLED.relative_to(ROOT), n, len(blob) / 1024))
    return 0


if __name__ == "__main__":
    sys.exit(main())
