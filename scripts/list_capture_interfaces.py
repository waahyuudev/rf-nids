#!/usr/bin/env python3
"""List host interfaces and highlight likely virtual-lab capture candidates."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ingestion.live_capture import list_interfaces


VIRTUAL_PREFIXES = ("bridge", "vmnet", "vboxnet", "utun", "tap")


def main() -> int:
    interfaces = list_interfaces()
    for interface in interfaces:
        marker = "candidate" if interface.startswith(VIRTUAL_PREFIXES) else "other"
        print(f"{interface}\t{marker}")
    print("Candidates are hints only; verify with benign lab traffic before selecting one.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
