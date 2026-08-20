"""Target-label mapping for the three RF-NIDS classes."""

from __future__ import annotations

import re

LABEL_MAPPING = {"Normal": 0, "DDoS": 1, "PortScan": 2}
CLASS_NAMES = tuple(LABEL_MAPPING)


def map_label(value: object) -> str | None:
    """Map a raw label to Normal, DDoS, PortScan, or None when out of scope."""
    if value is None:
        return None
    normalized = re.sub(r"\s+", " ", str(value).strip()).casefold()
    compact = normalized.replace(" ", "")
    if normalized in {"benign", "normal"}:
        return "Normal"
    if "ddos" in compact:
        return "DDoS"
    if "portscan" in compact:
        return "PortScan"
    return None

