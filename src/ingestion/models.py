"""Small data contracts shared by ingestion components."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ExtractedFlow:
    fields: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)
    flow_id: str | None = None


@dataclass(slots=True)
class AdaptedFlow:
    features: dict[str, float | None]
    metadata: dict[str, Any] = field(default_factory=dict)
    fingerprint: str | None = None
