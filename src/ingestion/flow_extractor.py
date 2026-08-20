"""Readers for CICFlowMeter-compatible flow CSV output."""

from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path

from .models import ExtractedFlow


class FlowCsvExtractor:
    """Yield extractor rows without pretending that CSV fields were packet-derived here."""

    def read(self, path: Path) -> Iterator[ExtractedFlow]:
        try:
            handle = path.open(newline="", encoding="utf-8-sig")
        except OSError as exc:
            raise RuntimeError(f"Unable to open flow CSV {path}: {exc}") from exc
        with handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                raise RuntimeError(f"Flow CSV has no header: {path}")
            for row in reader:
                yield ExtractedFlow(fields=dict(row))

    @staticmethod
    def field_names(path: Path) -> list[str]:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            return list(csv.DictReader(handle).fieldnames or [])
