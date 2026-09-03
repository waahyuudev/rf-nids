from __future__ import annotations

import importlib.util
from pathlib import Path

import pandas as pd


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/audit_experiment_d_adaptation.py"
SPEC = importlib.util.spec_from_file_location("adaptation_audit", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_sessions_are_unique_and_have_three_valid_per_class() -> None:
    captures = [f"{row[1]}-{row[2]}" for row in MODULE.SESSIONS]
    assert len(captures) == len(set(captures))
    for label in ("Normal", "PortScan", "DDoS"):
        assert sum(row[0] == label and row[3] not in MODULE.INVALID_FILES for row in MODULE.SESSIONS) >= 3


def test_duplicate_row_count_includes_all_occurrences() -> None:
    frames = [pd.DataFrame({"a": [1, 2]}), pd.DataFrame({"a": [1]})]
    assert MODULE.exact_duplicate_rows(frames) == 2
