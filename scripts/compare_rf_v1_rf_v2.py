#!/usr/bin/env python3
"""D1 guard-only RF-v1/RF-v2 comparison entrypoint."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.experiment_d.integrity import is_experiment_c_path
from src.experiment_d.paths import ExperimentDPaths, require_under


def load_report(path: Path) -> dict[str, object]:
    if is_experiment_c_path(path):
        raise ValueError("Experiment C metrics cannot be used as Experiment D final metrics")
    require_under(path, ExperimentDPaths().report_root / "final_test", "Experiment D final report")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to load evaluation report: {exc}") from exc
    if not isinstance(value, dict) or not value.get("final_test_manifest_sha256"):
        raise ValueError("report lacks final_test_manifest_sha256")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rf-v1-report", type=Path, required=True)
    parser.add_argument("--rf-v2-report", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    first, second = load_report(args.rf_v1_report), load_report(args.rf_v2_report)
    if first["final_test_manifest_sha256"] != second["final_test_manifest_sha256"]:
        raise ValueError("models were not evaluated on the identical sealed final-test manifest")
    identity = first["final_test_manifest_sha256"]
    if not args.dry_run:
        raise SystemExit("D1 guard: metric comparison is not implemented; use --dry-run")
    print(json.dumps({"status": "DRY_RUN_VALID", "comparison_performed": False,
                      "shared_final_test_identity": identity}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
