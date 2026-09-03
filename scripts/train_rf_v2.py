#!/usr/bin/env python3
"""Experiment D RF-v2 D3 manifest validator; fitting remains disabled."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.experiment_d.d3 import (  # noqa: E402
    assert_provenance_not_features,
    canonical_json_sha256,
    decode_index_membership,
    validate_output_contract,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--split-manifest", type=Path,
        default=ROOT / "reports/experiment_d/adaptation/split_manifest.json",
    )
    parser.add_argument(
        "--training-plan", type=Path,
        default=ROOT / "reports/experiment_d/adaptation/rf_v2_training_plan.json",
    )
    parser.add_argument(
        "--candidate-strategy", choices=("D3-A", "D3-B", "D3-C", "D3-D"),
        default="D3-C",
    )
    parser.add_argument("--dry-run", action="store_true", required=True)
    return parser


def validate_dry_run(split: dict, plan: dict, strategy: str) -> dict:
    if split.get("schema") != "experiment_d_d3_split_manifest" or split.get("schema_version") != 1:
        raise ValueError("unsupported D3 split manifest")
    calculated = canonical_json_sha256({k: v for k, v in split.items() if k != "content_identity"})
    if split.get("content_identity") != calculated:
        raise ValueError("split manifest content identity mismatch")
    if plan.get("phase") != "D3_PRE_TRAINING_ONLY" or plan.get("training_enabled") is not False:
        raise ValueError("training plan must remain D3 pre-training only")
    if strategy not in split["adaptation"]["candidate_strategies"]:
        raise ValueError(f"candidate strategy absent: {strategy}")

    adaptation = split["adaptation"]
    train_sessions = set(adaptation["selected_training_sessions"])
    validation_sessions = set(adaptation["selected_validation_sessions"])
    if train_sessions & validation_sessions:
        raise ValueError("adaptation session leakage")
    if "expd-adapt-ddos-session-03" not in adaptation["excluded_invalid_sessions"]:
        raise ValueError("invalid DDoS session 03 is not excluded")
    validation_capture_ids = {row["capture_id"] for row in adaptation["validation_rows"]}
    if len(validation_capture_ids) != len(validation_sessions):
        raise ValueError("adaptation validation capture/session separation mismatch")

    cicids = split["cicids2017"]
    train_indices = decode_index_membership(cicids["training_membership"])
    control_indices = decode_index_membership(cicids["internal_control_membership"])
    if set(train_indices) & set(control_indices):
        raise ValueError("CICIDS2017 training/control overlap")
    checks = split["leakage_checks"]
    if checks["post_handling_cross_source_overlap_count"] != 0:
        raise ValueError("cross-source feature overlap remains")
    if checks.get("experiment_c_used") or checks.get("final_test_used"):
        raise ValueError("Experiment C/final_test data is prohibited")

    assert_provenance_not_features(split["feature_order"])
    preprocessing = plan["preprocessing"]
    if (
        preprocessing["pipeline"][0] != "SimpleImputer(strategy='median')"
        or preprocessing["imputer_fit_scope"] != "combined D4 training partition only"
    ):
        raise ValueError("preprocessing leakage policy mismatch")
    if plan.get("randomized_search_cv_allowed") is not False:
        raise ValueError("RandomizedSearchCV is prohibited in D3")
    validate_output_contract(plan["outputs"])
    existing_outputs = [output for output in plan["outputs"] if (ROOT / output).exists()]

    candidate = adaptation["candidate_strategies"][strategy]
    names = ("Normal", "DDoS", "PortScan")
    combined = {
        name: cicids["training_class_counts"][name]
        + candidate["adaptation_class_counts"][name]
        for name in names
    }
    validation_counts = {
        name: sum(row["ground_truth_class"] == name for row in adaptation["validation_rows"])
        for name in names
    }
    return {
        "status": "DRY_RUN_VALID",
        "training_performed": False,
        "model_instantiated": False,
        "candidate_strategy": strategy,
        "adaptation_training_counts": candidate["adaptation_class_counts"],
        "adaptation_validation_counts": validation_counts,
        "combined_training_counts": combined,
        "planned_training_rows": sum(combined.values()),
        "planned_adaptation_validation_rows": sum(validation_counts.values()),
        "planned_cicids2017_internal_control_rows": sum(cicids["internal_control_class_counts"].values()),
        "outputs": plan["outputs"],
        "existing_outputs": existing_outputs,
        "create_new_required_for_training": True,
    }


def main() -> int:
    args = build_parser().parse_args()
    if not args.split_manifest.is_file() or not args.training_plan.is_file():
        raise ValueError("D3 split manifest and training plan must exist")
    split = json.loads(args.split_manifest.read_text(encoding="utf-8"))
    plan = json.loads(args.training_plan.read_text(encoding="utf-8"))
    print(json.dumps(validate_dry_run(split, plan, args.candidate_strategy), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
