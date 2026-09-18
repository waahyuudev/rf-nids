#!/usr/bin/env python3
"""Create the immutable thesis-scope RF-v5/A4 scientific freeze package."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports/experiment_f/freeze/rf_v5_candidate_01"
MODEL = ROOT / "models/experiment_f/random_forest_rf_v5_candidate_01.joblib"
META = ROOT / "models/experiment_f/random_forest_rf_v5_candidate_01_metadata.json"
TRAIN = ROOT / "data/lab/experiment_f/normal_remediation_a2/derived/a4_run_01/frozen/rf_v5_candidate_01_training.csv"
TRAIN_LINEAGE = ROOT / "data/lab/experiment_f/normal_remediation_a2/derived/a4_run_01/frozen/rf_v5_candidate_01_training_lineage.csv"
VALID = ROOT / "data/lab/experiment_f/validation/derived/f4_a2_run_03/frozen/f_validation_78_features_ground_truth.csv"
VALID_LINEAGE = ROOT / "data/lab/experiment_f/validation/derived/f4_a2_run_03/frozen/f_validation_lineage.csv"
COMPARATIVE = ROOT / "reports/experiment_f/normal_remediation_a2/a4_run_01/comparative_metrics.json"
ACCEPTANCE = ROOT / "reports/experiment_f/normal_remediation_a2/a4_run_01/acceptance_gate_evaluation.json"
CONFUSION = ROOT / "reports/experiment_f/normal_remediation_a2/a4_run_01/confusion_matrix_rf_v5.csv"
FEATURE_SHA = "9338f50fc3e7efc78d678cc65ab38d428a7f6912ed9467a2b99a449a7c8e3c13"
EXPECTED = {
    MODEL: "31d7d50fa79e3400e7d357cab05c780e038bc527b746d0be6ff894828c6b8d17",
    META: "b9255fb4ad067611db60632e384e2cc5e8aaa2f989228cbc0e541ef421c7224e",
    TRAIN: "d7392488e74a7f0ca4b0813faf5458b15ae4b8e5b3cb1ea25e1cd95a6b37df37",
    TRAIN_LINEAGE: "f74ab5bc460bc2154eaca035b4931564b68007d03dc4933358a951aeae59e53b",
    VALID: "d5dbc3e6a6de373526c46bb7220092c14e81779ec91ebfe5ef855db7f7d53d0e",
    VALID_LINEAGE: "8c2697841de6df5d66e22836eee100cf53de08935f1832f265130a9a2419c909",
    COMPARATIVE: "e96012fb9ec5b634777baaa067f800aeac77a3c0c87b0ddfc7dc6d424d0e1bba",
    ACCEPTANCE: "9f546af11c1d5fabf0e5ab76bee40560669ef3e9ff27e58c2901a94eb036231b",
    CONFUSION: "6cc4746de6558afe6d5cc2f0e327d10676f436938414c3f15b94d7f9b2ea7250",
}


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def write_new(path: Path, value: str) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {rel(path)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def json_new(path: Path, value: object) -> None:
    write_new(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> int:
    if OUT.exists():
        raise FileExistsError(f"refusing to overwrite {rel(OUT)}")
    for path, expected in EXPECTED.items():
        if sha(path) != expected:
            raise RuntimeError(f"RF_V5_FREEZE_BLOCKED: hash mismatch: {rel(path)}")

    metadata = json.loads(META.read_text(encoding="utf-8"))
    comparative = json.loads(COMPARATIVE.read_text(encoding="utf-8"))
    acceptance = json.loads(ACCEPTANCE.read_text(encoding="utf-8"))
    train = pd.read_csv(TRAIN, low_memory=False)
    train_lineage = pd.read_csv(TRAIN_LINEAGE, low_memory=False)
    valid = pd.read_csv(VALID, low_memory=False)
    valid_lineage = pd.read_csv(VALID_LINEAGE, low_memory=False)
    if metadata["status"] != "CANDIDATE / NOT_ACTIVE" or metadata["active"] is not False:
        raise RuntimeError("RF_V5_FREEZE_BLOCKED: model status mismatch")
    if metadata["feature_order_sha256"] != FEATURE_SHA or metadata["feature_count"] != 78:
        raise RuntimeError("RF_V5_FREEZE_BLOCKED: feature identity mismatch")
    if train.shape != (7303, 79) or train_lineage.shape[0] != 7303:
        raise RuntimeError("RF_V5_FREEZE_BLOCKED: training shape mismatch")
    if train.ground_truth_class.value_counts().to_dict() != {"DDoS": 4023, "PortScan": 2581, "Normal": 699}:
        raise RuntimeError("RF_V5_FREEZE_BLOCKED: training counts mismatch")
    if valid.shape != (5999, 79) or valid_lineage.shape[0] != 5999:
        raise RuntimeError("RF_V5_FREEZE_BLOCKED: validation identity mismatch")
    if acceptance["validation_decision"] != "FAIL" or acceptance["final_evaluation_authorized"] is not False:
        raise RuntimeError("RF_V5_FREEZE_BLOCKED: decision mismatch")

    dependency_roots = [
        ROOT / "data/lab/experiment_f/normal_remediation_a2/raw",
        ROOT / "data/lab/experiment_f/normal_remediation_a2/derived/a4_run_01",
        ROOT / "reports/experiment_f/normal_remediation_a2/a4_run_01",
        ROOT / "data/lab/experiment_f/validation/derived/f4_a2_run_03/frozen",
        ROOT / "reports/experiment_f/validation/f4_a2_run_03",
    ]
    dependency_files = set()
    for base in dependency_roots:
        dependency_files.update(path for path in base.rglob("*") if path.is_file())
    dependency_files.update([
        MODEL, META,
        ROOT / "models/experiment_e/random_forest_rf_v3_candidate.joblib",
        ROOT / "models/experiment_e/random_forest_rf_v3_candidate_metadata.json",
        ROOT / "models/experiment_f/random_forest_rf_v4_candidate_01.joblib",
        ROOT / "models/experiment_f/random_forest_rf_v4_candidate_01_metadata.json",
        ROOT / "data/lab/experiment_f/datasets/rf_v4_candidate_01_training.csv",
        ROOT / "data/lab/experiment_f/datasets/rf_v4_candidate_01_training_lineage.csv",
        ROOT / "reports/experiment_f/dataset_assembly/rf_v4_candidate_01_training_input_freeze.json",
        ROOT / "reports/experiment_f/training/f3_a2_training_audit.json",
        ROOT / "reports/experiment_f/amendments/f0_normal_remediation_amendment_a4.json",
        ROOT / "reports/experiment_f/amendments/f0_normal_remediation_amendment_a4_integrity.json",
        ROOT / "reports/experiment_f/amendments/f0_normal_remediation_amendment_a4_SHA256SUMS",
        ROOT / "reports/experiment_f/preregistration/f0_acceptance_gates.json",
        ROOT / "reports/experiment_f/preregistration/f0_a1_acceptance_gates.json",
        ROOT / "reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv",
    ])
    dependency_inventory = OUT / "DEPENDENCY_SHA256SUMS"
    write_new(dependency_inventory, "".join(f"{sha(p)}  {rel(p)}\n" for p in sorted(dependency_files)))

    rf_metrics = {name: {key: value for key, value in metric.items() if key in ("accuracy", "macro_f1", "per_class", "confusion_matrix", "model_sha256")} for name, metric in comparative["models"].items()}
    failed = {name: value for name, value in acceptance["gates"].items() if value["status"] == "FAIL"}
    manifest = {
        "schema": "experiment_f_rf_v5_thesis_scientific_freeze",
        "version": 1,
        "freeze_decision": "RF_V5_A4_SCIENTIFIC_EVIDENCE_FROZEN",
        "immutability_policy": "All bound dependencies and freeze artifacts are content-addressed by SHA256. Any byte change invalidates this freeze and requires a new prospective record; overwrite is prohibited.",
        "model": {"id": "rf-v5-candidate-01", "status": "CANDIDATE / NOT_ACTIVE", "active": False, "path": rel(MODEL), "sha256": sha(MODEL), "metadata_path": rel(META), "metadata_sha256": sha(META)},
        "feature_contract": {"ordered_feature_count": 78, "feature_names": metadata["feature_names"], "feature_order_sha256": FEATURE_SHA, "crosswalk_sha256": metadata["crosswalk_sha256"]},
        "training_provenance": {"preprocessing": metadata["preprocessing"], "random_forest_parameters": metadata["rf_parameters"], "same_as_rf_v4": True, "hyperparameter_tuning": False, "threshold_change": False},
        "training_dataset": {"path": rel(TRAIN), "sha256": sha(TRAIN), "shape": [7303, 79], "feature_count": 78, "label_column": "ground_truth_class", "class_counts": {"Normal": 699, "DDoS": 4023, "PortScan": 2581}, "lineage_path": rel(TRAIN_LINEAGE), "lineage_sha256": sha(TRAIN_LINEAGE), "lineage_rows": 7303},
        "normal_remediation": {"sessions": ["F-A1-NORMAL-A2-01", "F-A1-NORMAL-A2-02", "F-A1-NORMAL-A2-03"], "adapted_rows": 605, "split": "F-ADAPTATION-NORMAL-A2", "validation_eligible": False, "final_eligible": False},
        "validation_dataset": {"identity": "Frozen Experiment F F4-A2 validation run 03", "path": rel(VALID), "sha256": sha(VALID), "shape": [5999, 79], "class_counts": {"Normal": 180, "DDoS": 2819, "PortScan": 3000}, "lineage_path": rel(VALID_LINEAGE), "lineage_sha256": sha(VALID_LINEAGE), "lineage_rows": 5999, "training_use": False},
        "comparative_metrics": rf_metrics,
        "rf_v5_confusion_matrix": {"labels": ["Normal", "DDoS", "PortScan"], "rows": [[174, 6, 0], [265, 2554, 0], [0, 0, 3000]], "artifact_path": rel(CONFUSION), "artifact_sha256": sha(CONFUSION)},
        "acceptance_gates": acceptance["gates"],
        "failed_mandatory_gates": failed,
        "scientific_decision": "RF_V5_VALIDATION_FAIL",
        "authorizations": {"experiment_f_final_evaluation": "NOT_AUTHORIZED", "rf_v5_activation": "NOT_AUTHORIZED", "rf_v5_promotion": "NOT_AUTHORIZED", "automatic_rf_v6": "PROHIBITED"},
        "future_runtime_demo_policy": "Any future Streamlit/runtime integration is operational/demo evidence only. It must not modify this scientific freeze, alter any bound dependency, change thresholds/features/preprocessing, activate/promote RF-v5, or change RF-v5 status from CANDIDATE / NOT_ACTIVE.",
        "dependency_inventory": {"path": rel(dependency_inventory), "sha256": sha(dependency_inventory), "entry_count": len(dependency_files)},
        "prohibited_actions_confirmed_not_performed": ["traffic", "extraction", "training or retraining", "RF-v6 creation", "tuning", "threshold change", "feature or preprocessing change", "validation re-evaluation", "activation", "promotion", "database active-model change", "existing scientific artifact overwrite", "historical evidence mutation"],
    }
    manifest_path = OUT / "rf_v5_candidate_01_scientific_freeze.json"
    json_new(manifest_path, manifest)
    summary_path = OUT / "rf_v5_candidate_01_scientific_freeze_summary.md"
    write_new(summary_path, "# RF-v5 Amendment A4 scientific freeze\n\nDecision: `RF_V5_A4_SCIENTIFIC_EVIDENCE_FROZEN`. Scientific result: `RF_V5_VALIDATION_FAIL`.\n\n`rf-v5-candidate-01` remains `CANDIDATE / NOT_ACTIVE`. It achieved accuracy 0.9548258043 and macro F1 0.8372719935 on the unchanged 5,999-row F4-A2 validation dataset. Recall was Normal 174/180 (0.9666666667), DDoS 2554/2819 (0.9059950337), and PortScan 3000/3000 (1.0).\n\nThe mandatory Normal recall absolute, Normal recall relative to RF-v3, and Normal-to-DDoS false-positive gates failed. Final evaluation, activation, and promotion are not authorized. No RF-v6 is authorized.\n\nFuture Streamlit/runtime work, if separately authorized, is operational/demo evidence only and cannot modify this freeze or RF-v5 scientific status.\n")

    verification_path = OUT / "dependency_inventory_verification.json"
    checked = 0
    for line in dependency_inventory.read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        if sha(ROOT / relative) != expected:
            raise RuntimeError(f"RF_V5_FREEZE_BLOCKED: inventory mismatch: {relative}")
        checked += 1
    json_new(verification_path, {"schema": "experiment_f_rf_v5_freeze_inventory_verification", "status": "PASS", "inventory_path": rel(dependency_inventory), "inventory_sha256": sha(dependency_inventory), "verified_entries": checked})

    freeze_inventory = OUT / "FREEZE_SHA256SUMS"
    freeze_artifacts = [dependency_inventory, manifest_path, summary_path, verification_path]
    write_new(freeze_inventory, "".join(f"{sha(p)}  {rel(p)}\n" for p in freeze_artifacts))
    print(json.dumps({"freeze_decision": manifest["freeze_decision"], "scientific_decision": manifest["scientific_decision"], "model_sha256": sha(MODEL), "metadata_sha256": sha(META), "dependency_entries_verified": checked, "freeze_inventory_sha256": sha(freeze_inventory)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
