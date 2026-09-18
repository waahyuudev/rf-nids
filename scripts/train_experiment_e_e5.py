#!/usr/bin/env python3
"""Fit the single, inactive Experiment E RF-v3 candidate (E5 only)."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.verify_experiment_d_frozen_baseline import build_manifest as frozen_baseline
from src.experiment_d.integrity import sha256_file
from src.experiment_e.e1 import validate_e1
from src.experiment_e.integrity import ordered_feature_identity, validate_feature_contract
from src.ingestion.cicflowmeter_v3_adapter import MODEL_FEATURES

DATASET = ROOT / "data/lab/experiment_e/datasets/experiment_e_training_candidate.csv"
LINEAGE = ROOT / "data/lab/experiment_e/datasets/experiment_e_training_candidate_lineage.csv"
MANIFEST = ROOT / "data/lab/experiment_e/datasets/experiment_e_training_candidate_manifest.json"
MODEL = ROOT / "models/experiment_e/random_forest_rf_v3_candidate.joblib"
METADATA = ROOT / "models/experiment_e/random_forest_rf_v3_candidate_metadata.json"
AUDIT = ROOT / "reports/experiment_e/audit/e5_training_audit.json"
DIAGNOSTICS = ROOT / "reports/experiment_e/analysis/e5_training_diagnostics.json"

EXPECTED = {
    "dataset_sha256": "f716404391467b267cca2f989762c2d4740127a4e7dd11afe956e7e8940b2284",
    "lineage_sha256": "950868cc0e5f8943e7eb03dba544d535d4d20e74a018facf48dcb7ebcb38ecd9",
    "manifest_sha256": "fb2ba80d300a8e52fc3f441fca0d6b319be60633cc97f65f0f48e603428bfa0e",
    "feature_sha256": "9338f50fc3e7efc78d678cc65ab38d428a7f6912ed9467a2b99a449a7c8e3c13",
}
CLASSES = ["Normal", "DDoS", "PortScan"]
COUNTS = {"Normal": 94, "DDoS": 3081, "PortScan": 2581}
PARAMS = {"n_estimators": 200, "criterion": "gini", "max_depth": None,
          "min_samples_split": 5, "min_samples_leaf": 4, "max_features": "log2",
          "class_weight": "balanced", "bootstrap": False, "random_state": 42, "n_jobs": -1}


def write_new(path: Path, value: dict) -> None:
    if path.exists():
        raise FileExistsError(f"E5 create-new output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def integrity_gate() -> tuple[pd.DataFrame, pd.Series, dict, dict]:
    for path, key in ((DATASET, "dataset_sha256"), (LINEAGE, "lineage_sha256"), (MANIFEST, "manifest_sha256")):
        if not path.is_file() or sha256_file(path) != EXPECTED[key]:
            raise ValueError(f"E4 integrity mismatch: {path.name}")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("dataset_sha256") != EXPECTED["dataset_sha256"] or manifest.get("lineage_sha256") != EXPECTED["lineage_sha256"]:
        raise ValueError("manifest does not bind the authorized E4 files")
    if manifest.get("total_rows") != 5756 or manifest.get("rows_per_class") != COUNTS:
        raise ValueError("manifest row totals/classes mismatch")
    if manifest.get("label_column") != "ground_truth_class" or manifest.get("feature_order") != list(MODEL_FEATURES):
        raise ValueError("manifest label or feature contract mismatch")
    validate_feature_contract(MODEL_FEATURES)
    if ordered_feature_identity(MODEL_FEATURES) != EXPECTED["feature_sha256"]:
        raise ValueError("ordered feature identity mismatch")
    frame = pd.read_csv(DATASET, low_memory=False)
    if len(frame) != 5756 or list(frame.columns) != [*MODEL_FEATURES, "ground_truth_class"]:
        raise ValueError("E4 CSV rows, target, or exact feature order mismatch")
    labels = frame["ground_truth_class"].astype(str)
    if set(labels.unique()) != set(CLASSES) or {c: int((labels == c).sum()) for c in CLASSES} != COUNTS:
        raise ValueError("E4 CSV target classes/counts mismatch")
    features = frame.loc[:, list(MODEL_FEATURES)].replace([np.inf, -np.inf], np.nan).astype(np.float32)
    lineage = pd.read_csv(LINEAGE, low_memory=False)
    required = {"row_identity", "ground_truth_class", "source_role", "source_session_id", "source_experiment", "source_csv"}
    if len(lineage) != len(frame) or not required.issubset(lineage.columns):
        raise ValueError("lineage row count/schema mismatch")
    if lineage.row_identity.isna().any() or lineage.row_identity.duplicated().any():
        raise ValueError("duplicate or blank lineage identity")
    forbidden = (lineage.source_role.astype(str) != "adaptation").any() or lineage.source_session_id.astype(str).str.contains("n-v1|p-v1|n-f1|p-f1", case=False, regex=True).any()
    final_ref = lineage.astype(str).apply(lambda c: c.str.contains("final[_ -]?test|n-f1|p-f1", case=False, regex=True)).any().any()
    if forbidden or final_ref or not (lineage.ground_truth_class.astype(str).to_numpy() == labels.to_numpy()).all():
        raise ValueError("validation/final-test source or label mismatch in lineage")
    if not manifest.get("final_test_seal_confirmed") or not manifest.get("validation_exclusion_confirmed"):
        raise ValueError("E4 manifest seal/exclusion confirmation missing")
    return features, labels, manifest, {"lineage_rows": len(lineage), "lineage_unique_identities": int(lineage.row_identity.nunique())}


def main() -> int:
    for output in (MODEL, METADATA, AUDIT, DIAGNOSTICS):
        if output.exists():
            raise FileExistsError(f"E5 create-new output already exists: {output}")
    e1_before = validate_e1()
    baseline_before = frozen_baseline()
    x, y, manifest, lineage_check = integrity_gate()
    started_utc = datetime.now(timezone.utc)
    started = time.perf_counter()
    model = RandomForestClassifier(**PARAMS)
    model.fit(x, y)
    duration = time.perf_counter() - started
    ended_utc = datetime.now(timezone.utc)
    if model.n_features_in_ != 78 or set(model.classes_) != set(CLASSES) or len(model.estimators_) != 200:
        raise ValueError("fitted candidate identity mismatch")
    MODEL.parent.mkdir(parents=True, exist_ok=True)
    with MODEL.open("xb") as stream:
        joblib.dump(model, stream, compress=3)
    model_hash, model_size = sha256_file(MODEL), MODEL.stat().st_size
    subset = x.iloc[np.arange(0, len(x), 97, dtype=int)].copy()
    prediction_distribution = pd.Series(model.predict(x)).value_counts().reindex(CLASSES, fill_value=0).astype(int).to_dict()
    # Reloading the one serialized candidate is a non-competing reproducibility check; no second fit occurs.
    reloaded = joblib.load(MODEL)
    reproducibility = {
        "status": "PASS", "second_model_fit_performed": False,
        "method": "reload the sole serialized candidate and compare deterministic fixed-subset outputs",
        "fixed_subset": {"selection": "row indices 0,97,194,...", "rows": len(subset), "dataset_sha256": EXPECTED["dataset_sha256"]},
        "hyperparameters_match": reloaded.get_params() == model.get_params(),
        "estimator_classes_match": list(reloaded.classes_) == list(model.classes_),
        "tree_count_match": len(reloaded.estimators_) == len(model.estimators_),
        "tree_random_states_match": [t.random_state for t in reloaded.estimators_] == [t.random_state for t in model.estimators_],
        "predictions_match": bool(np.array_equal(reloaded.predict(subset), model.predict(subset))),
        "probabilities_match": bool(np.array_equal(reloaded.predict_proba(subset), model.predict_proba(subset))),
        "serialized_hash_note": "Only one serialization was produced; cross-serialization hash equality was intentionally not asserted.",
    }
    if not all(v for k, v in reproducibility.items() if k.endswith("_match")):
        raise ValueError("serialized candidate reproducibility check failed")
    metadata = {
        "schema": "experiment_e_e5_candidate_metadata", "schema_version": 1,
        "status": "CANDIDATE / NOT_ACTIVE", "experiment": "Experiment E", "version": "rf-v3.0-candidate",
        "parent_baseline": "rf-v2.0 / Experiment D", "model_path": str(MODEL.relative_to(ROOT)), "model_sha256": model_hash,
        "training_dataset": {"identity": "E4 candidate", "path": str(DATASET.relative_to(ROOT)), **EXPECTED},
        "classes_declared_order": CLASSES, "estimator_classes": list(model.classes_), "feature_count": 78,
        "feature_names": list(MODEL_FEATURES), "feature_order_sha256": EXPECTED["feature_sha256"],
        "rf_parameters": PARAMS, "training_class_counts": COUNTS, "training_rows": 5756,
        "preprocessing": "Pinned 78-feature contract; +/-Infinity converted to NaN; no scaling, normalization, PCA, feature selection, imputation, encoder, or threshold change.",
        "provenance": {"E1": "reports/experiment_e/audit E1 validation rerun", "E2": "reports/experiment_e/audit/e2_* capture validation", "E3": "reports/experiment_e/audit/e3_extraction_validation_final.json", "E4": "reports/experiment_e/audit/e4_dataset_construction_audit.json", "cicflowmeter_amendment": "reports/experiment_e/audit/e3_provenance_amendment_a1.json", "historical_ddos_source": manifest["historical_sources"], "session_aware_e4_capping": manifest["selection_rule"]},
        "validation_status": "NOT_YET_VALIDATED; N-V1/P-V1 were not read or evaluated in E5.",
        "final_test_status": "SEALED_AND_UNREAD; N-F1/P-F1 and Experiment D final-test were not read.",
        "environment": {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "joblib": joblib.__version__, "numpy": np.__version__, "platform": platform.platform()},
        "training": {"seed": 42, "started_utc": started_utc.isoformat(), "ended_utc": ended_utc.isoformat(), "fitting_duration_seconds": duration},
    }
    write_new(METADATA, metadata)
    metadata_hash = sha256_file(METADATA)
    baseline_after, e1_after = frozen_baseline(), validate_e1()
    d_final_audit = json.loads((ROOT / "reports/experiment_d/audit/final_test_leakage_audit.json").read_text(encoding="utf-8"))
    e4_audit = json.loads((ROOT / "reports/experiment_e/audit/e4_dataset_construction_audit.json").read_text(encoding="utf-8"))
    regression = {"e1_validation_rerun": e1_before == e1_after and e1_after["status"] == "PASS", "e3_integrity_evidence": json.loads((ROOT / "reports/experiment_e/audit/e3_extraction_validation_final.json").read_text())["session_isolation"]["final_test_sessions_absent_and_unread"], "e4_dataset_integrity": True, "frozen_experiment_d_baseline": baseline_before["path_independent_scientific_identity"] == baseline_after["path_independent_scientific_identity"], "rf_v2_artifact_hash_integrity": all(x["matches"] for x in baseline_after["entries"]), "feature_identity_78": True, "final_test_seal": d_final_audit["status"] == "PASS" and e4_audit["checks"]["final_test_unread_and_excluded"]}
    if not all(regression.values()):
        raise ValueError(f"post-training regression failed: {regression}")
    diagnostics = {"schema": "experiment_e_e5_training_diagnostics", "status": "PASS", "classification": "TRAINING_DIAGNOSTIC_ONLY / NON_EVALUATIVE", "training_rows": 5756, "training_class_counts": COUNTS, "fitting_duration_seconds": duration, "tree_count": len(model.estimators_), "feature_count": int(model.n_features_in_), "training_set_prediction_distribution": prediction_distribution, "explicit_limitation": "No training accuracy, recall, F1, or validation performance is reported or interpreted as evidence."}
    write_new(DIAGNOSTICS, diagnostics)
    audit = {"schema": "experiment_e_e5_training_audit", "schema_version": 1, "status": "PASS", "verdict": "PASS", "candidate": {"version": "rf-v3.0-candidate", "status": "CANDIDATE / NOT_ACTIVE", "model_path": str(MODEL.relative_to(ROOT)), "model_sha256": model_hash, "model_size_bytes": model_size, "metadata_path": str(METADATA.relative_to(ROOT)), "metadata_sha256": metadata_hash, "n_features_in": int(model.n_features_in_), "estimator_classes": list(model.classes_), "n_estimators": len(model.estimators_)}, "integrity_gate": {"authorized_dataset": EXPECTED, "rows": 5756, "class_counts": COUNTS, "lineage": lineage_check, "only_target_label": "ground_truth_class", "exact_78_feature_order": True, "validation_sources_absent": True, "final_test_sources_absent": True, "experiment_d_final_test_absent": True}, "rf_parameters": PARAMS, "environment": metadata["environment"], "training": metadata["training"], "reproducibility": reproducibility, "post_training_regression": regression, "evidence": {"audit": str(AUDIT.relative_to(ROOT)), "diagnostics": str(DIAGNOSTICS.relative_to(ROOT))}, "limitations": ["Class imbalance remains substantial (Normal=94).", "P-A3 contributes 25 rows; E4 retained its independent session signal.", "DDoS is historical Experiment D adaptation-only data.", "Candidate has not been validated; E5 contains no validation or final-test performance evidence."], "e6_offline_validation_scientifically_authorized": True}
    write_new(AUDIT, audit)
    print(json.dumps({"verdict": "PASS", "model_sha256": model_hash, "metadata_sha256": metadata_hash, "fitting_duration_seconds": duration, "e6_authorized": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
