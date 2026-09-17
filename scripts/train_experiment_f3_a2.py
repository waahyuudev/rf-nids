#!/usr/bin/env python3
"""Train and freeze the sole A2-authorized first RF-v4 candidate."""
from __future__ import annotations

import hashlib
import io
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

from src.experiment_e.integrity import ordered_feature_identity  # noqa: E402
from src.ingestion.cicflowmeter_v3_adapter import MODEL_FEATURES  # noqa: E402

FREEZE = ROOT / "reports/experiment_f/dataset_assembly/rf_v4_candidate_01_training_input_freeze.json"
DATASET = ROOT / "data/lab/experiment_f/datasets/rf_v4_candidate_01_training.csv"
LINEAGE = ROOT / "data/lab/experiment_f/datasets/rf_v4_candidate_01_training_lineage.csv"
RF_V3 = ROOT / "models/experiment_e/random_forest_rf_v3_candidate.joblib"
RF_V3_META = ROOT / "models/experiment_e/random_forest_rf_v3_candidate_metadata.json"
MODEL = ROOT / "models/experiment_f/random_forest_rf_v4_candidate_01.joblib"
METADATA = ROOT / "models/experiment_f/random_forest_rf_v4_candidate_01_metadata.json"
AUDIT = ROOT / "reports/experiment_f/training/f3_a2_training_audit.json"
REPRO = ROOT / "reports/experiment_f/training/f3_a2_training_reproducibility_audit.json"
SUMMARY = ROOT / "reports/experiment_f/training/f3_a2_training_summary.md"
CHECKSUMS = ROOT / "reports/experiment_f/training/f3_a2_SHA256SUMS"

EXPECTED = {
    "freeze": "1e89b78779c15d2c9f9cd21ea89fd39c88275a888fd28fd7d08b8d62d5cf4142",
    "dataset": "a65c812494917b2e6d18153b784fd0505b84229f86b6a6916c59fa1187bd778d",
    "lineage": "1ee2fdad6a9cb4321f6a85beb003e2eb2596518ddd9b54a7a9f151b1c65f4283",
    "feature": "9338f50fc3e7efc78d678cc65ab38d428a7f6912ed9467a2b99a449a7c8e3c13",
    "crosswalk": "66e517cdcea217f19de4d0a2cd45302ede999388393f539fb8ca4a2c68b74cf4",
    "rf_v2": "fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31",
    "rf_v3": "6b01c7b3923c1a6bd471862d011f8f5b88a31378e51d1dde082bd2e72bedef86",
    "rf_v3_meta": "30b6bdf2a6cb2d60e2be36d4db1e124d71504393081b229e6d94da7e70322cbc",
}
COUNTS = {"Normal": 94, "DDoS": 4023, "PortScan": 2581}
F_SESSIONS = ["F-A1-DDOSLIKE-A-01", "F-A1-DDOSLIKE-A-02", "F-A1-DDOSLIKE-A-03"]


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"F3_A2_RF_V4_TRAINING_BLOCKED: {message}")


def write_new(path: Path, text: str) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {rel(path)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def json_new(path: Path, payload: dict) -> None:
    write_new(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def serialized_sha(model: RandomForestClassifier) -> str:
    stream = io.BytesIO()
    joblib.dump(model, stream, compress=3)
    return hashlib.sha256(stream.getvalue()).hexdigest()


def tree_identity(model: RandomForestClassifier) -> str:
    h = hashlib.sha256()
    for estimator in model.estimators_:
        tree = estimator.tree_
        for array in (tree.children_left, tree.children_right, tree.feature, tree.threshold, tree.value, tree.impurity, tree.n_node_samples, tree.weighted_n_node_samples):
            h.update(np.ascontiguousarray(array).tobytes())
        h.update(str(estimator.random_state).encode())
    return h.hexdigest()


def main() -> int:
    outputs = (MODEL, METADATA, AUDIT, REPRO, SUMMARY, CHECKSUMS)
    require(not any(p.exists() for p in outputs), "one or more create-new outputs already exist")
    require(sha(FREEZE) == EXPECTED["freeze"], "training-input freeze checksum mismatch")
    require(sha(DATASET) == EXPECTED["dataset"], "dataset checksum mismatch")
    require(sha(LINEAGE) == EXPECTED["lineage"], "lineage checksum mismatch")
    require(sha(RF_V3) == EXPECTED["rf_v3"], "RF-v3 checksum mismatch")
    require(sha(RF_V3_META) == EXPECTED["rf_v3_meta"], "RF-v3 metadata checksum mismatch")
    require(sha(ROOT / "models/experiment_d/random_forest_rf_v2.joblib") == EXPECTED["rf_v2"], "RF-v2 checksum mismatch")
    require(sha(ROOT / "reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv") == EXPECTED["crosswalk"], "crosswalk checksum mismatch")

    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
    require(freeze["status"] == "F3_A2_RF_V4_TRAINING_READY", "freeze does not authorize training")
    require(freeze["candidate_dataset"]["sha256"] == EXPECTED["dataset"], "freeze dataset binding mismatch")
    require(freeze["row_lineage"]["sha256"] == EXPECTED["lineage"], "freeze lineage binding mismatch")
    require(freeze["feature_order_sha256"] == EXPECTED["feature"], "freeze feature binding mismatch")

    frame = pd.read_csv(DATASET, low_memory=False)
    lineage = pd.read_csv(LINEAGE, low_memory=False)
    require(frame.shape == (6698, 79), "dataset shape mismatch")
    require(list(frame.columns) == [*MODEL_FEATURES, "ground_truth_class"], "dataset feature/label order mismatch")
    require(ordered_feature_identity(list(frame.columns[:78])) == EXPECTED["feature"], "feature identity mismatch")
    require(len(lineage) == len(frame), "lineage cardinality mismatch")
    require(lineage.candidate_row_index.tolist() == list(range(6698)), "lineage row order mismatch")
    y = frame["ground_truth_class"].astype(str)
    require(y.value_counts().to_dict() == {"DDoS": 4023, "PortScan": 2581, "Normal": 94}, "class count mismatch")
    require((lineage.ground_truth_class.astype(str).to_numpy() == y.to_numpy()).all(), "lineage label mismatch")
    require(set(lineage[lineage.source_experiment == "EXPERIMENT_F"].source_session_id) == set(F_SESSIONS), "unauthorized F session")
    require(set(lineage.source_role) <= {"adaptation", "F-ADAPTATION"}, "non-adaptation lineage role")

    raw_features = frame.loc[:, list(MODEL_FEATURES)]
    raw_numeric = raw_features.to_numpy(dtype=np.float64)
    require(int(np.isnan(raw_numeric).sum()) == 336, "unexpected NaN count")
    require(int(np.isinf(raw_numeric).sum()) == 0, "unexpected Inf count")
    x = raw_features.replace([np.inf, -np.inf], np.nan).astype(np.float32)
    require(len(x) == len(frame) and list(x.columns) == list(MODEL_FEATURES), "preprocessing changed rows/features")

    rf_v3 = joblib.load(RF_V3)
    rf_v3_meta = json.loads(RF_V3_META.read_text(encoding="utf-8"))
    params = rf_v3.get_params(deep=False)
    require(params == rf_v3_meta["rf_parameters"] | {k: v for k, v in params.items() if k not in rf_v3_meta["rf_parameters"]}, "RF-v3 parameter resolution mismatch")
    expected_core = {"n_estimators": 200, "criterion": "gini", "max_depth": None, "min_samples_split": 5, "min_samples_leaf": 4, "max_features": "log2", "bootstrap": False, "class_weight": "balanced", "random_state": 42, "n_jobs": -1}
    require(all(params[k] == v for k, v in expected_core.items()), "RF-v3 core parameters mismatch")
    require(rf_v3_meta["preprocessing"] == "Pinned 78-feature contract; +/-Infinity converted to NaN; no scaling, normalization, PCA, feature selection, imputation, encoder, or threshold change.", "RF-v3 preprocessing cannot be reproduced exactly")

    started_utc = datetime.now(timezone.utc)
    started = time.perf_counter()
    candidate = RandomForestClassifier(**params)
    candidate.fit(x, y)
    fit_seconds = time.perf_counter() - started
    ended_utc = datetime.now(timezone.utc)

    repeat_started = time.perf_counter()
    repeat = RandomForestClassifier(**params)
    repeat.fit(x, y)
    repeat_seconds = time.perf_counter() - repeat_started
    subset = x.iloc[np.arange(0, len(x), 97, dtype=int)]
    candidate_tree_sha = tree_identity(candidate)
    repeat_tree_sha = tree_identity(repeat)
    candidate_probabilities = candidate.predict_proba(subset)
    repeat_probabilities = repeat.predict_proba(subset)
    behavior = {
        "predictions_match": bool(np.array_equal(candidate.predict(subset), repeat.predict(subset))),
        "probabilities_exact_match": bool(np.array_equal(candidate_probabilities, repeat_probabilities)),
        "probabilities_allclose": bool(np.allclose(candidate_probabilities, repeat_probabilities, rtol=0.0, atol=1e-15)),
        "probabilities_max_absolute_difference": float(np.max(np.abs(candidate_probabilities - repeat_probabilities))),
        "tree_identity_match": candidate_tree_sha == repeat_tree_sha,
        "tree_random_states_match": [t.random_state for t in candidate.estimators_] == [t.random_state for t in repeat.estimators_],
        "parameters_match": candidate.get_params(deep=False) == repeat.get_params(deep=False) == params,
        "classes_match": list(candidate.classes_) == list(repeat.classes_),
    }
    print(json.dumps({"repeat_fit_diagnostic": behavior, "candidate_tree_sha": candidate_tree_sha, "repeat_tree_sha": repeat_tree_sha}), flush=True)
    required_behavior = ("predictions_match", "probabilities_allclose", "tree_identity_match", "tree_random_states_match", "parameters_match", "classes_match")
    require(all(bool(behavior[k]) for k in required_behavior), "deterministic repeat-fit behavior mismatch")
    repeat_serialized_sha = serialized_sha(repeat)

    require(candidate.n_features_in_ == 78, "fitted feature count mismatch")
    require(list(candidate.feature_names_in_) == list(MODEL_FEATURES), "fitted feature names mismatch")
    require(set(candidate.classes_) == {"DDoS", "Normal", "PortScan"}, "fitted classes mismatch")
    require(candidate.get_params(deep=False) == params, "fitted parameters differ from RF-v3")
    require(candidate.random_state == 42 and len(candidate.estimators_) == 200, "fitted structural identity mismatch")

    MODEL.parent.mkdir(parents=True, exist_ok=True)
    with MODEL.open("xb") as stream:
        joblib.dump(candidate, stream, compress=3)
    model_sha = sha(MODEL)
    model_size = MODEL.stat().st_size
    reloaded = joblib.load(MODEL)
    reloaded_probabilities = reloaded.predict_proba(subset)
    candidate_reload_probabilities = candidate.predict_proba(subset)
    reload_checks = {
        "predictions_match": bool(np.array_equal(candidate.predict(subset), reloaded.predict(subset))),
        "probabilities_exact_match": bool(np.array_equal(candidate_reload_probabilities, reloaded_probabilities)),
        "probabilities_allclose": bool(np.allclose(candidate_reload_probabilities, reloaded_probabilities, rtol=0.0, atol=1e-15)),
        "probabilities_max_absolute_difference": float(np.max(np.abs(candidate_reload_probabilities - reloaded_probabilities))),
        "tree_identity_match": tree_identity(reloaded) == candidate_tree_sha,
        "parameters_match": reloaded.get_params(deep=False) == params,
        "classes_match": list(reloaded.classes_) == list(candidate.classes_),
    }
    required_reload = ("predictions_match", "probabilities_allclose", "tree_identity_match", "parameters_match", "classes_match")
    require(all(bool(reload_checks[k]) for k in required_reload), "serialized candidate reload mismatch")

    environment = {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "joblib": joblib.__version__, "numpy": np.__version__, "pandas": pd.__version__, "platform": platform.platform()}
    metadata = {
        "schema": "experiment_f_rf_v4_candidate_metadata", "schema_version": 1,
        "model_id": "rf-v4.0-candidate-01", "version": "rf-v4.0-candidate-01", "experiment": "Experiment F",
        "status": "CANDIDATE / NOT_ACTIVE", "active": False, "parent_model": "rf-v3.0-candidate",
        "model_path": rel(MODEL), "model_sha256": model_sha, "model_size_bytes": model_size,
        "training_input_freeze": {"path": rel(FREEZE), "sha256": EXPECTED["freeze"]},
        "training_dataset": {"path": rel(DATASET), "sha256": EXPECTED["dataset"], "rows": 6698, "class_counts": COUNTS},
        "training_lineage": {"path": rel(LINEAGE), "sha256": EXPECTED["lineage"], "rows": 6698},
        "amendment_a2": freeze["amendment_a2"], "experiment_f_sessions": F_SESSIONS,
        "feature_count": 78, "feature_names": list(MODEL_FEATURES), "feature_order_sha256": EXPECTED["feature"], "crosswalk_sha256": EXPECTED["crosswalk"],
        "label_column": "ground_truth_class", "estimator_classes": list(candidate.classes_), "rf_parameters": params,
        "preprocessing": {"input_dtype": "float32", "positive_negative_infinity": "replace with NaN", "nan_cells": 336, "imputation": "NONE", "scaling": "NONE", "normalization": "NONE", "encoding": "NONE", "PCA": "NONE", "feature_selection": "NONE", "row_deletion": "NONE", "source": "exact frozen RF-v3 training workflow"},
        "scientific_scope": "The additional Experiment F DDoS training contribution consists of controlled HTTP DDoS-like/load profiles collected under Amendment A1. RF-v4 has not demonstrated improved DDoS generalization. Training success is not evidence of detection improvement; prospectively separated validation is required.",
        "training": {"started_utc": started_utc.isoformat(), "ended_utc": ended_utc.isoformat(), "fitting_duration_seconds": fit_seconds, "train_test_split": False, "cross_validation": False, "hyperparameter_tuning": False, "candidate_count": 1},
        "environment": environment,
    }
    json_new(METADATA, metadata)
    metadata_sha = sha(METADATA)

    repro = {
        "schema": "experiment_f_f3_a2_training_reproducibility_audit", "version": 1, "status": "PASS",
        "method": "Independent non-candidate repeat-fit with the identical frozen input, float32/NaN preprocessing, feature order, labels, complete RF-v3 parameters, and random_state=42; compare fixed-subset behavior and exact tree structure. Reload the sole serialized candidate separately.",
        "candidate_model_sha256": model_sha, "repeat_model_persisted": False,
        "fixed_subset": {"selection": "row indices 0,97,194,...", "rows": len(subset), "dataset_sha256": EXPECTED["dataset"]},
        "candidate_tree_identity_sha256": candidate_tree_sha, "repeat_tree_identity_sha256": repeat_tree_sha,
        "candidate_serialized_sha256": model_sha, "repeat_in_memory_serialized_sha256": repeat_serialized_sha,
        "byte_serialization_match": model_sha == repeat_serialized_sha,
        "byte_serialization_policy": "Serialization equality is recorded but is not the scientific pass criterion; behavior and tree identity are authoritative.",
        "behavior_checks": behavior, "reload_checks": reload_checks,
        "candidate_fit_seconds": fit_seconds, "repeat_fit_seconds": repeat_seconds,
        "validation_or_final_data_used": False,
    }
    json_new(REPRO, repro)
    repro_sha = sha(REPRO)

    integrity_paths = {
        "models/experiment_d/random_forest_rf_v2.joblib": EXPECTED["rf_v2"],
        "models/experiment_e/random_forest_rf_v3_candidate.joblib": EXPECTED["rf_v3"],
        "models/experiment_e/random_forest_rf_v3_candidate_metadata.json": EXPECTED["rf_v3_meta"],
        "reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv": EXPECTED["crosswalk"],
        "reports/experiment_d/final_test/dataset_audit.json": "a0a22100cd0c6b923349aa6e899c2221b84d64991ca7e20b0626d811879d88c1",
        "reports/experiment_e/decision/e14_remediation_decision.json": "e5c11c39f7401fe89551d927b193978c59adc32bf7bb3052f619d225a595278e",
        "reports/experiment_f/preregistration/f0_preregistration.json": "dfc628b60bbd56ea0a78c4585ed28cfece2154b56fe101567b89e434e83d6cfb",
        "reports/experiment_f/amendments/f0_amendment_a1.json": "2116e1272ffc93dcaacfd105eb8f90afda10b2ccf5c2111ed2d2dd1179f6b95e",
        "reports/experiment_f/amendments/f0_composition_amendment_a2.json": "24840ecd9973e4028c0dd382da90d1a467f0190a654abcd2fbd50af9baed6afb",
        "reports/experiment_f/preflight/f1_a1_preflight_evidence.json": "a04fa37f5fccb32851d2a118316357d837aa7b61b1ad727b7a2e77a9711ddfd6",
        "reports/experiment_f/data_gates/f2_a1_extraction_data_gate.json": "5e45cb8bbf8d0857345843f3a28e05c5d173f350528c3bee6b797e04783f43e0",
        "reports/experiment_f/dataset_assembly/f3_a1_dataset_assembly_audit.json": "6dc316a4f27a39a4db81d3f0e787467236b2b4af42da87cacbb0524838464ee4",
        "reports/experiment_f/dataset_assembly/rf_v4_candidate_01_training_input_freeze.json": EXPECTED["freeze"],
    }
    integrity = {path: {"expected_sha256": expected, "actual_sha256": sha(ROOT / path), "match": sha(ROOT / path) == expected} for path, expected in integrity_paths.items()}
    require(all(item["match"] for item in integrity.values()), "post-training frozen integrity mismatch")
    audit = {
        "schema": "experiment_f_f3_a2_training_audit", "version": 1,
        "decision": "F3_A2_RF_V4_TRAINING_PASS", "validation_readiness": "F4_RF_V4_VALIDATION_READY",
        "candidate": {"model_id": "rf-v4.0-candidate-01", "status": "CANDIDATE / NOT_ACTIVE", "path": rel(MODEL), "sha256": model_sha, "metadata_path": rel(METADATA), "metadata_sha256": metadata_sha},
        "authorized_input": {"freeze_sha256": EXPECTED["freeze"], "dataset_sha256": EXPECTED["dataset"], "lineage_sha256": EXPECTED["lineage"], "rows": 6698, "class_counts": COUNTS},
        "preprocessing_verification": metadata["preprocessing"], "rf_parameters": params,
        "structural_audit": {"n_features_in": int(candidate.n_features_in_), "feature_names_in_match": True, "estimator_classes_actual_order": list(candidate.classes_), "tree_count": len(candidate.estimators_), "parameters_equal_rf_v3": True, "random_state": candidate.random_state, "status": "PASS"},
        "reproducibility": {"path": rel(REPRO), "sha256": repro_sha, "status": "PASS"},
        "frozen_integrity": {"artifacts": integrity, "status": "PASS"},
        "scientific_scope": metadata["scientific_scope"],
        "validation_data_used": False, "final_data_used": False, "training_set_performance_reported": False,
        "runtime_activation_performed": False, "promotion_performed": False,
    }
    json_new(AUDIT, audit)
    audit_sha = sha(AUDIT)
    summary = f"""# Experiment F3-A2 RF-v4 candidate training\n\nDecision: `F3_A2_RF_V4_TRAINING_PASS`. Validation readiness: `F4_RF_V4_VALIDATION_READY`.\n\nOne inactive candidate, `rf-v4.0-candidate-01`, was fitted on all 6,698 authorized rows using the exact RF-v3 preprocessing and Random Forest parameters. No split, tuning, cross-validation, validation/final inspection, runtime activation, or promotion occurred.\n\nThe estimator has 78 ordered features, 200 trees, class order `{list(candidate.classes_)}`, and random state 42. The independent repeat-fit matched fixed-subset predictions and probabilities, estimator random states, complete parameters, classes, and exact tree identity.\n\nThe additional Experiment F DDoS rows are controlled HTTP DDoS-like/load profiles under Amendment A1. Training success is not evidence of improved detection or generalization; validation is required.\n\nModel SHA256: `{model_sha}`. Metadata SHA256: `{metadata_sha}`. Reproducibility-audit SHA256: `{repro_sha}`. Training-audit SHA256: `{audit_sha}`.\n"""
    write_new(SUMMARY, summary)
    write_new(CHECKSUMS, "".join(f"{sha(p)}  {rel(p)}\n" for p in (MODEL, METADATA, AUDIT, REPRO, SUMMARY)))
    print(json.dumps({"decision": audit["decision"], "validation_readiness": audit["validation_readiness"], "model_sha256": model_sha, "metadata_sha256": metadata_sha, "audit_sha256": audit_sha, "reproducibility_sha256": repro_sha, "summary_sha256": sha(SUMMARY), "checksums_sha256": sha(CHECKSUMS), "fit_seconds": fit_seconds, "repeat_fit_seconds": repeat_seconds}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
