#!/usr/bin/env python3
"""Recover and evaluate the original rf-v1.0 holdout without fitting."""

from __future__ import annotations

import hashlib
import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from src.common.config import PROJECT_ROOT
from src.common.hashing import sha256_file
from src.preprocessing.columns import normalize_columns
from src.preprocessing.labels import CLASS_NAMES, map_label

ROOT = PROJECT_ROOT
MODEL = ROOT / "models/random_forest_active.joblib"
METADATA = ROOT / "models/model_metadata.json"
TUNED = ROOT / "reports/metrics/tuned_metrics.json"
AUDIT = ROOT / "reports/metrics/rf_v1_training_reproducibility_audit.json"
OUT_JSON = ROOT / "reports/metrics/rf_v1_cicids2017_holdout_evaluation_recovered.json"
OUT_CSV = ROOT / "reports/tables/rf_v1_cicids2017_holdout_predictions_recovered.csv"
VALID = "VALID_ORIGINAL_HOLDOUT_EVALUATION"
NOT_RECOVERABLE = "ORIGINAL_HOLDOUT_NOT_RECOVERABLE"
EXACT_MATCH = "EXACT_MATCH"
PREDICTION_MISMATCH = "PREDICTION_MISMATCH"
SOURCE_COMMIT = "4ed28d2be422e73e0755f80b81abe8d979fd1532"
MODEL_HASH = "73d86cb98f35c228d6e619e0f746a2b659d94deabe86d57e801c58bcf935f647"
MANIFEST_HASH = "85b8ebc7a54343204772cc25b75e8bcd5c739d87c45ffa9f1a9d829fd309251f"
EXPECTED_ROWS = 2_315_319
EXPECTED_TRAIN = 1_852_255
EXPECTED_TEST = 463_064
EXPECTED_TEST_CLASSES = {"Normal": 419_297, "DDoS": 25_603, "PortScan": 18_164}
EXPECTED_CONFUSION_MATRIX = [[419_110, 5, 182], [3, 25_600, 0], [6, 0, 18_158]]
EXPECTED_ACCURACY = 0.9995767323739267
EXPECTED_MACRO_RECALL = 0.9997021726418561
EXPECTED_MACRO_F1 = 0.9981532932369657
LABELS = list(CLASS_NAMES)
BATCH_SIZE = 50_000


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def refuse_overwrite() -> None:
    existing = [str(path) for path in (OUT_JSON, OUT_CSV) if path.exists()]
    if existing:
        raise SystemExit("refusing to overwrite: " + ", ".join(existing))


def historical_identity(recorded_paths: list[str], access_paths: list[Path]) -> dict[str, Any]:
    """Hash recorded relative path text while accessing files by absolute path."""
    if len(recorded_paths) != len(access_paths):
        raise ValueError("recorded/access path counts differ")
    files: list[dict[str, Any]] = []
    manifest = hashlib.sha256()
    for recorded, access in zip(recorded_paths, access_paths, strict=True):
        item = {"path": recorded, "size_bytes": access.stat().st_size, "sha256": sha256_file(access)}
        files.append(item)
        manifest.update(
            f"{recorded}\0{item['size_bytes']}\0{item['sha256']}\n".encode("utf-8")
        )
    return {"algorithm": "sha256", "manifest_sha256": manifest.hexdigest(), "files": files}


def verify_integrity(metadata: dict[str, Any], tuned: dict[str, Any]) -> tuple[list[Path], dict[str, Any]]:
    """Verify count, order, path spelling, size, hashes, manifest, and model."""
    failures: list[str] = []
    recorded_paths = tuned.get("dataset_paths")
    if not isinstance(recorded_paths, list) or not all(isinstance(path, str) for path in recorded_paths):
        raise ValueError("dataset_paths must be a list of strings")
    access_paths = [ROOT / path for path in recorded_paths]
    if len(recorded_paths) != 8:
        failures.append(f"file count {len(recorded_paths)} != 8")
    missing = [path for path, access in zip(recorded_paths, access_paths) if not access.is_file()]
    if missing:
        failures.append(f"missing files: {missing}")
    recorded_identity = tuned.get("dataset_identity", {})
    recorded_files = recorded_identity.get("files", [])
    if len(recorded_files) != len(recorded_paths):
        failures.append("identity file count differs from dataset_paths")
    observed = historical_identity(recorded_paths, access_paths) if not missing else None
    if observed:
        for index, (path, actual, expected) in enumerate(
            zip(recorded_paths, observed["files"], recorded_files, strict=False)
        ):
            if expected.get("path") != path:
                failures.append(f"ordered path mismatch at index {index}")
            if expected.get("size_bytes") != actual["size_bytes"]:
                failures.append(f"size mismatch: {path}")
            if expected.get("sha256") != actual["sha256"]:
                failures.append(f"SHA-256 mismatch: {path}")
        if observed["manifest_sha256"] != recorded_identity.get("manifest_sha256"):
            failures.append("relative-path historical manifest mismatch")
        if observed["manifest_sha256"] != MANIFEST_HASH:
            failures.append("manifest differs from audited rf-v1.0 identity")
    if metadata.get("dataset_identity") != recorded_identity:
        failures.append("metadata and tuned dataset identities differ")
    if metadata.get("model_version") != "rf-v1.0" or metadata.get("selected_experiment") != "tuned":
        failures.append("active metadata does not identify tuned rf-v1.0")
    historical_metrics = tuned.get("metrics", {})
    expected_historical = {
        "confusion_matrix": EXPECTED_CONFUSION_MATRIX,
        "accuracy": EXPECTED_ACCURACY,
        "macro_recall": EXPECTED_MACRO_RECALL,
        "macro_f1": EXPECTED_MACRO_F1,
    }
    if any(historical_metrics.get(key) != value for key, value in expected_historical.items()):
        failures.append("tuned_metrics historical reference values differ from rf-v1.0")
    actual_model_hash = sha256_file(MODEL)
    if actual_model_hash != MODEL_HASH or metadata.get("model_sha256") != actual_model_hash:
        failures.append("active model hash mismatch")
    if failures:
        raise ValueError("; ".join(failures))
    return access_paths, {
        "file_count": 8,
        "ordered_paths_verified": True,
        "file_sizes_verified": True,
        "per_file_sha256_verified": True,
        "historical_relative_path_manifest_verified": True,
        "identity": observed,
        "model_sha256": actual_model_hash,
    }


def reconstruct(paths: list[Path], feature_names: list[str]) -> tuple[pd.DataFrame, pd.Series, dict[str, Any]]:
    """Apply the exact historical loader, preparation, and split recipe."""
    frames: list[pd.DataFrame] = []
    schemas: list[list[str]] = []
    for path in paths:
        frame = pd.read_csv(path, low_memory=False)
        frames.append(frame)
        schemas.append(normalize_columns(frame.columns))
    if any(schema != schemas[0] for schema in schemas[1:]):
        raise ValueError("normalized CSV schemas differ")
    data = pd.concat(frames, ignore_index=True)
    data.columns = schemas[0]
    del frames
    mapped = data["label"].map(map_label)
    retained = mapped.notna()
    data = data.loc[retained].copy()
    data["label"] = mapped.loc[retained]
    data = data.drop_duplicates().reset_index(drop=True)
    labels = data["label"].astype(str)
    if len(data) != EXPECTED_ROWS:
        raise ValueError(f"deduplicated rows {len(data)} != {EXPECTED_ROWS}")
    if len(feature_names) != 78 or len(set(feature_names)) != 78:
        raise ValueError("recorded feature list is not exactly 78 unique names")
    numeric_order = list(
        data[[column for column in data.columns if column != "label"]]
        .select_dtypes(include=["number"])
        .columns
    )
    if numeric_order != feature_names:
        raise ValueError("historical numeric feature order differs from recorded feature order")
    features = data.loc[:, feature_names].replace([np.inf, -np.inf], np.nan).astype(np.float32)
    train_indices, test_indices = train_test_split(
        np.arange(len(data)), test_size=0.2, random_state=42, stratify=labels
    )
    if len(train_indices) != EXPECTED_TRAIN or len(test_indices) != EXPECTED_TEST:
        raise ValueError(
            f"split counts train={len(train_indices)} test={len(test_indices)}; "
            f"expected {EXPECTED_TRAIN}/{EXPECTED_TEST}"
        )
    x_test = features.iloc[test_indices].reset_index(drop=True)
    y_test = labels.iloc[test_indices].reset_index(drop=True)
    distribution = {label: int((y_test == label).sum()) for label in LABELS}
    if distribution != EXPECTED_TEST_CLASSES:
        raise ValueError(f"test distribution {distribution} != {EXPECTED_TEST_CLASSES}")
    split = {
        "rows_after_filtering_and_deduplication": len(data),
        "train_rows": len(train_indices),
        "test_rows": len(test_indices),
        "test_distribution": distribution,
        "test_size": 0.2,
        "random_state": 42,
        "stratified": True,
        "feature_order_verified": list(x_test.columns) == feature_names,
        "dtype_verified_float32": all(dtype == np.dtype("float32") for dtype in x_test.dtypes),
    }
    return x_test, y_test, split


def batch_predict(model: Pipeline, x_test: pd.DataFrame, y_test: pd.Series) -> tuple[pd.DataFrame, int, float]:
    """Use the existing fitted pipeline in efficient, scientifically equivalent batches."""
    classes = [str(value) for value in model.classes_]
    if set(classes) != set(LABELS):
        raise ValueError(f"unexpected model classes: {classes}")
    class_index = {label: classes.index(label) for label in LABELS}
    chunks: list[pd.DataFrame] = []
    failures = 0
    started = time.perf_counter()
    for start in range(0, len(x_test), BATCH_SIZE):
        stop = min(start + BATCH_SIZE, len(x_test))
        batch = x_test.iloc[start:stop]
        try:
            predicted = model.predict(batch)
            probabilities = model.predict_proba(batch)
            chunk = pd.DataFrame({
                "evaluation_row": np.arange(start, stop),
                "actual_class": y_test.iloc[start:stop].to_numpy(),
                "predicted_class": predicted,
                "probability_normal": probabilities[:, class_index["Normal"]],
                "probability_ddos": probabilities[:, class_index["DDoS"]],
                "probability_portscan": probabilities[:, class_index["PortScan"]],
                "inference_status": "SUCCESS",
                "failure": None,
            })
        except Exception as exc:
            failures += len(batch)
            chunk = pd.DataFrame({
                "evaluation_row": np.arange(start, stop),
                "actual_class": y_test.iloc[start:stop].to_numpy(),
                "predicted_class": None,
                "probability_normal": np.nan,
                "probability_ddos": np.nan,
                "probability_portscan": np.nan,
                "inference_status": "FAILED",
                "failure": f"{type(exc).__name__}: {exc}",
            })
        chunks.append(chunk)
    return pd.concat(chunks, ignore_index=True), failures, time.perf_counter() - started


def metrics_for(predictions: pd.DataFrame) -> dict[str, Any]:
    successful = predictions[predictions["inference_status"] == "SUCCESS"]
    true = successful["actual_class"]
    predicted = successful["predicted_class"]
    matrix = confusion_matrix(true, predicted, labels=LABELS)
    precision, recall, f1, support = precision_recall_fscore_support(
        true, predicted, labels=LABELS, average=None, zero_division=0
    )
    macro = precision_recall_fscore_support(
        true, predicted, labels=LABELS, average="macro", zero_division=0
    )
    weighted = precision_recall_fscore_support(
        true, predicted, labels=LABELS, average="weighted", zero_division=0
    )
    normal_total = int((true == "Normal").sum())
    normal_attack = int(((true == "Normal") & (predicted != "Normal")).sum())
    return {
        "confusion_matrix": matrix.tolist(),
        "confusion_matrix_labels": LABELS,
        "accuracy": float(accuracy_score(true, predicted)),
        "per_class": {
            label: {"precision": float(precision[i]), "recall": float(recall[i]),
                    "f1": float(f1[i]), "support": int(support[i])}
            for i, label in enumerate(LABELS)
        },
        "macro_precision": float(macro[0]),
        "macro_recall": float(macro[1]),
        "macro_f1": float(macro[2]),
        "weighted_f1": float(weighted[2]),
        "normal_attack_false_positive_rate": normal_attack / normal_total,
        "normal_rows_predicted_as_attack": normal_attack,
        "total_evaluated_rows": int(len(successful)),
    }


def compare_history(reproduced: dict[str, Any], tuned: dict[str, Any]) -> dict[str, Any]:
    source = tuned["metrics"]
    historical = {
        "confusion_matrix": source["confusion_matrix"],
        "accuracy": source["accuracy"],
        "macro_precision": source["macro_precision"],
        "macro_recall": source["macro_recall"],
        "macro_f1": source["macro_f1"],
        "weighted_f1": source["weighted_f1"],
        "normal_attack_false_positive_rate": (
            source["ids_error_counts"]["normal_predicted_as_attack"]
            / source["classification_report"]["Normal"]["support"]
        ),
        "total_evaluated_rows": int(source["classification_report"]["macro avg"]["support"]),
        "per_class": {
            label: {
                "precision": source["classification_report"][label]["precision"],
                "recall": source["classification_report"][label]["recall"],
                "f1": source["classification_report"][label]["f1-score"],
                "support": int(source["classification_report"][label]["support"]),
            } for label in LABELS
        },
    }
    differences: dict[str, Any] = {
        key: reproduced[key] - historical[key]
        for key in (
            "accuracy", "macro_precision", "macro_recall", "macro_f1", "weighted_f1",
            "normal_attack_false_positive_rate", "total_evaluated_rows",
        )
    }
    differences["confusion_matrix"] = (
        np.asarray(reproduced["confusion_matrix"]) - np.asarray(historical["confusion_matrix"])
    ).tolist()
    for label in LABELS:
        for metric in ("precision", "recall", "f1", "support"):
            differences[f"{label}.{metric}"] = (
                reproduced["per_class"][label][metric] - historical["per_class"][label][metric]
            )
    zero_matrix = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
    exact = differences["confusion_matrix"] == zero_matrix and all(
        value == 0 for key, value in differences.items() if key != "confusion_matrix"
    )
    return {"exact_match": exact, "historical": historical, "differences": differences}


def write_abort(reason: str, evidence: dict[str, Any]) -> None:
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with OUT_JSON.open("x", encoding="utf-8") as stream:
        json.dump({
            "status": NOT_RECOVERABLE,
            "holdout_reproduction": "NOT_EVALUATED",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "evaluation_performed": False,
            "fit_or_refit_performed": False,
            "reason": reason,
            "evidence_collected_before_abort": evidence,
        }, stream, indent=2, allow_nan=False)
        stream.write("\n")


def main() -> None:
    refuse_overwrite()
    evidence: dict[str, Any] = {}
    try:
        metadata, tuned, audit = read_json(METADATA), read_json(TUNED), read_json(AUDIT)
        if audit.get("exact_mismatch_diagnosis", {}).get("status") != "FALSE_NEGATIVE_IDENTITY_CHECK":
            raise ValueError("audit does not confirm the false-negative identity diagnosis")
        paths, provenance = verify_integrity(metadata, tuned)
        evidence["provenance"] = provenance
        features = metadata.get("feature_names")
        if not isinstance(features, list) or features != tuned["preprocessing"]["feature_names"]:
            raise ValueError("metadata and tuned feature orders differ")
        x_test, y_test, split = reconstruct(paths, features)
        evidence["split"] = split
        model = joblib.load(MODEL)
        if not isinstance(model, Pipeline):
            raise ValueError("active model is not a fitted Pipeline")
        if list(getattr(model, "feature_names_in_", [])) != features:
            raise ValueError("fitted model feature order differs from metadata")
        predictions, failures, seconds = batch_predict(model, x_test, y_test)
        scores = metrics_for(predictions)
        scores.update({"attempted_rows": len(predictions), "inference_failures": failures,
                       "total_inference_time_seconds": seconds})
        comparison = compare_history(scores, tuned)
        exact = comparison["exact_match"] and failures == 0
        report = {
            "status": VALID if exact else "ORIGINAL_HOLDOUT_EVALUATION_PREDICTION_MISMATCH",
            "holdout_reproduction": EXACT_MATCH if exact else PREDICTION_MISMATCH,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "evaluation_performed": True,
            "fit_or_refit_performed": False,
            "model": {"version": "rf-v1.0", "path": "models/random_forest_active.joblib",
                      "sha256": provenance["model_sha256"], "hash_verified": True},
            "dataset": provenance,
            "historical_source_commit": SOURCE_COMMIT,
            "runtime": {"python_version": platform.python_version(),
                        "scikit_learn_version": sklearn.__version__,
                        "recorded_python_version": tuned.get("python_version"),
                        "recorded_scikit_learn_version": tuned.get("scikit_learn_version")},
            "reconstructed_split": split,
            "feature_order_verification": {"verified": True, "count": 78,
                                           "ordered_features": features},
            "prediction_execution": {"method": "batch predict/predict_proba through fitted pipeline",
                                     "batch_size": BATCH_SIZE, "fit_calls": 0},
            "metrics": scores,
            "historical_metrics_comparison": comparison,
        }
    except Exception as exc:
        write_abort(f"{type(exc).__name__}: {exc}", evidence)
        return
    refuse_overwrite()
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("x", encoding="utf-8", newline="") as stream:
        predictions.to_csv(stream, index=False)
    with OUT_JSON.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")


if __name__ == "__main__":
    main()
