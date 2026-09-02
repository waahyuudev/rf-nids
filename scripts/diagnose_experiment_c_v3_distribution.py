#!/usr/bin/env python3
"""Diagnose Experiment C V3 feature distributions without inference or fitting."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from src.ingestion.cicflowmeter_v3_adapter import (
    ADAPTER_IDENTITY,
    ADAPTER_VERSION,
    CICFlowMeterV3ModelAdapter,
)


ROOT = Path(__file__).resolve().parents[1]
METADATA_PATH = ROOT / "models/model_metadata.json"
OUT_CSV = ROOT / "reports/tables/experiment_c_v3_distribution_diagnosis.csv"
OUT_JSON = ROOT / "reports/metrics/experiment_c_v3_distribution_diagnosis.json"
REFERENCE_DIR = ROOT / "data/raw/cicids2017"
SCENARIOS = {
    "Normal": {
        "path": ROOT / "data/lab/flows/cicflowmeter-v3/normal-http-test.pcap_ISCX.csv",
        "reference_label": "BENIGN",
    },
    "DDoS": {
        "path": ROOT / "data/lab/flows/cicflowmeter-v3/ddos-test.pcap_ISCX.csv",
        "reference_label": "DDoS",
    },
    "PortScan": {
        "path": ROOT / "data/lab/flows/cicflowmeter-v3/portscan-test.pcap_ISCX.csv",
        "reference_label": "PortScan",
    },
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def normalize_columns(columns: Any) -> list[str]:
    """Mirror validate_cicflowmeter_v3_compatibility.py exactly."""
    return [re.sub(r"\s+", "_", str(name).strip().lower().replace("/", "_")) for name in columns]


def json_number(value: Any) -> float | int | None:
    if value is None:
        return None
    result = float(value)
    return result if np.isfinite(result) else None


def empirical_ks(left: np.ndarray, right: np.ndarray) -> float | None:
    """Return max |F_left-F_right| directly from the two empirical CDFs."""
    if not len(left) or not len(right):
        return None
    left = np.sort(left)
    right = np.sort(right)
    support = np.concatenate((left, right))
    left_cdf = np.searchsorted(left, support, side="right") / len(left)
    right_cdf = np.searchsorted(right, support, side="right") / len(right)
    return float(np.max(np.abs(left_cdf - right_cdf)))


def describe(values: np.ndarray) -> dict[str, float | int | None]:
    finite = values[np.isfinite(values)]
    return {
        "finite_count": int(len(finite)),
        "mean": json_number(np.mean(finite)) if len(finite) else None,
        "median": json_number(np.median(finite)) if len(finite) else None,
        "std": json_number(np.std(finite)) if len(finite) else None,
        "min": json_number(np.min(finite)) if len(finite) else None,
        "max": json_number(np.max(finite)) if len(finite) else None,
    }


def reference_arrays(
    features: list[str], labels: list[str]
) -> tuple[dict[str, np.memmap], tempfile.TemporaryDirectory[str], list[dict[str, Any]]]:
    """Reuse the compatibility validator's released-data mapping and chunk logic."""
    paths = sorted(REFERENCE_DIR.glob("*.csv"))
    if not paths:
        raise FileNotFoundError(f"No CICIDS2017 released CSV files found in {REFERENCE_DIR}")

    counts = {label: 0 for label in labels}
    provenance: list[dict[str, Any]] = []
    for path in paths:
        provenance.append(
            {"path": relative(path), "size_bytes": path.stat().st_size, "sha256": sha256_file(path)}
        )
        for chunk in pd.read_csv(path, usecols=[" Label"], chunksize=200_000, low_memory=False):
            observed = chunk.iloc[:, 0].astype(str).str.strip()
            for label in labels:
                counts[label] += int((observed == label).sum())

    missing = [label for label, count in counts.items() if count == 0]
    if missing:
        raise ValueError(f"No released reference rows found for labels: {missing}")

    temporary = tempfile.TemporaryDirectory(prefix="rf_nids_experiment_c_v3_distribution_")
    arrays = {
        label: np.memmap(
            Path(temporary.name) / f"{label.lower()}.f32",
            mode="w+",
            dtype=np.float32,
            shape=(counts[label], len(features)),
        )
        for label in labels
    }
    offsets = {label: 0 for label in labels}
    for path in paths:
        for chunk in pd.read_csv(path, chunksize=100_000, low_memory=False):
            chunk.columns = normalize_columns(chunk.columns)
            observed = chunk["label"].astype(str).str.strip()
            # Identical to the validated reference path: ordered normalized model
            # columns, infinities to NaN, then float32. In particular, -1 remains -1.
            values = chunk[features].replace([np.inf, -np.inf], np.nan).to_numpy(dtype=np.float32)
            for label in labels:
                mask = (observed == label).to_numpy()
                count = int(mask.sum())
                start = offsets[label]
                arrays[label][start : start + count] = values[mask]
                offsets[label] += count
    for array in arrays.values():
        array.flush()
    return arrays, temporary, provenance


def feature_importances(
    metadata: dict[str, Any], features: list[str]
) -> tuple[dict[str, float] | None, dict[str, Any]]:
    """Read importances only from the hash-verified active fitted artifact."""
    model_path = Path(metadata.get("model_path", ""))
    if not model_path.is_absolute():
        model_path = ROOT / model_path
    expected_hash = metadata.get("model_sha256")
    try:
        actual_hash = sha256_file(model_path)
        if not expected_hash or actual_hash != expected_hash:
            raise ValueError("active model SHA256 does not match metadata")
        fitted = joblib.load(model_path)
        classifier = fitted.named_steps.get("classifier") if hasattr(fitted, "named_steps") else fitted
        raw = np.asarray(classifier.feature_importances_, dtype=float)
        if raw.shape != (len(features),) or not np.isfinite(raw).all():
            raise ValueError("feature_importances_ does not match the 78-feature schema")
        return dict(zip(features, map(float, raw))), {
            "available": True,
            "source": relative(model_path),
            "model_sha256_verified": True,
            "method": "fitted Random Forest feature_importances_",
        }
    except Exception as exc:  # Availability is optional; never infer or guess values.
        return None, {
            "available": False,
            "source": relative(model_path),
            "reason": f"{type(exc).__name__}: {exc}",
            "guessed": False,
        }


def main() -> None:
    existing = [path for path in (OUT_CSV, OUT_JSON) if path.exists()]
    if existing:
        raise SystemExit("refusing to overwrite: " + ", ".join(map(str, existing)))

    metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    features = metadata["feature_names"]
    if metadata.get("feature_count") != 78 or len(features) != 78:
        raise ValueError("Active metadata does not declare exactly 78 features")
    adapter = CICFlowMeterV3ModelAdapter.from_metadata(METADATA_PATH)

    adapted: dict[str, pd.DataFrame] = {}
    adapter_provenance: dict[str, Any] = {}
    input_records: dict[str, Any] = {}
    for scenario, specification in SCENARIOS.items():
        path = specification["path"]
        result = adapter.adapt_csv(path)
        if list(result.features.columns) != features:
            raise ValueError(f"{scenario} adapter output order differs from active metadata")
        adapted[scenario] = result.features
        adapter_provenance[scenario] = result.provenance
        input_records[scenario] = {
            "path": relative(path),
            "sha256": sha256_file(path),
            "reference_label": specification["reference_label"],
        }

    importance, importance_status = feature_importances(metadata, features)
    labels = list(dict.fromkeys(spec["reference_label"] for spec in SCENARIOS.values()))
    references, temporary, reference_files = reference_arrays(features, labels)
    rows: list[dict[str, Any]] = []
    try:
        for scenario, specification in SCENARIOS.items():
            lab = adapted[scenario]
            reference = references[specification["reference_label"]]
            for index, feature in enumerate(features):
                lab_values = lab[feature].to_numpy(dtype=float)
                reference_values = np.asarray(reference[:, index], dtype=float)
                lab_stats = describe(lab_values)
                reference_stats = describe(reference_values)
                ks = empirical_ks(
                    lab_values[np.isfinite(lab_values)],
                    reference_values[np.isfinite(reference_values)],
                )
                feature_importance = importance[feature] if importance is not None else None
                rows.append(
                    {
                        "scenario": scenario,
                        "reference_label": specification["reference_label"],
                        "feature_index": index,
                        "feature": feature,
                        "lab_row_count": int(len(lab_values)),
                        "reference_row_count": int(len(reference_values)),
                        "lab_finite_count": lab_stats["finite_count"],
                        "reference_finite_count": reference_stats["finite_count"],
                        "lab_mean": lab_stats["mean"],
                        "reference_mean": reference_stats["mean"],
                        "lab_median": lab_stats["median"],
                        "reference_median": reference_stats["median"],
                        "lab_std": lab_stats["std"],
                        "reference_std": reference_stats["std"],
                        "lab_min": lab_stats["min"],
                        "reference_min": reference_stats["min"],
                        "lab_max": lab_stats["max"],
                        "reference_max": reference_stats["max"],
                        "ks_statistic": ks,
                        "feature_importance": feature_importance,
                        "importance_times_ks": (
                            feature_importance * ks
                            if feature_importance is not None and ks is not None
                            else None
                        ),
                    }
                )
    finally:
        del references
        temporary.cleanup()

    table = pd.DataFrame(rows)
    summaries: dict[str, Any] = {}
    top_shifted: dict[str, Any] = {}
    high_importance_shift: dict[str, Any] = {}
    for scenario in SCENARIOS:
        subset = table[table["scenario"] == scenario]
        finite_ks = subset["ks_statistic"].dropna().to_numpy(dtype=float)
        ranked = subset.sort_values(
            ["ks_statistic", "feature_index"], ascending=[False, True], na_position="last"
        )
        summaries[scenario] = {
            "lab_row_count": int(subset["lab_row_count"].iloc[0]),
            "reference_label": SCENARIOS[scenario]["reference_label"],
            "reference_row_count": int(subset["reference_row_count"].iloc[0]),
            "feature_count": int(len(subset)),
            "features_with_ks_gte_0_9": int(np.sum(finite_ks >= 0.9)),
            "features_with_ks_gte_0_75": int(np.sum(finite_ks >= 0.75)),
            "features_with_ks_gte_0_5": int(np.sum(finite_ks >= 0.5)),
            "maximum_ks": json_number(np.max(finite_ks)) if len(finite_ks) else None,
            "median_ks": json_number(np.median(finite_ks)) if len(finite_ks) else None,
        }
        top_shifted[scenario] = ranked[["feature", "feature_index", "ks_statistic"]].head(20).to_dict("records")
        if importance is not None:
            diagnostic = subset.sort_values(
                ["importance_times_ks", "feature_index"],
                ascending=[False, True],
                na_position="last",
            )
            high_importance_shift[scenario] = diagnostic[
                ["feature", "feature_index", "feature_importance", "ks_statistic", "importance_times_ks"]
            ].head(20).to_dict("records")
        else:
            high_importance_shift[scenario] = []

    report = {
        "status": "completed",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Read-only feature-level distribution diagnosis; no inference, fitting, retraining, persistence, or dashboard update.",
        "model": {
            "version": metadata.get("model_version"),
            "sha256": metadata.get("model_sha256"),
            "metadata_path": relative(METADATA_PATH),
            "metadata_sha256": sha256_file(METADATA_PATH),
        },
        "adapter": {
            "identity": ADAPTER_IDENTITY,
            "version": ADAPTER_VERSION,
            "feature_count": len(features),
            "exact_ordered_features": features,
            "scenario_provenance": adapter_provenance,
        },
        "inputs": input_records,
        "reference_dataset_provenance": {
            "dataset": "CICIDS2017 released MachineLearningCSV data",
            "directory": relative(REFERENCE_DIR),
            "files": reference_files,
            "selection": {scenario: spec["reference_label"] for scenario, spec in SCENARIOS.items()},
            "mapping_and_preprocessing": "Reuses validate_cicflowmeter_v3_compatibility.py: whitespace/lowercase/slash normalization, active ordered feature names, +/-Infinity to NaN, float32; -1 is preserved.",
        },
        "per_scenario_summary": summaries,
        "top_shifted_features": top_shifted,
        "feature_importance_availability": importance_status,
        "high_importance_high_shift_diagnostics": {
            "score": "feature_importance * empirical_KS",
            "interpretation": "Diagnostic ranking only; it is not causal proof.",
            "rankings": high_importance_shift,
        },
        "outputs": {"table": relative(OUT_CSV), "metrics": relative(OUT_JSON)},
        "limitations": [
            "Empirical KS is descriptive evidence of covariate/distribution shift; it does not establish that a shifted feature caused a prediction failure.",
            "KS is univariate and does not describe interactions or joint feature distributions.",
            "Only finite values enter descriptive statistics and empirical CDFs; row and finite counts are reported separately.",
            "The reference labels are released CICIDS2017 labels and the laboratory captures may differ in environment, duration, flow construction, and sample size.",
            "No KS p-values are calculated or reported.",
        ],
    }

    # Recheck immediately before writing so completed reports are never replaced.
    existing = [path for path in (OUT_CSV, OUT_JSON) if path.exists()]
    if existing:
        raise SystemExit("refusing to overwrite: " + ", ".join(map(str, existing)))
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("x", encoding="utf-8", newline="") as stream:
        table.to_csv(stream, index=False)
    with OUT_JSON.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")


if __name__ == "__main__":
    main()
