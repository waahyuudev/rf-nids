"""Complete the authorized read-only Experiment C external evaluation."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from src.inference.predictor import InferenceEngine
from src.ingestion.cicflowmeter_v3_adapter import (
    ADAPTER_IDENTITY,
    CICFLOWMETER_V3_COMMIT,
    CICFLOWMETER_V3_IMAGE_DIGEST,
    CICFlowMeterV3ModelAdapter,
    MAPPING_RULES,
)
from src.preprocessing.columns import normalize_columns


ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "models/random_forest_active.joblib"
METADATA = ROOT / "models/model_metadata.json"
INPUT = ROOT / "data/lab/flows/cicflowmeter-v3/ddos-test.pcap_ISCX.csv"
PRIOR = ROOT / "reports/metrics/experiment_c_v3_inference.json"
COMPARISON = ROOT / "reports/metrics/validation_comparison.json"
TRAINING_DDOS = ROOT / "data/raw/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
IMPORTANCE = ROOT / "reports/metrics/tuned_feature_importance.csv"
OUT_JSON = ROOT / "reports/metrics/experiment_c_final.json"
OUT_PREDICTIONS = ROOT / "reports/tables/experiment_c_v3_ddos_predictions.csv"
OUT_CONFUSION = ROOT / "reports/tables/experiment_c_final_confusion_matrix.csv"
OUT_CLASSES = ROOT / "reports/tables/experiment_c_final_class_metrics.csv"
OUT_COMPARISON = ROOT / "reports/tables/experiment_a_b_c_comparison.csv"
CLASSES = ["Normal", "DDoS", "PortScan"]


def summary(values: pd.Series) -> dict[str, float]:
    return {
        "mean": float(values.mean()),
        "median": float(values.median()),
        "std": float(values.std(ddof=0)),
        "min": float(values.min()),
        "p05": float(values.quantile(0.05)),
        "p95": float(values.quantile(0.95)),
        "max": float(values.max()),
    }


def ks_statistic(left_values: np.ndarray, right_values: np.ndarray) -> float | None:
    left = np.sort(left_values[np.isfinite(left_values)])
    right = np.sort(right_values[np.isfinite(right_values)])
    if not len(left) or not len(right):
        return None
    support = np.concatenate((left, right))
    left_cdf = np.searchsorted(left, support, side="right") / len(left)
    right_cdf = np.searchsorted(right, support, side="right") / len(right)
    return float(np.max(np.abs(left_cdf - right_cdf)))


def distribution_shift(lab: pd.DataFrame) -> tuple[list[dict[str, Any]], float]:
    ranked = pd.read_csv(IMPORTANCE).head(20)
    wanted = ranked["feature"].tolist()
    released_parts: list[pd.DataFrame] = []
    for chunk in pd.read_csv(TRAINING_DDOS, chunksize=100_000, low_memory=False):
        chunk.columns = normalize_columns(chunk.columns)
        selected = chunk.loc[chunk["label"].astype(str).str.strip() == "DDoS", wanted]
        released_parts.append(selected.replace([np.inf, -np.inf], np.nan).astype(np.float32))
    released = pd.concat(released_parts, ignore_index=True)
    rows: list[dict[str, Any]] = []
    for record in ranked.to_dict(orient="records"):
        feature = str(record["feature"])
        training = released[feature].to_numpy(dtype=float)
        external = lab[feature].to_numpy(dtype=float)
        ks = ks_statistic(training, external)
        rows.append({
            "feature": feature,
            "model_importance": float(record["importance"]),
            "cicids2017_ddos_finite_count": int(np.isfinite(training).sum()),
            "ddos_like_v3_finite_count": int(np.isfinite(external).sum()),
            "ks_statistic": ks,
        })
    rows.sort(key=lambda row: -1.0 if row["ks_statistic"] is None else row["ks_statistic"], reverse=True)
    return rows, max(float(row["ks_statistic"]) for row in rows if row["ks_statistic"] is not None)


def main() -> None:
    raw = pd.read_csv(INPUT)
    if raw.shape != (10226, 84):
        raise RuntimeError(f"Raw input shape differs from required (10226, 84): {raw.shape}")
    if int(raw.duplicated().sum()) != 0:
        raise RuntimeError("Raw input contains duplicate rows")

    engine = InferenceEngine(MODEL, METADATA)
    adapter = CICFlowMeterV3ModelAdapter.from_metadata(METADATA)
    adaptation = adapter.adapt_csv(INPUT)
    features = adaptation.features
    if features.shape != (10226, 78):
        raise RuntimeError(f"Adapter output shape differs from required (10226, 78): {features.shape}")
    if list(features.columns) != engine.feature_names:
        raise RuntimeError("Adapter feature order differs from active model metadata")
    if features.columns.duplicated().any():
        raise RuntimeError("Adapter output contains duplicate features")
    raw_required = [source for _, source, _ in MAPPING_RULES]
    raw_null_values = int(raw[list(dict.fromkeys(raw_required))].isna().sum().sum())
    prepared = engine.model[:-1].transform(features)
    prepared_missing = int(np.isnan(np.asarray(prepared, dtype=float)).sum())
    if prepared_missing:
        raise RuntimeError(f"Fitted training-equivalent preprocessing left {prepared_missing} missing values")

    predictions: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for row_number, (_, row) in enumerate(features.iterrows(), start=1):
        try:
            predictions.append(engine.predict_one(row.to_dict()))
        except Exception as exc:
            failures.append({"flow_row_number": row_number, "error": str(exc)})
    if failures:
        raise RuntimeError(f"{len(failures)} inference operations failed: {failures[:3]}")

    table = pd.DataFrame({
        "flow_row_number": np.arange(1, len(raw) + 1),
        "ground_truth": "DDoS",
        "predicted_label": [row["prediction"] for row in predictions],
        "confidence": [row["confidence"] for row in predictions],
        "P_Normal": [row["probabilities"]["Normal"] for row in predictions],
        "P_DDoS": [row["probabilities"]["DDoS"] for row in predictions],
        "P_PortScan": [row["probabilities"]["PortScan"] for row in predictions],
        "source_ip": raw["Src IP"].to_numpy(),
        "destination_ip": raw["Dst IP"].to_numpy(),
        "source_port": raw["Src Port"].to_numpy(),
        "destination_port": raw["Dst Port"].to_numpy(),
    })
    counts = {label: int(Counter(table["predicted_label"])[label]) for label in CLASSES}
    probabilities = {label: summary(table[f"P_{label}"]) for label in CLASSES}
    top_columns = ["flow_row_number", "source_ip", "destination_ip", "source_port", "destination_port", "predicted_label", "confidence", "P_Normal", "P_DDoS", "P_PortScan"]
    top20 = table.nlargest(20, "P_DDoS")[top_columns].rename(columns={"predicted_label": "predicted_class"})

    prior = json.loads(PRIOR.read_text(encoding="utf-8"))
    normal_counts = prior["normal"]["predictions"]
    portscan_counts = prior["portscan"]["predictions"]
    matrix = np.array([
        [normal_counts[label] for label in CLASSES],
        [counts[label] for label in CLASSES],
        [portscan_counts[label] for label in CLASSES],
    ], dtype=int)
    actual = ["Normal"] * 61 + ["DDoS"] * 10226 + ["PortScan"] * 1000
    predicted = (
        sum(([label] * normal_counts[label] for label in CLASSES), [])
        + table["predicted_label"].tolist()
        + sum(([label] * portscan_counts[label] for label in CLASSES), [])
    )
    if not np.array_equal(confusion_matrix(actual, predicted, labels=CLASSES), matrix):
        raise RuntimeError("Final confusion matrix consistency check failed")
    metrics = classification_report(actual, predicted, labels=CLASSES, output_dict=True, zero_division=0)
    class_rows = [{
        "class": label,
        "precision": float(metrics[label]["precision"]),
        "recall": float(metrics[label]["recall"]),
        "f1": float(metrics[label]["f1-score"]),
        "support": int(metrics[label]["support"]),
    } for label in CLASSES]
    overall = {
        "accuracy": float(metrics["accuracy"]),
        "macro_precision": float(metrics["macro avg"]["precision"]),
        "macro_recall": float(metrics["macro avg"]["recall"]),
        "macro_f1": float(metrics["macro avg"]["f1-score"]),
        "weighted_precision": float(metrics["weighted avg"]["precision"]),
        "weighted_recall": float(metrics["weighted avg"]["recall"]),
        "weighted_f1": float(metrics["weighted avg"]["f1-score"]),
    }
    normal_fp = int(normal_counts["DDoS"] + normal_counts["PortScan"])
    attack_detected = int(matrix[1, 1] + matrix[1, 2] + matrix[2, 1] + matrix[2, 2])
    attack_total = 10226 + 1000
    overall["controlled_normal_candidate_false_positive_rate"] = normal_fp / 61
    overall["attack_detection_rate"] = attack_detected / attack_total
    overall["attack_detection_numerator"] = attack_detected
    overall["attack_detection_denominator"] = attack_total

    shift_rows, ddos_max_ks = distribution_shift(features)
    ab = json.loads(COMPARISON.read_text(encoding="utf-8"))
    comparison_rows = [
        {"experiment": "A", "purpose": "in-dataset stratified/random evaluation", **ab["experiment_a"]},
        {"experiment": "B", "purpose": "scenario/ordered CICIDS2017 validation", **ab["experiment_b"]},
        {"experiment": "C", "purpose": "external controlled virtual laboratory validation", "accuracy": overall["accuracy"], "macro_f1": overall["macro_f1"], "normal_recall": class_rows[0]["recall"], "ddos_recall": class_rows[1]["recall"], "portscan_recall": class_rows[2]["recall"]},
    ]

    report = {
        "status": "COMPLETED",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Experiment C flow-level external validation using controlled Normal, PortScan, and single-source high-rate HTTP DoS-like traffic. DDoS is the expected model class; the lab traffic itself is not claimed to be distributed.",
        "validation": {
            "input_rows": len(raw), "output_rows": len(features), "features": features.shape[1],
            "raw_required_null_values": raw_null_values,
            "model_ready_missing_values": prepared_missing,
            "raw_duplicate_rows": int(raw.duplicated().sum()),
            "feature_order_matches_active_model_metadata": True,
            "non_finite_preparation": adaptation.provenance["non_finite_before"],
            "non_finite_after_preparation": adaptation.provenance["non_finite_after"],
        },
        "extractor": {"name": "CICFlowMeter V3", "commit": CICFLOWMETER_V3_COMMIT, "image_digest": CICFLOWMETER_V3_IMAGE_DIGEST},
        "adapter": {"identity": ADAPTER_IDENTITY, "feature_count": 78},
        "model": {"artifact": "models/random_forest_active.joblib", "sha256": engine.metadata["model_sha256"], "fitted_pipeline_reused": True, "fitting_performed": False},
        "scenarios": {
            "normal": prior["normal"],
            "portscan": prior["portscan"],
            "controlled_ddos_like": {"ground_truth_expected_model_class": "DDoS", "traffic_description": "controlled high-rate HTTP DoS-like traffic from one attacking VM", "total": len(table), "successful_inference": len(table), "failed_inference": 0, "predictions": counts, "ddos_to_ddos": counts["DDoS"], "ddos_to_normal": counts["Normal"], "ddos_to_portscan": counts["PortScan"], "ddos_recall": counts["DDoS"] / len(table), "probability_summary": probabilities},
        },
        "highest_ddos_probability_flows": top20.to_dict(orient="records"),
        "final_confusion_matrix": {"actual_rows": CLASSES, "predicted_columns": CLASSES, "values": matrix.tolist()},
        "final_metrics": {**overall, "per_class": {row["class"]: row for row in class_rows}, "zero_division": 0, "note": "Undefined class metrics use sklearn zero_division=0."},
        "experiment_a_b_c_comparison": {"comparison_type": "descriptive_only", "warning": "Experiments A, B, and C have different distributions and purposes and are not statistically equivalent.", "rows": comparison_rows},
        "distribution_shift": {"normal_max_ks_approx": 0.796064, "portscan_max_ks_approx": 0.996533, "ddos_like_max_ks": ddos_max_ks, "scope": "top 20 active-model features ranked by tuned feature importance", "largest_shifted_features": shift_rows, "interpretation": "External distribution shift after semantic compatibility passed; KS is not treated as semantic incompatibility."},
        "inference_failures": [],
        "database_persistence": "NOT_PERFORMED",
        "dashboard_update": "NOT_PERFORMED",
        "limitations": [
            "The DDoS-like scenario uses one attacking VM, not a distributed botnet.",
            "External lab traffic differs substantially from CICIDS2017.",
            "Flow-level labels are assigned from controlled scenario context.",
            "The exact historical binary used to generate CICIDS2017 is not known, although an official V3 commit with compatible semantics was pinned.",
            "The virtual lab is controlled and not representative of production enterprise traffic.",
            "Experiment C measures external generalization, not training accuracy.",
        ],
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_PREDICTIONS.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(OUT_PREDICTIONS, index=False)
    pd.DataFrame(matrix, index=[f"Actual {x}" for x in CLASSES], columns=[f"Predicted {x}" for x in CLASSES]).to_csv(OUT_CONFUSION, index_label="actual_class")
    pd.DataFrame(class_rows).to_csv(OUT_CLASSES, index=False)
    pd.DataFrame(comparison_rows).to_csv(OUT_COMPARISON, index=False)
    OUT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("Experiment C — Final External Validation")
    print("=========================================")
    for title, total, values, recall in (("Normal", 61, normal_counts, normal_counts["Normal"] / 61), ("PortScan", 1000, portscan_counts, portscan_counts["PortScan"] / 1000)):
        print(f"\n{title}\n" + "-" * len(title))
        print(f"Flows: {total}\nPredicted Normal: {values['Normal']}\nPredicted DDoS: {values['DDoS']}\nPredicted PortScan: {values['PortScan']}\nRecall: {recall:.6f}")
        if title == "Normal": print(f"Candidate FPR: {normal_fp / 61:.6f}")
    print(f"\nControlled DDoS-like\n--------------------\nFlows: {len(table)}\nPredicted Normal: {counts['Normal']}\nPredicted DDoS: {counts['DDoS']}\nPredicted PortScan: {counts['PortScan']}\nDDoS recall: {counts['DDoS'] / len(table):.6f}")
    print(f"\nDDoS probability\n----------------\nMean: {probabilities['DDoS']['mean']:.6f}\nMedian: {probabilities['DDoS']['median']:.6f}\nP95: {probabilities['DDoS']['p95']:.6f}\nMax: {probabilities['DDoS']['max']:.6f}")
    print("\nFinal confusion matrix\n----------------------")
    print(pd.DataFrame(matrix, index=CLASSES, columns=CLASSES).to_string())
    print(f"\nFinal metrics\n-------------\nAccuracy: {overall['accuracy']:.6f}\nMacro Precision: {overall['macro_precision']:.6f}\nMacro Recall: {overall['macro_recall']:.6f}\nMacro F1: {overall['macro_f1']:.6f}\nWeighted F1: {overall['weighted_f1']:.6f}")
    print(f"\nPer-class recall:\nNormal: {class_rows[0]['recall']:.6f}\nDDoS: {class_rows[1]['recall']:.6f}\nPortScan: {class_rows[2]['recall']:.6f}\n\nAttack detection rate: {overall['attack_detection_rate']:.6f} ({attack_detected}/{attack_total})")
    print(f"\nExperiment A vs B vs C\n----------------------\nA Accuracy: {comparison_rows[0]['accuracy']:.6f}\nA Macro F1: {comparison_rows[0]['macro_f1']:.6f}\n\nB Accuracy: {comparison_rows[1]['accuracy']:.6f}\nB Macro F1: {comparison_rows[1]['macro_f1']:.6f}\n\nC Accuracy: {overall['accuracy']:.6f}\nC Macro F1: {overall['macro_f1']:.6f}")
    print(f"\nDistribution shift\n------------------\nNormal max KS: 0.796064\nPortScan max KS: 0.996533\nDDoS-like max KS: {ddos_max_ks:.6f}")
    print("\nInference failures: 0\n\nDatabase persistence:\nNOT_PERFORMED\n\nDashboard:\nNOT_PERFORMED\n\nFinal Experiment C status:\nCOMPLETED")
    print("\nScientific conclusion:")
    print("The active model's controlled-lab results quantify external generalization under substantial distribution shift. The DDoS-like scenario is single-source high-rate HTTP traffic evaluated against the DDoS model class, not evidence of a distributed attack.")


if __name__ == "__main__":
    main()
