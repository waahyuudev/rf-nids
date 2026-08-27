"""Run the authorized, read-only Experiment C CICFlowMeter V3 inference."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.inference.predictor import InferenceEngine
from src.ingestion.cicflowmeter_v3_adapter import (
    ADAPTER_IDENTITY,
    CICFLOWMETER_V3_COMMIT,
    CICFLOWMETER_V3_IMAGE_DIGEST,
    CICFlowMeterV3ModelAdapter,
)


ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "models/random_forest_active.joblib"
METADATA = ROOT / "models/model_metadata.json"
NORMAL_INPUT = ROOT / "data/lab/flows/cicflowmeter-v3/normal-http-test.pcap_ISCX.csv"
PORTSCAN_INPUT = ROOT / "data/lab/flows/cicflowmeter-v3/portscan-test.pcap_ISCX.csv"
REPORT = ROOT / "reports/metrics/experiment_c_v3_inference.json"
NORMAL_TABLE = ROOT / "reports/tables/experiment_c_v3_normal_predictions.csv"
PORTSCAN_TABLE = ROOT / "reports/tables/experiment_c_v3_portscan_predictions.csv"
CLASSES = ("Normal", "DDoS", "PortScan")
METADATA_COLUMNS = {
    "Flow ID": "flow_id",
    "Src IP": "source_ip",
    "Dst IP": "destination_ip",
    "Src Port": "source_port",
    "Dst Port": "destination_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
}


def _summary(values: pd.Series) -> dict[str, float]:
    return {
        "mean": float(values.mean()),
        "median": float(values.median()),
        "std": float(values.std(ddof=0)),
        "min": float(values.min()),
        "p05": float(values.quantile(0.05)),
        "p95": float(values.quantile(0.95)),
        "max": float(values.max()),
    }


def _evaluate(
    path: Path,
    ground_truth: str,
    adapter: CICFlowMeterV3ModelAdapter,
    engine: InferenceEngine,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    raw = pd.read_csv(path)
    adaptation = adapter.adapt_csv(path)
    features = adaptation.features
    if features.shape != (len(raw), 78):
        raise RuntimeError("Adapter feature count validation failed")
    if list(features.columns) != engine.feature_names:
        raise RuntimeError("Adapter feature order differs from active model metadata")
    if features.columns.duplicated().any():
        raise RuntimeError("Adapter produced duplicate features")
    missing_features = [name for name in engine.feature_names if name not in features.columns]
    if missing_features:
        raise RuntimeError(f"Adapter output is missing features: {missing_features}")

    predictions: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    # InferenceEngine is deliberately used instead of duplicating model/pipeline logic.
    for row_number, (_, row) in enumerate(features.iterrows(), start=1):
        try:
            predictions.append(engine.predict_one(row.to_dict()))
        except Exception as exc:  # retain exact per-row technical failures in the report
            failures.append({"flow_row_number": row_number, "error": str(exc)})
    if failures:
        raise RuntimeError(f"{len(failures)} inference operations failed: {failures[:3]}")

    table = pd.DataFrame(
        {
            "flow_row_number": np.arange(1, len(raw) + 1),
            "ground_truth": ground_truth,
            "predicted_label": [item["prediction"] for item in predictions],
            "confidence": [item["confidence"] for item in predictions],
            "P_Normal": [item["probabilities"]["Normal"] for item in predictions],
            "P_DDoS": [item["probabilities"]["DDoS"] for item in predictions],
            "P_PortScan": [item["probabilities"]["PortScan"] for item in predictions],
        }
    )
    for source, target in METADATA_COLUMNS.items():
        if source in raw.columns:
            table[target] = raw[source].to_numpy()
    counts = {label: int(Counter(table["predicted_label"])[label]) for label in CLASSES}
    probability_summary = {
        label: _summary(table[f"P_{label}"]) for label in CLASSES
    }
    details = {
        "ground_truth": ground_truth,
        "input_path": str(path.relative_to(ROOT)),
        "raw_input_sha256": adaptation.provenance["raw_input_sha256"],
        "total": len(raw),
        "successful_inference": len(predictions),
        "failed_inference": len(failures),
        "predictions": counts,
        "probability_summary": probability_summary,
    }
    return table, details


def main() -> None:
    engine = InferenceEngine(MODEL, METADATA)
    adapter = CICFlowMeterV3ModelAdapter.from_metadata(METADATA)
    if len(engine.feature_names) != 78 or len(set(engine.feature_names)) != 78:
        raise RuntimeError("Active model metadata failed exact 78-feature validation")
    if list(adapter.feature_names) != engine.feature_names:
        raise RuntimeError("Adapter schema/order differs from active model metadata")

    # Scientific protocol: controlled Normal must be inferred first.
    normal_table, normal = _evaluate(NORMAL_INPUT, "Normal", adapter, engine)
    normal_fp = normal["predictions"]["DDoS"] + normal["predictions"]["PortScan"]
    normal["normal_correctly_classified"] = normal["predictions"]["Normal"]
    normal["normal_to_ddos"] = normal["predictions"]["DDoS"]
    normal["normal_to_portscan"] = normal["predictions"]["PortScan"]
    normal["false_positive_candidates"] = normal_fp
    normal["controlled_normal_flow_level_false_positive_rate"] = normal_fp / normal["total"]

    portscan_table, portscan = _evaluate(PORTSCAN_INPUT, "PortScan", adapter, engine)
    portscan["portscan_to_portscan"] = portscan["predictions"]["PortScan"]
    portscan["portscan_to_normal"] = portscan["predictions"]["Normal"]
    portscan["portscan_to_ddos"] = portscan["predictions"]["DDoS"]
    portscan["portscan_recall"] = portscan["predictions"]["PortScan"] / portscan["total"]

    confusion = [
        [normal["predictions"][label] for label in CLASSES],
        [portscan["predictions"][label] for label in CLASSES],
    ]
    correct = normal["predictions"]["Normal"] + portscan["predictions"]["PortScan"]
    top20_columns = [
        "flow_row_number", "source_ip", "destination_ip", "source_port",
        "destination_port", "predicted_label", "confidence", "P_Normal", "P_DDoS",
        "P_PortScan",
    ]
    top20 = (
        portscan_table.nlargest(20, "P_PortScan")[top20_columns]
        .rename(columns={"predicted_label": "predicted_class"})
        .to_dict(orient="records")
    )
    prior_mean = 0.02053784032049202
    report = {
        "status": "completed",
        "experiment_status": "PARTIAL — DDoS NOT YET TESTED",
        "inference_path": {
            "type": "direct_read_only",
            "engine": "src.inference.predictor.InferenceEngine",
            "database_persistence": False,
            "dashboard_data": False,
            "note": "No API submission, prediction persistence, alert creation, or dashboard update was performed.",
        },
        "extractor": {
            "name": "CICFlowMeter V3",
            "commit": CICFLOWMETER_V3_COMMIT,
            "image_digest": CICFLOWMETER_V3_IMAGE_DIGEST,
        },
        "adapter": {"name": ADAPTER_IDENTITY, "feature_count": 78},
        "model": {
            "artifact": "models/random_forest_active.joblib",
            "metadata": "models/model_metadata.json",
            "version": engine.metadata["model_version"],
            "sha256": engine.metadata["model_sha256"],
            "fitted_pipeline_reused": True,
            "fitting_performed": False,
        },
        "normal": normal,
        "portscan": portscan,
        "partial_confusion_matrix": {
            "label": "PARTIAL Experiment C confusion matrix",
            "actual_rows": ["Normal", "PortScan"],
            "predicted_columns": list(CLASSES),
            "values": confusion,
        },
        "probability_summary": {
            "Normal": normal["probability_summary"],
            "PortScan": portscan["probability_summary"],
        },
        "highest_portscan_probability_flows": top20,
        "preliminary_partial_experiment_c_metrics": {
            "normal_recall": normal["predictions"]["Normal"] / normal["total"],
            "normal_correct_count": normal["predictions"]["Normal"],
            "normal_candidate_false_positive_count": normal_fp,
            "experiment_c_controlled_normal_flow_level_false_positive_rate": normal_fp / normal["total"],
            "portscan_recall": portscan["portscan_recall"],
            "overall_flow_level_accuracy_available_scenarios": correct / (normal["total"] + portscan["total"]),
        },
        "old_hieulw_comparison": {
            "old_hieulw": {
                "total": 1000,
                "predictions": {"Normal": 1000, "DDoS": 0, "PortScan": 0},
                "mean_portscan_probability": prior_mean,
                "source": "reports/metrics/experiment_c_portscan_diagnostic.json",
            },
            "validated_v3": {
                "total": portscan["total"],
                "predictions": portscan["predictions"],
                "portscan_probability_summary": portscan["probability_summary"]["PortScan"],
            },
            "interpretation": "Descriptive comparison only; it does not attribute differences to any single feature.",
        },
        "distribution_shift": {
            "interpretation": "External distribution shift between CICIDS2017 and the controlled Experiment C traffic; not semantic incompatibility because the validated V3 compatibility gate passed.",
            "normal_max_ks_approx": 0.796064,
            "portscan_max_ks_approx": 0.996533,
        },
        "inference_failures": [],
        "limitations": [
            "Only controlled Normal and PortScan scenarios are included; DDoS has not yet been tested.",
            "The controlled-normal flow-level false-positive rate is not a global production false-positive rate.",
            "Metrics are preliminary/partial and flow-level only.",
            "Direct read-only inference did not verify database records, alerts, or dashboard summaries.",
            "Large KS values describe external distribution shift and are not treated as adapter semantic incompatibility.",
        ],
    }

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    NORMAL_TABLE.parent.mkdir(parents=True, exist_ok=True)
    normal_table.to_csv(NORMAL_TABLE, index=False)
    portscan_table.to_csv(PORTSCAN_TABLE, index=False)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("Experiment C — Validated V3 Inference")
    print("======================================")
    print(f"\nModel: {engine.metadata['model_version']} ({MODEL.relative_to(ROOT)})")
    print("Extractor: CICFlowMeter V3")
    print(f"Adapter: {ADAPTER_IDENTITY}")
    print("\nNormal\n------")
    print("Ground truth: Normal")
    print(f"Flows: {normal['total']}")
    print(f"Predicted Normal: {normal['predictions']['Normal']}")
    print(f"Predicted DDoS: {normal['predictions']['DDoS']}")
    print(f"Predicted PortScan: {normal['predictions']['PortScan']}")
    print(f"Candidate false positives: {normal_fp}")
    print(f"Candidate FPR: {normal['controlled_normal_flow_level_false_positive_rate']:.6f}")
    print("\nPortScan\n--------")
    print("Ground truth: PortScan")
    print(f"Flows: {portscan['total']}")
    print(f"Predicted Normal: {portscan['predictions']['Normal']}")
    print(f"Predicted DDoS: {portscan['predictions']['DDoS']}")
    print(f"Predicted PortScan: {portscan['predictions']['PortScan']}")
    print(f"PortScan recall: {portscan['portscan_recall']:.6f}")
    p = portscan["probability_summary"]
    print("\nProbability summary — PortScan\n------------------------------")
    print(f"Mean P(Normal): {p['Normal']['mean']:.6f}")
    print(f"Mean P(DDoS): {p['DDoS']['mean']:.6f}")
    print(f"Mean P(PortScan): {p['PortScan']['mean']:.6f}")
    print(f"Max P(PortScan): {p['PortScan']['max']:.6f}")
    print("\nPartial confusion matrix\n------------------------")
    print("Actual\\Predicted  Normal  DDoS  PortScan")
    print(f"Normal            {confusion[0][0]:6d}  {confusion[0][1]:4d}  {confusion[0][2]:8d}")
    print(f"PortScan          {confusion[1][0]:6d}  {confusion[1][1]:4d}  {confusion[1][2]:8d}")
    print("\nOld hieulw PortScan\n-------------------")
    print("Normal: 1000")
    print("PortScan: 0")
    print("\nValidated V3 PortScan\n---------------------")
    print(f"Normal: {portscan['predictions']['Normal']}")
    print(f"PortScan: {portscan['predictions']['PortScan']}")
    print("\nInference failures: 0")
    print("\nDatabase persistence: not performed (direct read-only inference)")
    print("Dashboard data: not updated")
    print("\nExperiment C status:\nPARTIAL — DDoS NOT YET TESTED")
    print("\nNext step:\nReview V3 Normal/PortScan result before DDoS.")


if __name__ == "__main__":
    main()
