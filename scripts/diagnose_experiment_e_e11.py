#!/usr/bin/env python3
"""Read-only E11 diagnosis from frozen E10 exports and RF-v3 training evidence."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT / "reports/experiment_e/runtime_exports/e10"
OUT = ROOT / "reports/experiment_e/diagnostic/e11_ddos_failure_diagnostic.json"
SUMMARY = ROOT / "reports/experiment_e/diagnostic/e11_ddos_failure_diagnostic_summary.md"
MODEL = ROOT / "models/experiment_e/random_forest_rf_v3_candidate.joblib"
METADATA = ROOT / "models/experiment_e/random_forest_rf_v3_candidate_metadata.json"
TRAINING = ROOT / "data/lab/experiment_e/datasets/experiment_e_training_candidate.csv"
LINEAGE = ROOT / "data/lab/experiment_e/datasets/experiment_e_training_candidate_lineage.csv"
TRAINING_MANIFEST = ROOT / "data/lab/experiment_e/datasets/experiment_e_training_candidate_manifest.json"
HISTORICAL = (
    "models/experiment_d/random_forest_rf_v2.joblib",
    "models/experiment_e/random_forest_rf_v3_candidate.joblib",
    "models/experiment_e/random_forest_rf_v3_candidate_metadata.json",
    "reports/experiment_e/evaluation/e6_offline_validation.json",
    "reports/experiment_e/runtime_validation/e7_runtime_validation.json",
    "reports/experiment_e/analysis/e8_final_comparison.json",
    "reports/experiment_e/audit/e8_scientific_decision.json",
    "reports/experiment_e/analysis/e10_runtime_validation_analysis.json",
    "reports/experiment_e/analysis/e10_runtime_validation_summary.md",
)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def stat(series: pd.Series) -> dict[str, float]:
    return {"min": float(series.min()), "q1": float(series.quantile(.25)),
            "median": float(series.median()), "mean": float(series.mean()),
            "q3": float(series.quantile(.75)), "max": float(series.max()),
            "standard_deviation": float(series.std(ddof=1))}


def main() -> None:
    if OUT.exists() or SUMMARY.exists():
        raise FileExistsError("E11 evidence already exists; diagnostics are create-new only")
    before = {item: digest(ROOT / item) for item in HISTORICAL}
    metadata = json.loads(METADATA.read_text(encoding="utf-8"))
    manifest = json.loads(TRAINING_MANIFEST.read_text(encoding="utf-8"))
    predictions = pd.read_csv(EXPORT / "session_11_predictions.csv")
    artifacts = pd.read_csv(EXPORT / "runtime_artifacts_10_11.csv")
    e10 = json.loads((ROOT / "reports/experiment_e/analysis/e10_runtime_validation_analysis.json").read_text())
    feature_names = metadata["feature_names"]
    runtime_columns = list(predictions.columns)
    artifact_columns = list(artifacts.columns)
    candidate_paths = artifacts.loc[(artifacts.monitoring_session_id == 11) & (artifacts.state == "COMMITTED"), "csv_relative_path"].dropna().tolist()
    raw_feature_columns_present = "raw_features" in runtime_columns
    extracted_payloads_present = any((ROOT / path).is_file() for path in candidate_paths)
    recoverable = False
    training = pd.read_csv(TRAINING)
    lineage = pd.read_csv(LINEAGE)
    if list(training.columns) != feature_names + ["ground_truth_class"]:
        raise ValueError("frozen RF-v3 training dataset violates metadata feature order")
    if len(feature_names) != 78 or len(set(feature_names)) != 78:
        raise ValueError("locked feature contract is not 78 unique ordered names")
    ddos = training.loc[training.ground_truth_class.eq("DDoS"), feature_names]
    if len(ddos) != 3081 or len(lineage) != len(training):
        raise ValueError("frozen DDoS reference lineage/count mismatch")
    model = joblib.load(MODEL)
    if int(model.n_features_in_) != 78 or list(model.classes_) != ["DDoS", "Normal", "PortScan"]:
        raise ValueError("candidate model identity mismatch")
    importance = sorted(({"feature": name, "importance": float(value)} for name, value in zip(feature_names, model.feature_importances_)), key=lambda row: row["importance"], reverse=True)
    parsed = predictions.assign(probability=predictions.class_probabilities.map(json.loads))
    for label in ("DDoS", "Normal", "PortScan"):
        parsed[f"P({label})"] = parsed.probability.map(lambda value: float(value[label]))
    top_ddos = parsed.sort_values("P(DDoS)", ascending=False).head(10)
    top_ddos_rows = [{
        "prediction_id": int(row.prediction_id), "traffic_flow_id": int(row.traffic_flow_id),
        "runtime_artifact_id": int(row.runtime_artifact_id), "source_ip": row.source_ip,
        "destination_ip": row.destination_ip, "destination_port": int(row.destination_port),
        "predicted_label": row.predicted_label, "P(DDoS)": row["P(DDoS)"],
        "P(Normal)": row["P(Normal)"], "P(PortScan)": row["P(PortScan)"],
        "feature_values_vs_session_median": "unavailable: exact Session 11 feature vectors are absent",
    } for _, row in top_ddos.iterrows()]
    provenance = {
        "session_11_committed_runtime_artifact": {
            "artifact_id": 807, "csv_relative_path": candidate_paths[0] if candidate_paths else None,
            "csv_payload_present_in_repository": extracted_payloads_present,
            "csv_sha256": "3a6b58afcda68baae9d620afa6f9c0e286589253827836b61cb021bbc6d7432b",
            "pcap_sha256": "8bfa65f4d4e395044016dab174477781e1e14416b9059207e559614fd6fb3509",
            "extractor_identity": "sha256:b12b3a4a4218968aba2436685a4eb113473e5681de70705409e834e4613a879b",
        },
        "runtime_export_has_raw_features_column": raw_feature_columns_present,
        "prediction_linkage_fields": [name for name in ("prediction_id", "traffic_flow_id", "runtime_artifact_id") if name in runtime_columns],
        "adapter_transformation_path": "CICFlowMeter V3 raw 84-column CSV -> pinned CICFlowMeterV3ModelAdapter -> exact ordered 78-feature model input; adapter maps fields and converts +/-Infinity to NaN without fitting or imputation.",
        "e3_a1_qualification": "approved replacement extractor digest b12... was byte-identical on nine non-final Experiment D adaptation reference PCAPs and accepted by the pinned adapter.",
    }
    payload = {
        "schema": "experiment_e_e11_ddos_failure_diagnostic", "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(), "mode": "diagnostic-only; read-only frozen evidence",
        "e11_gate": "PASS_WITH_DOCUMENTED_LIMITATION",
        "session_11_feature_reconstruction": {"recoverable": recoverable, "row_count": None, "feature_count": None, "feature_dataset_sha256": None, "reason": "The frozen E10 export contains 802 prediction records and artifact hashes/relative paths, but not traffic_flows.raw_features, the committed raw 84-column CSV payload, PCAP payload, or exact model-input vectors. The referenced Session 11 CSV path is not present in this repository. Therefore an exact ordered 78-feature dataset cannot be reconstructed reproducibly.", "inspection": {"prediction_export_columns": runtime_columns, "runtime_artifact_export_columns": artifact_columns, "committed_csv_relative_paths": candidate_paths, "raw_features_present": raw_feature_columns_present, "referenced_csv_payload_present": extracted_payloads_present}},
        "reconstruction_provenance": provenance,
        "historical_ddos_reference": {"source": "Exact RF-v3 E4 frozen training candidate rows with ground_truth_class=DDoS", "path": str(TRAINING.relative_to(ROOT)), "sha256": digest(TRAINING), "lineage_path": str(LINEAGE.relative_to(ROOT)), "lineage_sha256": digest(LINEAGE), "manifest_sha256": digest(TRAINING_MANIFEST), "row_count": int(len(ddos)), "provenance": manifest["historical_sources"], "selection_rule": manifest["selection_rule"], "feature_statistics": {name: stat(ddos[name]) for name in feature_names}},
        "distribution_shift": {"available": False, "statement": "Session 11-versus-historical-DDoS feature distribution shift and top shifted features are unavailable because exact Session 11 feature vectors cannot be reproducibly reconstructed.", "top_10_shifted_features": []},
        "model_behavior": {"offline_rf_v3_prediction_reproducibility": {"available": False, "mismatch_count": None, "reason": "Exact Session 11 vectors are unavailable; no offline inference was run."}, "persisted_session_11_distribution": e10["session_11"]["analysis"]["prediction_distribution"], "top_10_highest_p_ddos_persisted_rows": top_ddos_rows, "global_rf_v3_feature_importances": importance, "importance_vs_shift_comparison": "unavailable because Session 11 feature-shift statistics are unavailable; feature importances are non-causal global model properties."},
        "rf_v2_identical_flow_diagnostic": {"available": False, "statement": "RF-v2 identical-flow diagnostic comparison unavailable because exact E10 Session 11 model input vectors could not be reproducibly reconstructed."},
        "schema_order_and_provenance_findings": {"feature_schema_mismatch": "not established: no Session 11 vector payload exists to validate actual runtime values/order; the persisted model version/hash and 78-feature metadata contract match the candidate.", "extractor_provenance_mismatch": "not established: Session 11 uses the E3-A1 approved b12... replacement extractor, which has a documented byte-identical compatibility gate on non-final adaptation references.", "model_loading_or_ordering_error": "not established: persisted Session 11 model version and artifact hash match RF-v3 candidate, but offline prediction/order reproducibility cannot be tested without vectors."},
        "root_cause_categories": [{"category": "INSUFFICIENT_EVIDENCE", "support": "Missing exact Session 11 raw/model-input feature payload prevents distribution-shift analysis, offline RF-v3 reproducibility, RF-v2 same-flow comparison, and causal discrimination among schema, workload, distribution, and class-boundary hypotheses."}],
        "scientific_interpretation": "E10 establishes that RF-v3 did not detect this scoped controlled multi-source DDoS-like workload (0/802 DDoS predictions), but E11 cannot determine why from the preserved evidence. Runtime distribution shift, workload non-representativeness, and model class-boundary limitation remain hypotheses rather than supported root causes.",
        "scientific_decision": "ROOT_CAUSE_UNRESOLVED", "remediation_or_promotion_authorized": False,
        "limitations": ["No Session 11 exact model-input vectors, raw CSV, PCAP, or traffic_flows.raw_features were preserved in the authoritative export.", "Global RandomForest feature_importances_ are not causal explanations.", "The four logical sources originated from one physical generator VM; E10 is not a real distributed DDoS experiment.", "No traffic, rerun, retraining, threshold change, or model promotion was performed."],
        "integrity": {"historical_hashes_before": before, "locked_feature_contract": {"count": 78, "order_sha256": metadata["feature_order_sha256"], "unchanged": True}, "database_rows": "not modified; analysis used frozen CSV exports only", "no_training_or_threshold_change": True},
        "recommended_next_step": "Preserve and checksum-export the exact Session 11 raw 84-column CSV and/or traffic_flows.raw_features with prediction/flow/artifact lineage, then reconstruct the locked 78-feature matrix and conduct the deferred reproducibility and same-flow diagnostic analyses before considering any remediation.",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    after = {item: digest(ROOT / item) for item in HISTORICAL}
    if before != after:
        raise RuntimeError("historical evidence changed during E11 diagnosis")
    SUMMARY.write_text(f"""# E11 DDoS Failure Diagnostic\n\nE11 gate: **PASS_WITH_DOCUMENTED_LIMITATION**. Exact Session 11 78-feature vectors are **not recoverable** from the frozen E10 export, so no feature dataset, offline RF-v3 reproduction, RF-v2 same-flow comparison, Session 11-vs-DDoS shift table, or top shifted features was fabricated.\n\nThe exact committed RF-v3 DDoS reference is the 3,081-row DDoS subset of the frozen E4 candidate training dataset. Its per-feature statistics and RF-v3 global feature importances are preserved in [the diagnostic JSON](e11_ddos_failure_diagnostic.json). The highest persisted P(DDoS) Session 11 rows are reported there from stored probabilities only; their feature values cannot be inspected.\n\nNo schema, extractor provenance, or model-loading/ordering error is established. E3-A1 records the runtime extractor as compatibility-qualified; actual Session 11 input ordering cannot be independently reproduced without the missing vectors.\n\nScientific decision: **ROOT_CAUSE_UNRESOLVED**. The only assigned category is **INSUFFICIENT_EVIDENCE**. This authorizes neither remediation nor promotion.\n\nEvidence SHA-256: `{digest(OUT)}`\n""", encoding="utf-8")
    print(json.dumps({"diagnostic": str(OUT.relative_to(ROOT)), "diagnostic_sha256": digest(OUT), "summary": str(SUMMARY.relative_to(ROOT)), "summary_sha256": digest(SUMMARY)}))


if __name__ == "__main__":
    main()
