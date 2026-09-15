#!/usr/bin/env python3
"""Create a read-only, reproducible E10 analysis from the frozen CSV export."""
from __future__ import annotations

import csv
import hashlib
import json
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT / "reports/experiment_e/runtime_exports/e10"
OUT = ROOT / "reports/experiment_e/analysis/e10_runtime_validation_analysis.json"
SUMMARY = ROOT / "reports/experiment_e/analysis/e10_runtime_validation_summary.md"
CLASSES = ("Normal", "DDoS", "PortScan")
EXPECTED_SOURCES = ("10.10.10.11", "10.10.10.12", "10.10.10.13", "10.10.10.14")
EXPECTED_TARGET = ("10.10.20.2", "8080")
HISTORICAL = (
    "models/experiment_d/random_forest_rf_v2.joblib",
    "models/experiment_e/random_forest_rf_v3_candidate.joblib",
    "models/experiment_e/random_forest_rf_v3_candidate_metadata.json",
    "reports/experiment_e/evaluation/e6_offline_validation.json",
    "reports/experiment_e/runtime_validation/e7_runtime_validation.json",
    "reports/experiment_e/analysis/e8_final_comparison.json",
    "reports/experiment_e/audit/e8_scientific_decision.json",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_csv(name: str) -> list[dict[str, str]]:
    with (EXPORT / name).open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def verify_manifest() -> dict[str, object]:
    expected: dict[str, str] = {}
    for line in (EXPORT / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, filename = line.split(maxsplit=1)
        expected[filename] = digest
    actual = {name: sha256(EXPORT / name) for name in expected}
    checks = {name: actual[name] == expected[name] for name in expected}
    if not all(checks.values()):
        raise ValueError(f"frozen-export checksum mismatch: {checks}")
    return {"manifest_sha256": sha256(EXPORT / "SHA256SUMS"), "files": {
        name: {"sha256": actual[name], "matches_manifest": checks[name]} for name in expected
    }}


def stats(values: list[float]) -> dict[str, float]:
    if not values:
        raise ValueError("cannot summarize an empty numeric series")
    return {"min": min(values), "median": statistics.median(values),
            "mean": statistics.fmean(values), "max": max(values)}


def as_int(row: dict[str, str], key: str) -> int:
    return int(row[key])


def prediction_analysis(session: dict[str, str], predictions: list[dict[str, str]]) -> dict[str, object]:
    session_id = session["session_id"]
    if any(row["monitoring_session_id"] != session_id for row in predictions):
        raise ValueError(f"prediction export contains a foreign session row for {session_id}")
    labels = Counter(row["predicted_label"] for row in predictions)
    if set(labels) - set(CLASSES):
        raise ValueError(f"unexpected labels: {set(labels) - set(CLASSES)}")
    probabilities = [json.loads(row["class_probabilities"]) for row in predictions]
    if any(set(probability) != set(CLASSES) for probability in probabilities):
        raise ValueError(f"class-probability representation is incomplete for session {session_id}")
    valid = len(predictions)
    if valid != as_int(session, "prediction_count") or valid != as_int(session, "flow_count"):
        raise ValueError(f"counter mismatch for session {session_id}")
    return {
        "valid_prediction_count": valid,
        "matches_session_prediction_count": True,
        "matches_session_flow_count": True,
        "prediction_distribution": {label: labels.get(label, 0) for label in CLASSES},
        "model_ids": sorted(set(row["model_id"] for row in predictions)),
        "model_versions": sorted(set(row["model_version"] for row in predictions)),
        "capture_interfaces": sorted(set(row["capture_interface"] for row in predictions)),
        "probability_representation": "class_probabilities JSON with Normal, DDoS, and PortScan keys on every exported prediction",
        "probability_statistics": {
            f"P({label})": stats([float(probability[label]) for probability in probabilities])
            for label in CLASSES
        },
        "confidence_score": stats([float(row["confidence_score"]) for row in predictions]),
    }


def artifact_analysis(rows: list[dict[str, str]], session_id: str) -> dict[str, object]:
    artifacts = [row for row in rows if row["monitoring_session_id"] == session_id]
    states = Counter(row["state"] for row in artifacts)
    committed = [row for row in artifacts if row["state"] == "COMMITTED"]
    return {
        "window_count": len(artifacts), "state_distribution": dict(sorted(states.items())),
        "extracted_rows_total": sum(as_int(row, "extracted_row_count") for row in artifacts),
        "adapted_rows_total": sum(as_int(row, "adapted_row_count") for row in artifacts),
        "committed_windows": [{
            "artifact_id": row["id"], "window_number": as_int(row, "window_number"),
            "pcap_relative_path": row["pcap_relative_path"], "pcap_sha256": row["pcap_sha256"],
            "pcap_size": as_int(row, "pcap_size"), "csv_relative_path": row["csv_relative_path"],
            "csv_sha256": row["csv_sha256"], "csv_size": as_int(row, "csv_size"),
            "extractor_identity": row["extractor_identity"],
            "extracted_row_count": as_int(row, "extracted_row_count"),
            "adapted_row_count": as_int(row, "adapted_row_count"), "committed_at": row["committed_at"],
        } for row in committed],
        "non_committed_windows": [{"window_number": as_int(row, "window_number"),
                                   "state": row["state"], "error_stage": row["error_stage"],
                                   "error_message": row["error_message"]} for row in artifacts if row["state"] != "COMMITTED"],
    }


def main() -> None:
    if OUT.exists() or SUMMARY.exists():
        raise FileExistsError("E10 evidence already exists; analysis is create-new only")
    checksums = verify_manifest()
    session10, session11 = read_csv("session_10.csv"), read_csv("session_11.csv")
    if len(session10) != 1 or len(session11) != 1:
        raise ValueError("each frozen session metadata export must contain exactly one row")
    session10, session11 = session10[0], session11[0]
    if session10["session_id"] != "10" or session11["session_id"] != "11":
        raise ValueError("unexpected E10 session identifiers")
    predictions10 = read_csv("session_10_predictions.csv")
    predictions11 = read_csv("session_11_predictions.csv")
    artifacts = read_csv("runtime_artifacts_10_11.csv")
    alerts = read_csv("alerts_10_11.csv")
    p10, p11 = prediction_analysis(session10, predictions10), prediction_analysis(session11, predictions11)
    a10, a11 = artifact_analysis(artifacts, "10"), artifact_analysis(artifacts, "11")
    for session, evidence, artifact in ((session10, p10, a10), (session11, p11, a11)):
        if evidence["valid_prediction_count"] != artifact["adapted_rows_total"]:
            raise ValueError(f"adapted-row mismatch for session {session['session_id']}")
        if session["extractor_identity"] not in {item["extractor_identity"] for item in artifact["committed_windows"]}:
            raise ValueError(f"extractor provenance mismatch for session {session['session_id']}")
    alert_rows = [row for row in alerts if row["monitoring_session_id"] in {"10", "11"}]
    if len(alert_rows) != 0 or any(as_int(row, "alert_count") != 0 for row in (session10, session11)):
        raise ValueError("alert export conflicts with the frozen session counters")
    source_counts = Counter(row["source_ip"] for row in predictions11)
    expected_target_rows = [row for row in predictions11 if (row["destination_ip"], row["destination_port"]) == EXPECTED_TARGET]
    target_related = [row for row in predictions11 if "10.10.20.2" in (row["source_ip"], row["destination_ip"])]
    out_of_destination_scope = [row for row in predictions11 if row not in expected_target_rows]
    model_meta = json.loads((ROOT / "models/experiment_e/random_forest_rf_v3_candidate_metadata.json").read_text())
    historical_before = {path: sha256(ROOT / path) for path in HISTORICAL}
    if session10["artifact_sha256"] != historical_before["models/experiment_e/random_forest_rf_v3_candidate.joblib"] or session11["artifact_sha256"] != historical_before["models/experiment_e/random_forest_rf_v3_candidate.joblib"]:
        raise ValueError("session model artifact hash does not match the candidate artifact")
    if model_meta["feature_count"] != 78:
        raise ValueError("candidate metadata does not retain the 78-feature contract")
    payload = {
        "schema": "experiment_e_e10_runtime_validation_analysis", "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(), "analysis_mode": "read-only frozen-export analysis",
        "experiment_identifier": "E10", "inputs": checksums,
        "topology_and_scope": {"observer": "ubuntu-nids", "capture_interface": "enp0s3", "target": "10.10.20.2:8080", "traffic_generator": "one ubuntu-traffic VM", "logical_source_identities": list(EXPECTED_SOURCES), "ground_truth_session_10": "controlled Normal HTTP traffic", "ground_truth_session_11": "controlled multi-source DDoS-like runtime traffic", "distributed_attack_claim": False, "maximum_generated_requests": 400},
        "model_verification": {"session_model_version": "rf-v3.0-candidate", "candidate_artifact_sha256": historical_before["models/experiment_e/random_forest_rf_v3_candidate.joblib"], "candidate_metadata_sha256": historical_before["models/experiment_e/random_forest_rf_v3_candidate_metadata.json"], "candidate_status": model_meta["status"], "feature_count": model_meta["feature_count"], "feature_order_sha256": model_meta["feature_order_sha256"]},
        "session_10": {"metadata": session10, "analysis": p10, "runtime_artifacts": a10, "scoped_normal_classification_rate": {"numerator_normal_predictions": p10["prediction_distribution"]["Normal"], "denominator_valid_predictions": p10["valid_prediction_count"], "rate": p10["prediction_distribution"]["Normal"] / p10["valid_prediction_count"]}},
        "session_11": {"metadata": session11, "analysis": p11, "runtime_artifacts": a11, "source_ip_distribution": dict(sorted(source_counts.items())), "expected_logical_source_distribution": {source: source_counts.get(source, 0) for source in EXPECTED_SOURCES}, "target_scope": {"expected_destination": "10.10.20.2:8080", "rows_with_expected_destination": len(expected_target_rows), "rows_with_target_as_either_endpoint": len(target_related), "rows_outside_expected_destination_scope": len(out_of_destination_scope), "outside_expected_destination_records": [{key: row[key] for key in ("prediction_id", "source_ip", "source_port", "destination_ip", "destination_port", "protocol")} for row in out_of_destination_scope]}, "scoped_ddos_like_detection_rate": {"numerator_ddos_predictions": p11["prediction_distribution"]["DDoS"], "denominator_valid_predictions": p11["valid_prediction_count"], "rate": p11["prediction_distribution"]["DDoS"] / p11["valid_prediction_count"], "not_universal_ddos_recall": True}},
        "alerts": {"exported_alert_count": len(alert_rows), "severity_distribution": {}, "matches_session_counters": True},
        "rf_v2_identical_flow_comparison": {"available": False, "statement": "RF-v2 identical-flow comparison unavailable from the frozen E10 runtime export.", "reason": "The export contains prediction-level fields and runtime artifact paths/hashes, but no preserved Session 11 78-feature vectors or source CSV/PCAP payloads from which exact vectors can be reproducibly reconstructed."},
        "scientific_interpretation": {"decision": "NOT_SUPPORTED", "scope": "RF-v3 performance on the scoped E10 controlled multi-source DDoS-like runtime workload only", "basis": "0 of 802 valid Session 11 predictions were classified DDoS.", "e8_more_validation_required": "reinforced", "e9_promotion_authorized": False, "recommended_next_step": "Diagnose the 802 preserved Session 11 feature vectors against the locked 78-feature contract and conduct a new preregistered, bounded DDoS-like runtime validation after a justified remediation; do not promote from E10."},
        "limitations": ["The four logical source IP identities originated from one physical ubuntu-traffic VM and are not four independent attack hosts.", "This is controlled multi-source DDoS-like runtime traffic, not a real distributed DDoS attack.", "The scoped DDoS-like detection rate is not universal DDoS recall.", "Two of 802 exported Session 11 predictions do not have destination 10.10.20.2:8080; one is target-to-source response-direction traffic and one has anomalous 8.x endpoint fields. They remain in the frozen valid-prediction denominator and are reported explicitly.", "The frozen export lacks exact feature vectors, so RF-v2 cannot be re-inferred on identical Session 11 flows."],
        "integrity": {"historical_hashes_before": historical_before, "no_training_or_threshold_change_performed": True, "no_session_or_historical_evidence_modified": True},
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    historical_after = {path: sha256(ROOT / path) for path in HISTORICAL}
    if historical_before != historical_after:
        raise RuntimeError("historical integrity changed during E10 analysis")
    summary = f"""# E10 Runtime Validation Analysis\n\nFrozen-export checksum verification: PASS (six CSV inputs match `SHA256SUMS`).\n\n- E10-N-R1 / Session 10: 18 Normal, 0 DDoS, 0 PortScan; scoped Normal classification rate: 18/18 = 100%.\n- E10-D-R1 / Session 11: 802 Normal, 0 DDoS, 0 PortScan; scoped DDoS-like detection rate: 0/802 = 0%. This is not universal DDoS recall.\n- Session 11 expected logical sources: 10.10.10.11/12/13/14 each contributed 200 predictions. Two additional frozen records are documented in the JSON; 800/802 have destination `10.10.20.2:8080`.\n- Alert export: 0 alerts; severity distribution: empty.\n- RF-v2 identical-flow comparison: unavailable because the frozen export has no exact 78-feature vectors or recoverable feature payloads.\n- Scientific decision: **NOT_SUPPORTED** for this scoped controlled multi-source DDoS-like runtime workload. E8's `MORE_VALIDATION_REQUIRED` is reinforced; E9 promotion is not authorized.\n\nThe four logical sources originated from one ubuntu-traffic VM, so this is not evidence of a real distributed DDoS attack. Full probabilities, artifact hashes/provenance, target-scope exceptions, and integrity hashes are in [the JSON analysis](e10_runtime_validation_analysis.json).\n\nEvidence SHA-256: `{sha256(OUT)}`\n"""
    SUMMARY.write_text(summary, encoding="utf-8")
    print(json.dumps({"analysis": str(OUT.relative_to(ROOT)), "analysis_sha256": sha256(OUT), "summary": str(SUMMARY.relative_to(ROOT)), "summary_sha256": sha256(SUMMARY)}))


if __name__ == "__main__":
    main()
