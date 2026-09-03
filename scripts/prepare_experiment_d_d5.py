#!/usr/bin/env python3
"""Build model-blind D5 manifests and audits from captured/extracted artifacts."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from scripts.verify_experiment_d_frozen_baseline import build_manifest as frozen_baseline
from src.common.config import PROJECT_ROOT
from src.experiment_d.d5 import canonical_identity, verify_frozen_manifest
from src.experiment_d.integrity import require_create_new, sha256_file
from src.experiment_d.manifest import ManifestEntry, Provenance, ScientificManifest, entry_from_file, load_manifest
from src.experiment_d.split import validate_role_exclusivity
from src.ingestion.cicflowmeter_v3_adapter import CICFlowMeterV3ModelAdapter


ROOT = PROJECT_ROOT
DATA = ROOT / "data/lab/experiment_d"
FINAL = DATA / "final_test"
CAPTURE = FINAL / "manifests/capture_manifest.json"
LABELED = FINAL / "manifests/labeled_flow_manifest.json"
LEAKAGE = ROOT / "reports/experiment_d/audit/final_test_leakage_audit.json"
AUDIT = ROOT / "reports/experiment_d/final_test/dataset_audit.json"
DIST = ROOT / "reports/experiment_d/final_test/class_distribution.csv"
ADAPTATION = DATA / "adaptation/manifests/capture_manifest.json"


def write_new(path: Path, payload: object) -> None:
    require_create_new(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def main() -> int:
    for path in (LABELED, LEAKAGE, AUDIT, DIST): require_create_new(path)
    capture = json.loads(CAPTURE.read_text())
    valid = [x for x in capture["sessions"] if x["valid"]]
    invalid = [x for x in capture["sessions"] if not x["valid"]]
    if len(valid) != 9 or Counter(x["class"] for x in valid) != Counter({"Normal": 3, "PortScan": 3, "DDoS": 3}):
        raise ValueError("final-test requires exactly three valid sessions per class")
    adaptation_raw = json.loads(ADAPTATION.read_text())
    adaptation_ids = {x["capture_id"] for x in adaptation_raw["captures"]} | {x["session_id"] for x in adaptation_raw["captures"]}
    final_ids = {x["capture_id"] for x in capture["sessions"]} | {x["session_id"] for x in capture["sessions"]}
    if adaptation_ids & final_ids: raise ValueError("adaptation/final-test identity overlap")
    adapter = CICFlowMeterV3ModelAdapter.from_metadata(ROOT / "models/experiment_d/random_forest_rf_v2_metadata.json")
    entries: list[ManifestEntry] = []
    flow_records, frames = [], []
    for session in valid:
        clsdir = session["logical_path"].split("/")[1]
        pcap = FINAL / session["logical_path"]
        report_path = FINAL / "manifests" / f"{pcap.name}.extraction.json"
        report = json.loads(report_path.read_text())
        flow = DATA / report["output_logical_path"]
        if report["raw_column_count"] != 84 or report["row_count"] <= 0: raise ValueError("invalid extraction shape")
        if sha256_file(pcap) != report["input_sha256"] or sha256_file(flow) != report["output_sha256"]: raise ValueError("extraction hash mismatch")
        frame = pd.read_csv(flow)
        if len(frame.columns) != 84 or frame.columns.duplicated().any(): raise ValueError("raw CSV schema failure")
        adapted = adapter.adapt(frame, raw_input_path=flow, raw_input_sha256=report["output_sha256"])
        if adapted.features.shape != (report["row_count"], 78): raise ValueError("adapter shape failure")
        frames.append(frame.assign(__ground_truth=session["class"], __session_id=session["session_id"]))
        provenance = Provenance.model_validate({
            "role": "final_test", "class": session["class"], "capture_id": session["capture_id"],
            "session_id": session["session_id"], "source_host": session["source_host"],
            "target_host": session["target_host"], "capture_started_at": session["started_at"],
            "capture_ended_at": session["ended_at"], "scenario_id": session["scenario_id"],
        })
        entries.append(entry_from_file(pcap, f"final_test/{session['logical_path']}", provenance))
        entries.append(entry_from_file(flow, report["output_logical_path"], provenance))
        flow_records.append({
            "capture_id": session["capture_id"], "session_id": session["session_id"],
            "scenario_id": session["scenario_id"], "role": "final_test", "ground_truth": session["class"],
            "raw_csv_logical_path": report["output_logical_path"], "raw_csv_sha256": report["output_sha256"],
            "row_count": report["row_count"], "raw_column_count": 84,
            "adapter_validation": adapted.provenance, "extractor": report["extractor"],
        })
    freeze_path = ROOT / "reports/experiment_d/audit/rf_v2_frozen_manifest.json"
    freeze = verify_frozen_manifest(freeze_path, ROOT / "models/experiment_d/random_forest_rf_v2.joblib")
    metadata = {
        "ground_truth_identity": canonical_identity([{k:r[k] for k in ("capture_id","session_id","ground_truth","raw_csv_sha256","row_count")} for r in flow_records]),
        "capture_manifest_identity": capture["scientific_identity"], "flow_records": flow_records,
        "adapter": {"identity": "CICFLOWMETER_V3_CICIDS2017_MODEL_ADAPTER", "version": "1.0.0", "crosswalk_sha256": "66e517cdcea217f19de4d0a2cd45302ede999388393f539fb8ca4a2c68b74cf4"},
        "rf_v2_frozen_identity": freeze["frozen_identity"], "model_blind": True,
    }
    manifest = ScientificManifest(role="final_test", entries=entries, metadata=metadata)
    write_new(LABELED, manifest.model_dump(mode="json", by_alias=True))
    combined = pd.concat(frames, ignore_index=True)
    technical = combined.drop(columns=["__ground_truth", "__session_id"])
    per_class = Counter()
    for record in flow_records: per_class[record["ground_truth"]] += record["row_count"]
    duplicate_count = int(technical.duplicated().sum())
    dataset_audit = {
        "schema": "experiment_d_final_test_dataset_audit", "status": "PASS", "model_blind": True,
        "valid_sessions": dict(Counter(x["class"] for x in valid)), "invalid_sessions": dict(Counter(x["class"] for x in invalid)),
        "pcap_counts": dict(Counter(x["class"] for x in valid)), "flow_counts": dict(per_class),
        "total_flows": int(sum(per_class.values())), "raw_column_count": 84, "feature_count": 78,
        "raw_schema_status": "PASS", "adapter_schema_status": "PASS", "exact_duplicate_rows": duplicate_count,
        "missing_values": sum(r["adapter_validation"]["non_finite_before"]["nan"] for r in flow_records),
        "positive_infinity": sum(r["adapter_validation"]["non_finite_before"]["positive_infinity"] for r in flow_records),
        "negative_infinity": sum(r["adapter_validation"]["non_finite_before"]["negative_infinity"] for r in flow_records),
        "ground_truth_distribution": dict(per_class),
    }
    write_new(AUDIT, dataset_audit)
    DIST.parent.mkdir(parents=True, exist_ok=True)
    with DIST.open("x", newline="") as f:
        writer=csv.writer(f); writer.writerow(["ground_truth","valid_sessions","flow_count"])
        for label in ("Normal","PortScan","DDoS"): writer.writerow([label, 3, per_class[label]])
    experiment_c_hashes = {x["sha256"] for x in frozen_baseline()["entries"]}
    adaptation_hashes = {x["sha256"] for x in adaptation_raw["captures"]}
    adaptation_flow = load_manifest(FINAL.parent / "adaptation/manifests/labeled_flow_manifest.json")
    adaptation_hashes |= {x.sha256 for x in adaptation_flow.entries}
    final_hashes = {x.sha256 for x in entries}
    training_text = (ROOT / "models/experiment_d/training_manifest.json").read_text()
    final_paths = [x.logical_path for x in entries]
    checks = {
        "no_experiment_c_content_hash_overlap": not bool(final_hashes & experiment_c_hashes),
        "no_adaptation_content_hash_overlap": not bool(final_hashes & adaptation_hashes),
        "no_adaptation_identity_overlap": not bool(adaptation_ids & final_ids),
        "no_final_test_path_in_training_manifest": not any(x in training_text for x in final_paths),
        "rf_v2_frozen_hash_unchanged": freeze["model_sha256"] == "fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31",
        "model_artifacts_predate_freeze": all(datetime.fromtimestamp((ROOT/p).stat().st_mtime, timezone.utc) <= datetime.fromisoformat(freeze["frozen_at"]) for p in ("models/experiment_d/random_forest_rf_v2.joblib","models/experiment_d/random_forest_rf_v2_metadata.json","models/experiment_d/training_manifest.json")),
        "no_evaluation_outputs_exist": not any((ROOT / "reports/experiment_d/final_test").glob("*prediction*")) and not any((ROOT / "reports/experiment_d/final_test").glob("*metrics*")),
    }
    if not all(checks.values()): raise ValueError(f"leakage audit failed: {checks}")
    write_new(LEAKAGE, {"schema":"experiment_d_final_test_leakage_audit","status":"PASS","checks":checks,
                        "final_test_manifest_identity":manifest.scientific_identity,"rf_v2_frozen_identity":freeze["frozen_identity"],
                        "audited_at":datetime.now(timezone.utc).isoformat()})
    print(json.dumps({"status":"PASS","manifest_identity":manifest.scientific_identity,"flow_counts":dict(per_class)}))
    return 0


if __name__ == "__main__": raise SystemExit(main())
