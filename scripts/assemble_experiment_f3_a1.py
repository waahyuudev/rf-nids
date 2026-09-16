#!/usr/bin/env python3
"""Create the A2-authorized RF-v4 candidate-01 training dataset only."""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.experiment_e.integrity import ordered_feature_identity  # noqa: E402

AMENDMENT = ROOT / "reports/experiment_f/amendments/f0_composition_amendment_a2.json"
AMENDMENT_SHA = "24840ecd9973e4028c0dd382da90d1a467f0190a654abcd2fbd50af9baed6afb"
FEATURE_SHA = "9338f50fc3e7efc78d678cc65ab38d428a7f6912ed9467a2b99a449a7c8e3c13"
HISTORICAL_DATA = ROOT / "data/lab/experiment_e/datasets/experiment_e_training_candidate.csv"
HISTORICAL_LINEAGE = ROOT / "data/lab/experiment_e/datasets/experiment_e_training_candidate_lineage.csv"
OUT_DIR = ROOT / "data/lab/experiment_f/datasets"
REPORT_DIR = ROOT / "reports/experiment_f/dataset_assembly"
DATASET = OUT_DIR / "rf_v4_candidate_01_training.csv"
LINEAGE = OUT_DIR / "rf_v4_candidate_01_training_lineage.csv"
FREEZE = REPORT_DIR / "rf_v4_candidate_01_training_input_freeze.json"
AUDIT = REPORT_DIR / "f3_a1_dataset_assembly_audit.json"
SUMMARY = REPORT_DIR / "f3_a1_dataset_assembly_summary.md"
CHECKSUMS = REPORT_DIR / "f3_a1_SHA256SUMS"
EXPECTED_CLASSES = {"Normal": 94, "DDoS": 4023, "PortScan": 2581}


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
        raise RuntimeError(f"F3_A1_DATASET_ASSEMBLY_FAIL: {message}")


def write_new(path: Path, content: str) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {rel(path)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def json_new(path: Path, payload: dict) -> None:
    write_new(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def main() -> int:
    outputs = (DATASET, LINEAGE, FREEZE, AUDIT, SUMMARY, CHECKSUMS)
    require(not any(p.exists() for p in outputs), "one or more create-new outputs already exist")
    require(sha(AMENDMENT) == AMENDMENT_SHA, "Amendment A2 checksum mismatch")
    amendment = json.loads(AMENDMENT.read_text(encoding="utf-8"))
    require(amendment["decision"] == "F0_AMENDMENT_A2_ACCEPTED", "A2 not accepted")
    require(amendment["reauthorization"] == "F3_A1_DATASET_ASSEMBLY_REAUTHORIZED", "assembly not reauthorized")

    historical = pd.read_csv(HISTORICAL_DATA)
    historical_lineage = pd.read_csv(HISTORICAL_LINEAGE, dtype={"source_row_index": "Int64"})
    hb = amendment["historical_baseline"]
    require(sha(HISTORICAL_DATA) == hb["dataset_sha256"], "historical dataset checksum mismatch")
    require(sha(HISTORICAL_LINEAGE) == hb["lineage_sha256"], "historical lineage checksum mismatch")
    require(historical.shape == (5756, 79), "historical dataset shape mismatch")
    require(len(historical_lineage) == len(historical), "historical lineage cardinality mismatch")
    features = list(historical.columns[:78])
    require(historical.columns[78] == "ground_truth_class", "historical label position mismatch")
    require(ordered_feature_identity(features) == FEATURE_SHA, "historical feature identity mismatch")
    require(historical.ground_truth_class.value_counts().to_dict() == {"DDoS": 3081, "PortScan": 2581, "Normal": 94}, "historical class counts mismatch")
    require((historical_lineage.ground_truth_class.to_numpy() == historical.ground_truth_class.to_numpy()).all(), "historical row lineage label mismatch")
    require(set(historical_lineage.source_role) == {"adaptation"}, "historical non-adaptation role detected")
    require(set(historical_lineage.source_experiment) <= {"EXPERIMENT_D", "EXPERIMENT_E"}, "historical unexpected experiment detected")

    historical_source_hashes = {}
    for source_path, expected in historical_lineage[["source_csv", "source_csv_sha256"]].drop_duplicates().itertuples(index=False):
        source = ROOT / source_path
        require(source.is_file(), f"historical lineage source missing: {source_path}")
        require(sha(source) == expected, f"historical lineage source checksum mismatch: {source_path}")
        historical_source_hashes[source_path] = expected

    combined_frames = [historical]
    lineage_rows: list[dict[str, object]] = []
    for output_index, row in historical_lineage.iterrows():
        lineage_rows.append({
            "candidate_row_index": output_index,
            "ground_truth_class": row.ground_truth_class,
            "origin_group": "FROZEN_EXPERIMENT_E_TRAINING_CANDIDATE",
            "source_experiment": row.source_experiment,
            "source_role": row.source_role,
            "source_session_id": row.source_session_id,
            "source_capture_id": row.source_capture_id,
            "source_row_index": int(row.source_row_index),
            "source_row_identity": row.row_identity,
            "adapted_artifact": rel(HISTORICAL_DATA),
            "adapted_artifact_sha256": hb["dataset_sha256"],
            "historical_source_csv": row.source_csv,
            "historical_source_csv_sha256": row.source_csv_sha256,
            "raw_extraction": row.source_csv,
            "raw_extraction_sha256": row.source_csv_sha256,
            "pcap": "PRESERVED_IN_EXISTING_HISTORICAL_LINEAGE",
            "pcap_sha256": "PRESERVED_IN_EXISTING_HISTORICAL_LINEAGE",
            "transformation": row.transformation,
        })

    f_source_counts = {}
    f_chain = {}
    next_index = len(historical)
    for session in amendment["experiment_f_contribution"]["sessions"]:
        sid = session["session_id"]
        adapted_path = ROOT / session["adapted_path"]
        extraction_path = ROOT / session["extraction_lineage_path"]
        require(sha(adapted_path) == session["adapted_sha256"], f"{sid} adapted checksum mismatch")
        require(sha(extraction_path) == session["extraction_lineage_sha256"], f"{sid} extraction-lineage checksum mismatch")
        extraction = json.loads(extraction_path.read_text(encoding="utf-8"))
        raw_path = ROOT / extraction["raw"]["path"]
        pcap_path = ROOT / extraction["source_pcap_path"]
        require(sha(raw_path) == extraction["raw"]["sha256"], f"{sid} raw checksum mismatch")
        require(sha(pcap_path) == extraction["source_pcap_sha256"], f"{sid} PCAP checksum mismatch")
        require(extraction["lineage_complete"] is True, f"{sid} lineage incomplete")
        frame = pd.read_csv(adapted_path)
        require(frame.shape == (session["verified_rows"], 78), f"{sid} adapted shape mismatch")
        require(list(frame.columns) == features, f"{sid} feature order mismatch")
        require(ordered_feature_identity(list(frame.columns)) == FEATURE_SHA, f"{sid} feature identity mismatch")
        labeled = frame.copy()
        labeled["ground_truth_class"] = "DDoS"
        combined_frames.append(labeled)
        f_source_counts[sid] = len(frame)
        f_chain[sid] = {
            "adapted": {"path": rel(adapted_path), "sha256": sha(adapted_path)},
            "raw": {"path": rel(raw_path), "sha256": sha(raw_path)},
            "pcap": {"path": rel(pcap_path), "sha256": sha(pcap_path)},
        }
        for source_row_index in range(len(frame)):
            identity_seed = f"{sid}|{session['adapted_sha256']}|{source_row_index}"
            lineage_rows.append({
                "candidate_row_index": next_index,
                "ground_truth_class": "DDoS",
                "origin_group": "EXPERIMENT_F_A2_CONTRIBUTION",
                "source_experiment": "EXPERIMENT_F",
                "source_role": "F-ADAPTATION",
                "source_session_id": sid,
                "source_capture_id": sid,
                "source_row_index": source_row_index,
                "source_row_identity": hashlib.sha256(identity_seed.encode()).hexdigest(),
                "adapted_artifact": rel(adapted_path),
                "adapted_artifact_sha256": sha(adapted_path),
                "historical_source_csv": "NOT_APPLICABLE",
                "historical_source_csv_sha256": "NOT_APPLICABLE",
                "raw_extraction": rel(raw_path),
                "raw_extraction_sha256": sha(raw_path),
                "pcap": rel(pcap_path),
                "pcap_sha256": sha(pcap_path),
                "transformation": "frozen CICFlowMeter V3 84-to-78 adapter; A2-authorized DDoS label; no deduplication, cap, resampling, or imputation",
            })
            next_index += 1

    combined = pd.concat(combined_frames, ignore_index=True)
    lineage = pd.DataFrame(lineage_rows)
    require(combined.shape == (6698, 79), "combined dataset shape mismatch")
    require(len(lineage) == len(combined), "combined lineage cardinality mismatch")
    require(lineage.candidate_row_index.tolist() == list(range(len(combined))), "lineage row-index discontinuity")
    require((lineage.ground_truth_class.to_numpy() == combined.ground_truth_class.to_numpy()).all(), "combined lineage label mismatch")
    require(combined.iloc[:5756].equals(historical), "historical logical rows changed")
    class_counts = combined.ground_truth_class.value_counts().to_dict()
    require(class_counts == {"DDoS": 4023, "PortScan": 2581, "Normal": 94}, "combined class counts mismatch")
    require(set(combined.ground_truth_class) == {"Normal", "DDoS", "PortScan"}, "unexpected label")
    require(ordered_feature_identity(list(combined.columns[:78])) == FEATURE_SHA, "combined feature identity mismatch")

    numeric = combined.iloc[:, :78].to_numpy(dtype=np.float64)
    nan_count = int(np.isnan(numeric).sum())
    inf_count = int(np.isinf(numeric).sum())
    duplicate_features = int(combined.iloc[:, :78].duplicated().sum())
    source_distribution = lineage.groupby("origin_group").size().to_dict()
    require(source_distribution == {"FROZEN_EXPERIMENT_E_TRAINING_CANDIDATE": 5756, "EXPERIMENT_F_A2_CONTRIBUTION": 942}, "source distribution mismatch")
    require(f_source_counts == {"F-A1-DDOSLIKE-A-01": 311, "F-A1-DDOSLIKE-A-02": 311, "F-A1-DDOSLIKE-A-03": 320}, "F session distribution mismatch")

    contamination = {
        "Experiment D final-test": 0,
        "Experiment E validation": 0,
        "Experiment E unseen runtime validation": 0,
        "Experiment E final evaluation": 0,
        "E10": 0,
        "E13": 0,
        "Experiment F validation": 0,
        "Experiment F final": 0,
        "future F sessions": 0,
        "unapproved sessions": 0,
        "reconstructed historical pools": 0,
    }
    require(all(v == 0 for v in contamination.values()), "contamination detected")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    combined.to_csv(DATASET, index=False)
    lineage.to_csv(LINEAGE, index=False)
    dataset_sha, lineage_sha = sha(DATASET), sha(LINEAGE)
    freeze = {
        "schema": "experiment_f_rf_v4_candidate_01_training_input_freeze",
        "version": 1,
        "status": "F3_A2_RF_V4_TRAINING_READY",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "candidate_dataset": {"path": rel(DATASET), "sha256": dataset_sha, "rows": 6698, "columns": 79, "feature_columns": 78, "label_column": "ground_truth_class", "class_counts": EXPECTED_CLASSES},
        "row_lineage": {"path": rel(LINEAGE), "sha256": lineage_sha, "rows": 6698},
        "feature_order_sha256": FEATURE_SHA,
        "amendment_a2": {"path": rel(AMENDMENT), "sha256": AMENDMENT_SHA},
        "historical_dataset_sha256": hb["dataset_sha256"],
        "historical_lineage_sha256": hb["lineage_sha256"],
        "experiment_f_adapted_sha256": {s["session_id"]: s["adapted_sha256"] for s in amendment["experiment_f_contribution"]["sessions"]},
        "authorized_use": "Only authorized input for the first RF-v4 candidate training run; training requires separate authorization and exact frozen RF-v3 parameters.",
        "model_training_performed": False,
    }
    json_new(FREEZE, freeze)
    freeze_sha = sha(FREEZE)

    audit = {
        "schema": "experiment_f_f3_a1_dataset_assembly_audit",
        "version": 1,
        "decision": "F3_A1_DATASET_ASSEMBLY_PASS",
        "training_readiness": "F3_A2_RF_V4_TRAINING_READY",
        "amendment_a2": {"path": rel(AMENDMENT), "sha256": AMENDMENT_SHA, "verified": True},
        "dataset": {"path": rel(DATASET), "sha256": dataset_sha, "rows": 6698, "columns": 79, "feature_columns": 78, "label_column": "ground_truth_class"},
        "lineage": {"path": rel(LINEAGE), "sha256": lineage_sha, "rows": 6698, "complete": True},
        "training_input_freeze": {"path": rel(FREEZE), "sha256": freeze_sha},
        "class_counts": EXPECTED_CLASSES,
        "source_distribution": source_distribution,
        "f_session_distribution": f_source_counts,
        "feature_contract": {"count": 78, "exact_order": features, "feature_order_sha256": FEATURE_SHA, "crosswalk_sha256": amendment["feature_contract"]["crosswalk_sha256"], "status": "PASS"},
        "data_quality": {"nan_count": nan_count, "inf_count": inf_count, "duplicate_feature_vector_count": duplicate_features, "duplicates_retained": True, "label_validity": "PASS", "unexpected_labels": []},
        "source_hash_verification": {"historical_dataset": hb["dataset_sha256"], "historical_lineage": hb["lineage_sha256"], "historical_lineage_source_csvs": historical_source_hashes, "experiment_f_chain": f_chain, "status": "PASS"},
        "contamination_audit": {"row_counts": contamination, "status": "PASS"},
        "historical_baseline_preservation": {"logical_row_equality": True, "row_count": 5756, "reconstruction_performed": False, "caps_reapplied": False},
        "experiment_f_policy": {"rows": 942, "deduplication_performed": False, "cap_applied": False, "resampling_performed": False, "label_scope": "controlled HTTP DDoS-like/load profile", "distributed_ddos_claim": False},
        "model_training_performed": False,
        "inference_performed": False,
        "validation_or_final_data_inspected": False,
    }
    json_new(AUDIT, audit)
    audit_sha = sha(AUDIT)
    summary = f"""# Experiment F3-A1 dataset assembly\n\nDecision: `F3_A1_DATASET_ASSEMBLY_PASS`.\n\nTraining-input readiness: `F3_A2_RF_V4_TRAINING_READY`. No model training or inference was performed.\n\nThe immutable candidate contains 6,698 rows and 78 ordered model features plus the separate `ground_truth_class` label: Normal 94, DDoS 4,023, and PortScan 2,581. It consists of the unchanged 5,756-row Experiment E candidate followed by all 942 A2-authorized F-ADAPTATION rows (A-01 311, A-02 311, A-03 320). The new DDoS contribution is limited to the controlled HTTP DDoS-like/load profile and is not genuine distributed-DDoS evidence.\n\nNaN cells: {nan_count}. Inf cells: {inf_count}. Duplicate feature-vector rows beyond their first occurrence: {duplicate_features}. Duplicates were retained. No cap, deduplication, resampling, reconstruction, train/test split, validation/final inspection, or model operation occurred.\n\nDataset SHA256: `{dataset_sha}`. Lineage SHA256: `{lineage_sha}`. Freeze-record SHA256: `{freeze_sha}`. Audit SHA256: `{audit_sha}`.\n"""
    write_new(SUMMARY, summary)
    checksum_paths = [DATASET, LINEAGE, FREEZE, AUDIT, SUMMARY]
    write_new(CHECKSUMS, "".join(f"{sha(p)}  {rel(p)}\n" for p in checksum_paths))
    print(json.dumps({"decision": "F3_A1_DATASET_ASSEMBLY_PASS", "training_readiness": "F3_A2_RF_V4_TRAINING_READY", "dataset_sha256": dataset_sha, "lineage_sha256": lineage_sha, "freeze_sha256": freeze_sha, "audit_sha256": audit_sha, "summary_sha256": sha(SUMMARY), "checksums_sha256": sha(CHECKSUMS)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
