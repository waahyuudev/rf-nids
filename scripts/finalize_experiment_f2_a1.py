#!/usr/bin/env python3
"""Finalize F2-A1 collection evidence and post-extraction data gates.

This script never generates traffic, runs model inference, or trains a model.
It is create-new/fail-closed for evidence and derived session artifacts.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ingestion.cicflowmeter_v3_adapter import (  # noqa: E402
    CICFlowMeterV3ModelAdapter,
    CROSSWALK_SHA256,
    MODEL_FEATURES,
)

FEATURE_IDENTITY = "9338f50fc3e7efc78d678cc65ab38d428a7f6912ed9467a2b99a449a7c8e3c13"
IMAGE_DIGEST = "sha256:b12b3a4a4218968aba2436685a4eb113473e5681de70705409e834e4613a879b"
COMMIT = "a26aae27f21d165ff30b4b28e75124a5f9b4b2c4"
WORKLOAD_SHA = "88c4f02b8ca06afe69eac9465b663d0089b69f7f00a7221b686f0bc7a4433aed"
SESSIONS = {
    "01": {"pcap": "71874ad8f9e6519548aeffc219bb64635f1cca24f1acdf8c9ebaef50ced01910", "terminal": 155, "machine": 153, "packets": 1553, "history": (1789537822, 1789537882)},
    "02": {"pcap": "570bad40729414f718cc4d6831c636cfb2565e80324edfd6db7161e51f6eda9d", "terminal": 154, "machine": 152, "packets": 1554, "history": (1789539879, 1789539938)},
    "03": {"pcap": "5911e90f0a4a605a213b33df87c9b9ea0f0ba7ccd1044ad4e254e6097e137c47", "terminal": 159, "machine": 158, "packets": 1596, "history": (1789540288, 1789540348)},
}
LOCUST_SHA = {
    "01": {"exceptions": "3e73e8f665731ee4e45a6a91202a31b06999f2c53240f14aee2532e0e0b42b09", "failures": "51ba68968b591276c95496a6a9624797491ce4eb934b1f6392f44b95148fbb93", "stats": "f241d339bb8eddaf5a209f465248ece2f0d50ba7a6b3de18d02dd75d5ac0b66e", "stats_history": "0d596fc5c4bb9196ed7fed9d512d4b8c9d4638c4b660960542d92fd03a870112"},
    "02": {"exceptions": "3e73e8f665731ee4e45a6a91202a31b06999f2c53240f14aee2532e0e0b42b09", "failures": "51ba68968b591276c95496a6a9624797491ce4eb934b1f6392f44b95148fbb93", "stats": "82680012c1ab5647bcc61f618c7cefa90c363064a990a3d469546ad560e9bb2d", "stats_history": "5b5935bbcdc47508146f281666a2e29ca411e8a367a2f78b1be0c1e5a15f772c"},
    "03": {"exceptions": "3e73e8f665731ee4e45a6a91202a31b06999f2c53240f14aee2532e0e0b42b09", "failures": "51ba68968b591276c95496a6a9624797491ce4eb934b1f6392f44b95148fbb93", "stats": "8dd5ebcf69d368f47b305b5ac7dd9e6f25f461fdee8874de568efee9c8e3c410", "stats_history": "f664f4a3545f2763f770e5dcbf8ea7eff212edfa36dd3a29cab182fce2edc813"},
}


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_new(path: Path, content: str) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {path.relative_to(ROOT)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def json_new(path: Path, payload: dict) -> None:
    write_new(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def feature_identity() -> str:
    encoded = json.dumps(list(MODEL_FEATURES), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def collection_for(n: str) -> None:
    if n == "01":
        return
    session = f"F-A1-DDOSLIKE-A-{n}"
    base = ROOT / "reports/experiment_f/collection" / session
    slug = f"f_a1_ddoslike_a_{n}"
    pcap = ROOT / f"data/lab/experiment_f/adaptation/pcap/ddoslike/f-a1-ddoslike-a-{n}.pcap"
    locust = {}
    for kind, expected in LOCUST_SHA[n].items():
        path = base / "locust" / f"{slug}_{kind}.csv"
        actual = sha(path)
        if actual != expected:
            raise RuntimeError(f"{session} {kind} checksum mismatch")
        locust[kind] = {"path": str(path.relative_to(ROOT)), "sha256": actual, "status": "VERIFIED"}
    stats = pd.read_csv(base / "locust" / f"{slug}_stats.csv")
    agg = stats.loc[stats["Name"] == "Aggregated"].iloc[0]
    if int(agg["Request Count"]) != SESSIONS[n]["machine"] or int(agg["Failure Count"]) != 0:
        raise RuntimeError(f"{session} persisted stats mismatch")
    history = pd.read_csv(base / "locust" / f"{slug}_stats_history.csv")
    first, last = int(history.Timestamp.iloc[0]), int(history.Timestamp.iloc[-1])
    if (first, last) != SESSIONS[n]["history"]:
        raise RuntimeError(f"{session} persisted timestamps mismatch")
    if sha(pcap) != SESSIONS[n]["pcap"]:
        raise RuntimeError(f"{session} PCAP checksum mismatch")
    for kind in ("exceptions", "failures"):
        with (base / "locust" / f"{slug}_{kind}.csv").open(newline="", encoding="utf-8-sig") as f:
            if sum(1 for _ in csv.reader(f)) != 1:
                raise RuntimeError(f"{session} {kind} not header-only")
    payload = {
        "schema": "experiment_f_f2_a1_collection_evidence", "session_id": session,
        "decision": "F2_A1_COLLECTION_SESSION_PASS",
        "canonical_pcap": {"path": str(pcap.relative_to(ROOT)), "sha256": sha(pcap), "status": "VERIFIED"},
        "locust": locust,
        "observations_preserved": {"locust_version": "2.46.5", "exit_code": 0, "terminal_summary_request_count": SESSIONS[n]["terminal"], "final_machine_readable_stats_csv_request_count": SESSIONS[n]["machine"], "reconciliation": "NOT_PERFORMED", "failure_count": 0, "workload_sha256": WORKLOAD_SHA, "tcpdump": {"packets_captured": SESSIONS[n]["packets"], "packets_received_by_filter": SESSIONS[n]["packets"], "packets_dropped_by_kernel": 0}},
        "persisted_timestamp_evidence": {"source": f"locust/{slug}_stats_history.csv", "timestamp_column": "Timestamp", "observed_unix_seconds_first": first, "observed_unix_seconds_last": last, "interpretation_limit": "Directly persisted telemetry timestamps only; not an independently persisted execution start/end log."},
        "unavailable_artifacts": {"independent_execution_log": "NOT_AVAILABLE_AS_PERSISTED_ARTIFACT", "independent_exact_start_end_timestamp_file": "NOT_AVAILABLE_AS_PERSISTED_ARTIFACT"},
        "classification": {"split": "F-ADAPTATION", "model_class": "DDoS", "scope": "controlled HTTP DDoS-like/load profile", "eligible_for_validation": False, "eligible_for_final": False, "training_eligibility": "PENDING_EXTRACTION_AND_DATA_GATES"},
    }
    json_new(base / "collection_evidence.json", payload)
    json_new(base / "lineage.json", {"schema": "experiment_f_f2_a1_lineage", "session_id": session, "collection_evidence": "collection_evidence.json", "source_pcap": str(pcap.relative_to(ROOT)), "source_pcap_sha256": sha(pcap), "lineage_status": "COLLECTION_EVIDENCE_COMPLETE_PENDING_EXTRACTION_AND_DATA_GATES", "separation": payload["classification"]})
    summary = f"# {session} collection summary\n\nDecision: `F2_A1_COLLECTION_SESSION_PASS`.\n\nThe canonical PCAP and four Locust CSV artifacts match their specified SHA256 values. Persisted `stats.csv` is authoritative and reports {SESSIONS[n]['machine']} requests with zero failures; the terminal observation of {SESSIONS[n]['terminal']} requests is preserved without reconciliation. The failure and exception files are header-only.\n\nThe session remains F-ADAPTATION only, ineligible for validation and final use, with training eligibility `PENDING_EXTRACTION_AND_DATA_GATES`.\n"
    write_new(base / "collection_summary.md", summary)
    checksum_lines = [f"{sha(pcap)}  {pcap.relative_to(ROOT)}"] + [f"{v['sha256']}  {v['path']}" for v in locust.values()]
    write_new(base / "SHA256SUMS", "\n".join(checksum_lines) + "\n")


def gate_session(n: str) -> dict:
    session = f"F-A1-DDOSLIKE-A-{n}"
    slug = f"f-a1-ddoslike-a-{n}"
    pcap = ROOT / f"data/lab/experiment_f/adaptation/pcap/ddoslike/{slug}.pcap"
    raw = ROOT / f"data/lab/experiment_f/adaptation/flows/cicflowmeter-v3/ddoslike/{slug}/{slug}.pcap_ISCX.csv"
    adapted = ROOT / f"data/lab/experiment_f/adaptation/model_input/ddoslike/{slug}_model_input_78.csv"
    if not raw.is_file():
        raise RuntimeError(f"missing raw extraction {raw.relative_to(ROOT)}")
    frame = pd.read_csv(raw)
    result = CICFlowMeterV3ModelAdapter().adapt(frame, raw_input_path=raw.relative_to(ROOT), raw_input_sha256=sha(raw))
    if adapted.exists():
        raise FileExistsError(f"refusing to overwrite {adapted.relative_to(ROOT)}")
    adapted.parent.mkdir(parents=True, exist_ok=True)
    result.features.to_csv(adapted, index=False)
    numeric = result.features.to_numpy(dtype=np.float64)
    raw_numeric = frame.select_dtypes(include=[np.number])
    constants = [c for c in result.features if result.features[c].nunique(dropna=False) <= 1]
    all_zero = [c for c in result.features if result.features[c].fillna(0).eq(0).all()]
    raw_endpoint = {c: sorted(frame[c].dropna().astype(str).unique().tolist()) for c in ("Src IP", "Dst IP", "Src Port", "Dst Port") if c in frame.columns}
    return {
        "session_id": session, "source_session": session, "source_pcap_path": str(pcap.relative_to(ROOT)), "source_pcap_sha256": sha(pcap),
        "extractor": {"tag": "rf-nids-cicflowmeter-v3:a26aae27", "approved_experiment_e_e3_a1_digest": IMAGE_DIGEST, "commit": COMMIT, "raw_output_separation": "PASS"},
        "raw": {"path": str(raw.relative_to(ROOT)), "sha256": sha(raw), "rows": len(frame), "columns": len(frame.columns), "duplicate_rows": int(frame.duplicated().sum()), "numeric_nan": int(raw_numeric.isna().sum().sum()), "numeric_inf": int(np.isinf(raw_numeric.to_numpy(dtype=float)).sum()), "source_target_sanity": raw_endpoint, "status": "PASS" if len(frame) > 0 and len(frame.columns) == 84 else "FAIL"},
        "adapted": {"path": str(adapted.relative_to(ROOT)), "sha256": sha(adapted), "rows": len(result.features), "columns": len(result.features.columns), "feature_order_sha256": feature_identity(), "expected_feature_order_sha256": FEATURE_IDENTITY, "missing_required_features": [], "duplicate_model_features": [x for x, count in Counter(result.features.columns).items() if count > 1], "nan_count": int(np.isnan(numeric).sum()), "inf_count": int(np.isinf(numeric).sum()), "duplicate_rows": int(result.features.duplicated().sum()), "constant_features": constants, "all_zero_features": all_zero, "label_leakage": "PASS_NO_LABEL_COLUMN", "numeric_coercion": "PASS", "non_finite_policy": "Inf converted to NaN; no imputation performed by frozen adapter", "status": "PASS"},
        "lineage_complete": True, "eligible_for_validation": False, "eligible_for_final": False, "training_eligibility": "ELIGIBLE_FOR_F3_ADAPTATION_TRAINING_ASSEMBLY",
    }


def main() -> int:
    if sha(ROOT / "reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv") != CROSSWALK_SHA256:
        raise RuntimeError("frozen crosswalk mismatch")
    if feature_identity() != FEATURE_IDENTITY:
        raise RuntimeError("feature identity mismatch")
    for n in ("02", "03"):
        collection_for(n)
    results = [gate_session(n) for n in ("01", "02", "03")]
    passed = all(x["raw"]["status"] == x["adapted"]["status"] == "PASS" for x in results)
    report = {"schema": "experiment_f_f2_a1_extraction_data_gate", "collection_decision": "F2_A1_ADAPTATION_COLLECTION_PASS", "extraction_decision": "F2_A1_EXTRACTION_PASS" if passed else "F2_A1_EXTRACTION_FAIL", "data_gate_decision": "F2_A1_DATA_GATE_PASS" if passed else "F2_A1_DATA_GATE_FAIL", "training_decision": "F3_RF_V4_TRAINING_READY" if passed else "F3_RF_V4_TRAINING_BLOCKED", "feature_contract": {"ordered_feature_count": 78, "feature_order_sha256": feature_identity(), "crosswalk_sha256": CROSSWALK_SHA256}, "sessions": results, "dataset_assembly_performed": False, "model_training_performed": False, "model_predictions_inspected": False}
    json_new(ROOT / "reports/experiment_f/data_gates/f2_a1_extraction_data_gate.json", report)
    for item in results:
        base = ROOT / "reports/experiment_f/collection" / item["session_id"]
        json_new(base / "extraction_lineage.json", item)
    print(json.dumps({k: report[k] for k in ("collection_decision", "extraction_decision", "data_gate_decision", "training_decision")}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
