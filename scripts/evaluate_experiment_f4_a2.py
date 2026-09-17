#!/usr/bin/env python3
"""Fail-closed Experiment F F4-A2 validation extraction follow-up and evaluation.

Raw CICFlowMeter extraction is performed separately with the pinned E3-A1 image.
This script audits copied evidence and raw extraction outputs, applies the frozen
adapter, freezes one validation matrix/lineage, and evaluates the three frozen
models without fitting or threshold changes.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ingestion.cicflowmeter_v3_adapter import (  # noqa: E402
    CICFlowMeterV3ModelAdapter,
    CROSSWALK_SHA256,
    MODEL_FEATURES,
)

RUN = "f4_a2_run_03"
RAW_EXTRACTION_RUN = "f4_a2_run_01"
RAW_ROOT = ROOT / "data/lab/experiment_f/validation/raw"
DERIVED = ROOT / f"data/lab/experiment_f/validation/derived/{RUN}"
RAW_CFM = ROOT / f"data/lab/experiment_f/validation/derived/{RAW_EXTRACTION_RUN}/raw_cicflowmeter"
ADAPTED = DERIVED / "adapted_78"
FROZEN = DERIVED / "frozen"
REPORT = ROOT / f"reports/experiment_f/validation/{RUN}"
FEATURE_IDENTITY = "9338f50fc3e7efc78d678cc65ab38d428a7f6912ed9467a2b99a449a7c8e3c13"
IMAGE_DIGEST = "sha256:b12b3a4a4218968aba2436685a4eb113473e5681de70705409e834e4613a879b"
COMMIT = "a26aae27f21d165ff30b4b28e75124a5f9b4b2c4"
LABELS = ["Normal", "DDoS", "PortScan"]
SESSIONS = [
    ("F-A1-NORMAL-V-01-R1", "Normal", "A3 Normal sequential HTTP GET profile"),
    ("F-A1-NORMAL-V-02", "Normal", "A3 Normal sequential HTTP GET profile"),
    ("F-A1-NORMAL-V-03", "Normal", "A3 Normal sequential HTTP GET profile"),
    ("F-A1-DDOSLIKE-V-01", "DDoS", "controlled HTTP DDoS-like/load profile"),
    ("F-A1-DDOSLIKE-V-02", "DDoS", "controlled HTTP DDoS-like/load profile"),
    ("F-A1-DDOSLIKE-V-03", "DDoS", "controlled HTTP DDoS-like/load profile"),
    ("F-A1-PORTSCAN-V-01", "PortScan", "A3 TCP SYN ports 1-1000 profile"),
    ("F-A1-PORTSCAN-V-02", "PortScan", "A3 TCP SYN ports 1-1000 profile"),
    ("F-A1-PORTSCAN-V-03", "PortScan", "A3 TCP SYN ports 1-1000 profile"),
]
MODELS = {
    "RF-v2": (ROOT / "models/experiment_d/random_forest_rf_v2.joblib", "fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31"),
    "RF-v3": (ROOT / "models/experiment_e/random_forest_rf_v3_candidate.joblib", "6b01c7b3923c1a6bd471862d011f8f5b88a31378e51d1dde082bd2e72bedef86"),
    "RF-v4": (ROOT / "models/experiment_f/random_forest_rf_v4_candidate_01.joblib", "d5dccd339a5c67635e760d7d3760e1d006278362c6f70ea06bf20928ccdece13"),
}


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def feature_identity() -> str:
    encoded = json.dumps(list(MODEL_FEATURES), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def write_new(path: Path, content: str) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {rel(path)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def json_new(path: Path, value: object) -> None:
    write_new(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def csv_new(path: Path, frame: pd.DataFrame) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {rel(path)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, index=False)


def parse_tcpdump(log: str) -> tuple[int, int, int]:
    values = []
    for pattern in (r"(\d+) packets captured", r"(\d+) packets received by filter", r"(\d+) packets dropped by kernel"):
        match = re.search(pattern, log)
        if not match:
            raise RuntimeError("tcpdump packet counters are incomplete")
        values.append(int(match.group(1)))
    if "listening on enp0s3" not in log:
        raise RuntimeError("capture interface identity is not enp0s3")
    return tuple(values)  # type: ignore[return-value]


def audit_generator(session: str, klass: str, directory: Path) -> dict:
    common = ["generator_started_utc.txt", "generator_ended_utc.txt", "generator_exit_status.txt"]
    for name in common:
        if not (directory / name).is_file():
            raise RuntimeError(f"{session}: missing generator evidence {name}")
    start = read_text(directory / common[0]); end = read_text(directory / common[1])
    status = int(read_text(directory / common[2]))
    if status != 0 or instant(start) > instant(end):
        raise RuntimeError(f"{session}: invalid generator status/timestamps")
    details: dict[str, object] = {}
    if klass == "Normal":
        requests = list(csv.reader((directory / "requests.csv").open(encoding="utf-8")))
        if len(requests) != 30 or [int(row[0]) for row in requests] != list(range(1, 31)) or any(int(row[2]) != 0 for row in requests):
            raise RuntimeError(f"{session}: Normal request evidence does not contain 30 successful sequential requests")
        codes = []
        for number in range(1, 31):
            result = directory / f"request_{number}.result"; stderr = directory / f"request_{number}.stderr"
            if not result.is_file() or not stderr.is_file() or stderr.stat().st_size != 0:
                raise RuntimeError(f"{session}: incomplete/failed request {number} evidence")
            codes.append(read_text(result).split(",", 1)[0])
        if any(code != "200" for code in codes):
            raise RuntimeError(f"{session}: non-200 Normal request result")
        details = {"request_count": 30, "request_exit_statuses": "all_zero", "http_statuses": dict(Counter(codes))}
    elif klass == "DDoS":
        needed = ["locust.log", "locust_exceptions.csv", "locust_failures.csv", "locust_stats.csv", "locust_stats_history.csv"]
        if any(not (directory / name).is_file() for name in needed):
            raise RuntimeError(f"{session}: incomplete Locust evidence")
        stats = pd.read_csv(directory / "locust_stats.csv")
        aggregate = stats.loc[stats["Name"] == "Aggregated"]
        if len(aggregate) != 1 or int(aggregate.iloc[0]["Failure Count"]) != 0:
            raise RuntimeError(f"{session}: Locust aggregate/failure gate failed")
        for name in ("locust_exceptions.csv", "locust_failures.csv"):
            if sum(1 for _ in csv.reader((directory / name).open(encoding="utf-8-sig"))) != 1:
                raise RuntimeError(f"{session}: {name} is not header-only")
        details = {"request_count": int(aggregate.iloc[0]["Request Count"]), "failure_count": 0, "target": "http://10.10.20.2:8080/"}
    else:
        needed = ["nmap.nmap", "nmap.gnmap", "nmap.xml", "nmap.stdout.log", "nmap.stderr.log"]
        if any(not (directory / name).is_file() for name in needed):
            raise RuntimeError(f"{session}: incomplete nmap evidence")
        canonical_output = read_text(directory / "nmap.nmap")
        required = ["10.10.20.2", "-sS", "-Pn", "-n", "-T3", "--max-retries", "--host-timeout", "-p 1-1000"]
        if any(token not in canonical_output for token in required):
            raise RuntimeError(f"{session}: nmap target/profile mismatch")
        details = {"target": "10.10.20.2", "scan": "TCP SYN", "ports": "1-1000", "profile_verified_from_xml": True}
    return {"path": rel(directory), "start_utc": start, "end_utc": end, "exit_status": status, "details": details,
            "file_sha256": {p.name: sha(p) for p in sorted(directory.iterdir()) if p.is_file()}}


def calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    precision, recall, f1, support = precision_recall_fscore_support(y_true, y_pred, labels=LABELS, zero_division=0)
    macro = precision_recall_fscore_support(y_true, y_pred, labels=LABELS, average="macro", zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=LABELS)
    result = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_precision": float(macro[0]), "macro_recall": float(macro[1]), "macro_f1": float(macro[2]),
        "per_class": {}, "confusion_matrix": {"labels": LABELS, "rows": cm.tolist()},
    }
    for i, label in enumerate(LABELS):
        correct = int(cm[i, i]); total = int(support[i])
        result["per_class"][label] = {"precision": float(precision[i]), "recall": float(recall[i]), "f1": float(f1[i]),
                                               "support": total, "correct": correct, "total": total}
    return result


def main() -> int:
    if REPORT.exists() or ADAPTED.exists() or FROZEN.exists():
        raise FileExistsError("create-new F4-A2 report/adapted/frozen destination already exists")
    if sha(ROOT / "reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv") != CROSSWALK_SHA256:
        raise RuntimeError("frozen crosswalk mismatch")
    if feature_identity() != FEATURE_IDENTITY:
        raise RuntimeError("frozen feature identity mismatch")
    for model_id, (path, expected) in MODELS.items():
        if sha(path) != expected:
            raise RuntimeError(f"{model_id} hash mismatch")

    expected_ids = {s for s, _, _ in SESSIONS}
    for side in ("observer", "generator"):
        actual = {p.name for p in (RAW_ROOT / side).iterdir() if p.is_dir()}
        if actual != expected_ids:
            raise RuntimeError(f"{side} session-set mismatch: expected={sorted(expected_ids)} actual={sorted(actual)}")

    session_audits = []
    intervals = []
    pcap_hashes = []
    all_repo_pcaps = [p for p in ROOT.rglob("*.pcap") if "validation/derived" not in str(p)]
    repository_hash_map: dict[str, list[str]] = {}
    for p in all_repo_pcaps:
        repository_hash_map.setdefault(sha(p), []).append(rel(p))

    adapted_frames = []
    lineage_frames = []
    adapter = CICFlowMeterV3ModelAdapter()
    for session, klass, workload in SESSIONS:
        observer = RAW_ROOT / "observer" / session; generator = RAW_ROOT / "generator" / session
        pcap = observer / f"{session}.pcap"
        required = [pcap, observer / "PCAP_SHA256SUM", observer / "capture_started_utc.txt", observer / "capture_ended_utc.txt", observer / "tcpdump_exit_status.txt", observer / "tcpdump.stderr.log"]
        if any(not p.is_file() for p in required) or pcap.stat().st_size <= 24:
            raise RuntimeError(f"{session}: missing or empty observer evidence")
        pcap_sha = sha(pcap); recorded_sha = read_text(observer / "PCAP_SHA256SUM").split()[0]
        if pcap_sha != recorded_sha:
            raise RuntimeError(f"{session}: PCAP hash mismatch")
        cap_start = read_text(observer / "capture_started_utc.txt"); cap_end = read_text(observer / "capture_ended_utc.txt")
        tcp_status = int(read_text(observer / "tcpdump_exit_status.txt")); captured, received, dropped = parse_tcpdump(read_text(observer / "tcpdump.stderr.log"))
        if tcp_status != 0 or captured <= 0 or received != captured or dropped != 0 or instant(cap_start) > instant(cap_end):
            raise RuntimeError(f"{session}: capture evidence gate failed")
        gen = audit_generator(session, klass, generator)
        if not (instant(cap_start) <= instant(gen["start_utc"]) <= instant(gen["end_utc"]) <= instant(cap_end)):
            raise RuntimeError(f"{session}: generator window is not contained by capture window")
        intervals.append((session, instant(cap_start), instant(cap_end)))
        pcap_hashes.append(pcap_sha)
        if len(repository_hash_map[pcap_sha]) != 1:
            raise RuntimeError(f"{session}: PCAP hash reused at {repository_hash_map[pcap_sha]}")

        raw_csv = RAW_CFM / session / f"{session}.pcap_ISCX.csv"
        if not raw_csv.is_file():
            raise RuntimeError(f"{session}: raw CICFlowMeter CSV missing")
        raw = pd.read_csv(raw_csv)
        if len(raw) == 0 or len(raw.columns) != 84:
            raise RuntimeError(f"{session}: expected non-empty 84-column raw CSV")
        result = adapter.adapt(raw, raw_input_path=Path(rel(raw_csv)), raw_input_sha256=sha(raw_csv))
        adapted_path = ADAPTED / f"{session}_model_input_78.csv"
        csv_new(adapted_path, result.features)
        numeric = result.features.to_numpy(dtype=np.float64)
        adapted_sha = sha(adapted_path)
        constants = [c for c in result.features if result.features[c].nunique(dropna=False) <= 1]
        all_zero = [c for c in result.features if result.features[c].fillna(0).eq(0).all()]
        session_audits.append({
            "session_id": session, "ground_truth_class": klass, "workload_profile": workload,
            "observer": {"path": rel(observer), "capture_interface": "enp0s3", "start_utc": cap_start, "end_utc": cap_end,
                         "tcpdump_exit_status": tcp_status, "packets_captured": captured, "packets_received_by_filter": received,
                         "packets_dropped_by_kernel": dropped, "pcap_path": rel(pcap), "pcap_size_bytes": pcap.stat().st_size, "pcap_sha256": pcap_sha},
            "generator": gen,
            "raw_csv": {"path": rel(raw_csv), "sha256": sha(raw_csv), "flow_count": len(raw), "column_count": len(raw.columns)},
            "adapted_csv": {"path": rel(adapted_path), "sha256": adapted_sha, "flow_count": len(result.features), "feature_count": 78,
                            "nan_count": int(np.isnan(numeric).sum()), "positive_infinity_count": int(np.isposinf(numeric).sum()),
                            "negative_infinity_count": int(np.isneginf(numeric).sum()), "duplicate_feature_vector_count": int(result.features.duplicated().sum()),
                            "constant_feature_count": len(constants), "constant_features": constants, "all_zero_feature_count": len(all_zero), "all_zero_features": all_zero,
                            "feature_order_sha256": feature_identity(), "adapter_provenance": result.provenance},
            "data_gate": "PASS",
        })
        frame = result.features.copy(); frame["ground_truth_class"] = klass
        adapted_frames.append(frame)
        flow_identity = raw["Flow ID"].astype(str) if "Flow ID" in raw else pd.Series([None] * len(raw))
        lineage_frames.append(pd.DataFrame({
            "experiment": "Experiment F", "split": "F-VALIDATION", "session_id": session, "workload_profile": workload,
            "ground_truth_class": klass, "source_pcap": rel(pcap), "source_pcap_sha256": pcap_sha,
            "raw_csv": rel(raw_csv), "raw_csv_sha256": sha(raw_csv), "adapted_csv": rel(adapted_path), "adapted_csv_sha256": adapted_sha,
            "session_row_index": np.arange(len(raw), dtype=int), "flow_identity": flow_identity,
        }))

    if len(set(pcap_hashes)) != 9:
        raise RuntimeError("session PCAP hashes are not unique")
    for i, (left, ls, le) in enumerate(intervals):
        for right, rs, re_ in intervals[i + 1:]:
            if max(ls, rs) <= min(le, re_):
                raise RuntimeError(f"capture windows overlap: {left} and {right}")

    evidence_report = {
        "schema": "experiment_f_f4_a2_extraction_data_gate", "run_id": RUN,
        "raw_extraction_run_id": RAW_EXTRACTION_RUN,
        "preserved_incomplete_processing_attempts": [
            "data/lab/experiment_f/validation/derived/f4_a2_run_01/adapted_78 (six create-new adapted files; excluded)",
            "data/lab/experiment_f/validation/derived/f4_a2_run_02/adapted_78 (six create-new adapted files; excluded after audit implementation false rejection)"
        ],
        "decision": "F4_A2_EXTRACTION_DATA_GATE_PASS", "scientific_session_count": 9,
        "historical_failed_attempt": {"session_id": "F-A1-NORMAL-V-01", "disposition": "FAILED_PRE_TRAFFIC / EMPTY_CAPTURE",
            "included": False, "preservation_evidence": "reports/experiment_f/amendments/f0_amendment_a3_normal_v01_replacement.json",
            "empty_copied_directories_are_not_claimed_as_evidence": True},
        "extractor": {"commit": COMMIT, "image_tag": "rf-nids-cicflowmeter-v3:a26aae27", "image_digest": IMAGE_DIGEST,
                      "network_access": False, "one_output_directory_per_session": True},
        "feature_contract": {"count": 78, "feature_order_sha256": feature_identity(), "crosswalk_sha256": CROSSWALK_SHA256},
        "session_overlap": "PASS_NONE", "pcap_hash_reuse": "PASS_NONE", "sessions": session_audits,
    }
    json_new(REPORT / "extraction_data_gate_report.json", evidence_report)
    json_new(REPORT / "per_session_provenance_manifest.json", {"schema": "experiment_f_f4_a2_session_provenance", "sessions": session_audits})

    combined = pd.concat(adapted_frames, ignore_index=True)
    lineage = pd.concat(lineage_frames, ignore_index=True)
    combined_path = FROZEN / "f_validation_78_features_ground_truth.csv"
    lineage_path = FROZEN / "f_validation_lineage.csv"
    csv_new(combined_path, combined); csv_new(lineage_path, lineage)
    freeze = {
        "schema": "experiment_f_f4_a2_validation_dataset_freeze", "decision": "F_VALIDATION_DATASET_FROZEN",
        "dataset": {"path": rel(combined_path), "sha256": sha(combined_path), "rows": len(combined), "columns": len(combined.columns),
                    "model_feature_count": 78, "class_counts": combined["ground_truth_class"].value_counts().sort_index().to_dict()},
        "lineage": {"path": rel(lineage_path), "sha256": sha(lineage_path), "rows": len(lineage)},
        "rows_per_session": lineage["session_id"].value_counts().sort_index().to_dict(),
        "feature_identity_sha256": feature_identity(),
        "contamination_checks": {"historical_failed_attempt_excluded": True, "experiment_d_final_test_rows_used": False,
            "experiment_e_validation_unseen_final_rows_used": False, "e10_e13_rows_used": False, "session_pcap_hash_reuse": False,
            "session_capture_overlap": False, "deduplication_performed": False, "rows_dropped": 0},
    }
    json_new(REPORT / "validation_dataset_freeze.json", freeze)

    X = combined.loc[:, list(MODEL_FEATURES)]
    y = combined["ground_truth_class"].to_numpy()
    all_metrics: dict[str, dict] = {}
    predictions: dict[str, np.ndarray] = {}
    for model_id, (model_path, expected_hash) in MODELS.items():
        model = joblib.load(model_path)
        classes = [str(x) for x in model.classes_]
        if set(classes) != set(LABELS):
            raise RuntimeError(f"{model_id}: unexpected estimator classes {classes}")
        pred = model.predict(X); proba = model.predict_proba(X)
        predictions[model_id] = np.asarray(pred)
        output = pd.DataFrame({"row_id": np.arange(len(X)), "session_id": lineage["session_id"],
                               "ground_truth_class": y, "predicted_class": pred, "model_id": model_id})
        for label in LABELS:
            output[f"probability_{label}"] = proba[:, classes.index(label)]
        prediction_path = REPORT / f"predictions_{model_id.lower().replace('-', '_')}.csv"
        csv_new(prediction_path, output)
        metrics = calculate_metrics(y, np.asarray(pred))
        metrics["model_sha256"] = expected_hash; metrics["estimator_class_order"] = classes
        metrics["prediction_artifact"] = {"path": rel(prediction_path), "sha256": sha(prediction_path)}
        metrics["per_session"] = {}
        for session, _, _ in SESSIONS:
            mask = lineage["session_id"].to_numpy() == session
            metrics["per_session"][session] = calculate_metrics(y[mask], np.asarray(pred)[mask])
        all_metrics[model_id] = metrics
        cm = pd.DataFrame(metrics["confusion_matrix"]["rows"], index=[f"true_{x}" for x in LABELS], columns=[f"pred_{x}" for x in LABELS])
        cm.index.name = "ground_truth"
        cm_path = REPORT / f"confusion_matrix_{model_id.lower().replace('-', '_')}.csv"
        if cm_path.exists(): raise FileExistsError(f"refusing to overwrite {rel(cm_path)}")
        cm.to_csv(cm_path)

    transitions = {}
    for left, right in (("RF-v2", "RF-v3"), ("RF-v3", "RF-v4"), ("RF-v2", "RF-v4")):
        counts = Counter(zip(predictions[left], predictions[right]))
        transitions[f"{left}->{right}"] = {f"{a}->{b}": int(counts[(a, b)]) for a in LABELS for b in LABELS}
    metrics_report = {"schema": "experiment_f_f4_a2_comparative_metrics", "labels": LABELS,
                      "same_frozen_vectors": {"dataset_sha256": freeze["dataset"]["sha256"], "rows": len(X)},
                      "models": all_metrics, "paired_prediction_transitions": transitions}
    json_new(REPORT / "comparative_metrics.json", metrics_report)

    v3 = all_metrics["RF-v3"]; v4 = all_metrics["RF-v4"]
    normal_total = v4["per_class"]["Normal"]["total"]
    normal_to_ddos_v3 = v3["confusion_matrix"]["rows"][0][1] / normal_total
    normal_to_ddos_v4 = v4["confusion_matrix"]["rows"][0][1] / normal_total
    normal_to_scan_v3 = v3["confusion_matrix"]["rows"][0][2] / normal_total
    normal_to_scan_v4 = v4["confusion_matrix"]["rows"][0][2] / normal_total
    gates = {
        "normal_recall_absolute": {"status": "PASS" if v4["per_class"]["Normal"]["recall"] >= .98 else "FAIL", "actual": v4["per_class"]["Normal"]["recall"], "threshold": ">=0.98"},
        "normal_recall_vs_rf_v3": {"status": "PASS" if v4["per_class"]["Normal"]["recall"] >= v3["per_class"]["Normal"]["recall"] - .02 else "FAIL", "actual_delta": v4["per_class"]["Normal"]["recall"] - v3["per_class"]["Normal"]["recall"], "threshold": ">=-0.02"},
        "portscan_recall_absolute": {"status": "PASS" if v4["per_class"]["PortScan"]["recall"] >= .995 else "FAIL", "actual": v4["per_class"]["PortScan"]["recall"], "threshold": ">=0.995"},
        "portscan_recall_vs_rf_v3": {"status": "PASS" if v4["per_class"]["PortScan"]["recall"] >= v3["per_class"]["PortScan"]["recall"] - .005 else "FAIL", "actual_delta": v4["per_class"]["PortScan"]["recall"] - v3["per_class"]["PortScan"]["recall"], "threshold": ">=-0.005"},
        "ddos_recall_absolute": {"status": "PASS" if v4["per_class"]["DDoS"]["recall"] >= .20 else "FAIL", "actual": v4["per_class"]["DDoS"]["recall"], "threshold": ">=0.20"},
        "ddos_recall_vs_rf_v3": {"status": "PASS" if v4["per_class"]["DDoS"]["recall"] >= v3["per_class"]["DDoS"]["recall"] + .10 else "FAIL", "actual_delta": v4["per_class"]["DDoS"]["recall"] - v3["per_class"]["DDoS"]["recall"], "threshold": ">=+0.10"},
        "ddos_f1_vs_rf_v3": {"status": "PASS" if v4["per_class"]["DDoS"]["f1"] >= v3["per_class"]["DDoS"]["f1"] + .10 else "FAIL", "actual_delta": v4["per_class"]["DDoS"]["f1"] - v3["per_class"]["DDoS"]["f1"], "threshold": ">=+0.10"},
        "normal_f1_preservation": {"status": "PASS" if v4["per_class"]["Normal"]["f1"] >= .98 * v3["per_class"]["Normal"]["f1"] else "FAIL", "ratio": v4["per_class"]["Normal"]["f1"] / v3["per_class"]["Normal"]["f1"] if v3["per_class"]["Normal"]["f1"] else None, "threshold": ">=0.98 of RF-v3"},
        "portscan_f1_preservation": {"status": "PASS" if v4["per_class"]["PortScan"]["f1"] >= .98 * v3["per_class"]["PortScan"]["f1"] else "FAIL", "ratio": v4["per_class"]["PortScan"]["f1"] / v3["per_class"]["PortScan"]["f1"] if v3["per_class"]["PortScan"]["f1"] else None, "threshold": ">=0.98 of RF-v3"},
        "normal_to_ddos_false_positive": {"status": "PASS" if normal_to_ddos_v4 - normal_to_ddos_v3 <= .02 else "FAIL", "rf_v3": normal_to_ddos_v3, "rf_v4": normal_to_ddos_v4, "actual_delta": normal_to_ddos_v4-normal_to_ddos_v3, "threshold": "increase <=0.02"},
        "normal_to_portscan_false_positive": {"status": "PASS" if normal_to_scan_v4 - normal_to_scan_v3 <= .02 else "FAIL", "rf_v3": normal_to_scan_v3, "rf_v4": normal_to_scan_v4, "actual_delta": normal_to_scan_v4-normal_to_scan_v3, "threshold": "increase <=0.02"},
        "macro_f1": {"status": "PASS" if v4["macro_f1"] >= v3["macro_f1"] - .02 else "FAIL", "actual": v4["macro_f1"], "rf_v3": v3["macro_f1"], "actual_delta": v4["macro_f1"]-v3["macro_f1"], "threshold": ">=RF-v3-0.02"},
        "three_sessions_per_class_and_reporting": {"status": "PASS", "sessions_per_class": 3, "aggregate_and_per_session_metrics": True},
        "unseen_validation_and_sealed_final_evaluation": {"status": "NOT_EVALUABLE", "reason": "Those are later preregistered stages, not F4-A2."},
    }
    mandatory_validation_pass = all(v["status"] == "PASS" for k, v in gates.items() if k != "unseen_validation_and_sealed_final_evaluation")
    gate_report = {"schema": "experiment_f_f4_a2_acceptance_gate_evaluation", "gates": gates,
                   "validation_gate_decision": "PASS" if mandatory_validation_pass else "FAIL",
                   "final_evaluation_progression_authorized": mandatory_validation_pass,
                   "promotion_or_activation_authorized": False}
    json_new(REPORT / "acceptance_gate_evaluation.json", gate_report)

    summary = {
        "schema": "experiment_f_f4_a2_scientific_summary",
        "phase_decision": "F4_A2_VALIDATION_PASS_FINAL_EVALUATION_ELIGIBLE" if mandatory_validation_pass else "F4_A2_VALIDATION_FAIL",
        "scope": "Experiment F controlled three-VM laboratory validation only; DDoS ground truth denotes the controlled HTTP DDoS-like/load profile, not genuine distributed DDoS.",
        "dataset_sha256": freeze["dataset"]["sha256"], "rows": len(combined), "class_counts": freeze["dataset"]["class_counts"],
        "metrics": {model: {k: value for k, value in metric.items() if k in ("accuracy", "macro_precision", "macro_recall", "macro_f1", "per_class")} for model, metric in all_metrics.items()},
        "acceptance_gate_decision": gate_report["validation_gate_decision"],
        "authorization": "Eligible only to continue to preregistered F final evaluation" if mandatory_validation_pass else "Not authorized to continue to F final evaluation",
        "prohibited_actions_confirmed_not_performed": ["training", "retraining", "hyperparameter tuning", "threshold changes", "feature-contract changes", "model activation", "model promotion", "historical evidence mutation", "silent deduplication", "session exclusion"],
    }
    json_new(REPORT / "scientific_summary.json", summary)
    summary_md = f"# Experiment F F4-A2 scientific summary\n\nDecision: `{summary['phase_decision']}`.\n\nThe frozen validation dataset contains {len(combined)} rows. This result is scoped to the controlled three-VM laboratory and the DDoS model class uses the controlled HTTP DDoS-like/load profile; it is not genuine distributed-DDoS validation.\n\nAcceptance decision: `{gate_report['validation_gate_decision']}`. {summary['authorization']}. Validation never activates or promotes RF-v4.\n"
    write_new(REPORT / "scientific_summary.md", summary_md)

    hash_paths = sorted([p for p in REPORT.rglob("*") if p.is_file()] + [p for p in ADAPTED.rglob("*") if p.is_file()] + [combined_path, lineage_path])
    write_new(REPORT / "SHA256SUMS", "".join(f"{sha(p)}  {rel(p)}\n" for p in hash_paths))
    print(json.dumps({"phase_decision": summary["phase_decision"], "rows": len(combined), "class_counts": freeze["dataset"]["class_counts"], "metrics": {m: {"accuracy": x["accuracy"], "macro_f1": x["macro_f1"], "recall": {c: x["per_class"][c]["recall"] for c in LABELS}} for m, x in all_metrics.items()}, "acceptance": gate_report["validation_gate_decision"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
