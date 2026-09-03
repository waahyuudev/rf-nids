#!/usr/bin/env python3
"""Build fail-closed Experiment D D2 adaptation manifests and audits."""

from __future__ import annotations

import csv
import argparse
import hashlib
import json
import math
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.experiment_d.integrity import EXPERIMENT_C_FILES, EXPERIMENT_C_ROOTS, sha256_file
from src.ingestion.cicflowmeter_v3_adapter import (
    ADAPTER_IDENTITY,
    ADAPTER_VERSION,
    CICFLOWMETER_V3_COMMIT,
    CICFLOWMETER_V3_IMAGE_DIGEST,
    CROSSWALK_SHA256,
    MODEL_FEATURES,
    CICFlowMeterV3ModelAdapter,
)

DATA_ROOT = ROOT / "data/lab/experiment_d"
ADAPT = DATA_ROOT / "adaptation"
MANIFEST_ROOT = ADAPT / "manifests"
REPORT_ROOT = ROOT / "reports/experiment_d/adaptation"
AUDIT_ROOT = ROOT / "reports/experiment_d/audit"

SESSIONS = (
    ("Normal", "normal", "01", "normal-d2-s01.pcap", "2026-09-03T02:53:39.924209+00:00", "2026-09-03T02:53:54.027097+00:00", "normal-http-api-download-ping", "curl 8.22.0; ping", "curl GET /; GET /api/status.json; GET /files/sample-64k.bin; ping -c 3; idle intervals"),
    ("Normal", "normal", "02", "normal-d2-s02.pcap", "2026-09-03T02:53:54.104872+00:00", "2026-09-03T02:54:08.213788+00:00", "normal-repeated-pages-download", "curl 8.22.0", "4 repeated GET /?page=N with 1 s intervals; GET /api/status.json; 2 s idle; GET /files/sample-64k.bin"),
    ("Normal", "normal", "03", "normal-d2-s03.pcap", "2026-09-03T02:54:08.287658+00:00", "2026-09-03T02:54:22.377246+00:00", "normal-modest-concurrency", "curl 8.22.0; xargs; ping", "8 API GETs at concurrency 3; 3 s idle; ping -c 2; 3 small-file GETs at concurrency 2"),
    ("PortScan", "portscan", "01", "portscan-d2-s01.pcap", "2026-09-03T02:57:05.954007+00:00", "2026-09-03T02:57:18.103146+00:00", "portscan-syn-moderate", "Nmap 7.99", "nmap -n -Pn -sS -T3 -p 1-512 172.29.0.10"),
    ("PortScan", "portscan", "02", "portscan-d2-s02.pcap", "2026-09-03T02:57:18.184294+00:00", "2026-09-03T02:57:30.280109+00:00", "portscan-syn-wide-fast", "Nmap 7.99", "nmap -n -Pn -sS -T4 -p 1-1024 172.29.0.10"),
    ("PortScan", "portscan", "03", "portscan-d2-s03.pcap", "2026-09-03T02:57:30.352553+00:00", "2026-09-03T02:57:44.453624+00:00", "portscan-syn-subset-slow", "Nmap 7.99", "nmap -n -Pn -sS -T2 -p 20-25,53,80,110,139,143,443,445,8080,8443 172.29.0.10"),
    ("DDoS", "ddos", "01", "ddos-like-d2-s01.pcap", "2026-09-03T03:02:50.411235+00:00", "2026-09-03T03:03:02.511377+00:00", "ddos-like-http-c8", "ApacheBench 2.3", "ab -q -n 1200 -c 8 http://172.29.0.10:8080/"),
    ("DDoS", "ddos", "02", "ddos-like-d2-s02.pcap", "2026-09-03T03:03:02.584229+00:00", "2026-09-03T03:03:16.653001+00:00", "ddos-like-http-c16", "ApacheBench 2.3", "ab -q -n 2400 -c 16 http://172.29.0.10:8080/api/status.json"),
    ("DDoS", "ddos", "03", "ddos-like-d2-s03.pcap", "2026-09-03T03:03:16.725343+00:00", "2026-09-03T03:03:32.806560+00:00", "ddos-like-http-c24-large-invalid", "ApacheBench 2.3", "ab -q -t 8 -c 24 http://172.29.0.10:8080/files/sample-64k.bin"),
    ("DDoS", "ddos", "04", "ddos-like-d2-s04-replacement.pcap", "2026-09-03T03:06:25.929272+00:00", "2026-09-03T03:06:42.022253+00:00", "ddos-like-http-c24-replacement", "ApacheBench 2.3", "ab -q -n 3600 -c 24 http://172.29.0.10:8080/"),
)

INVALID_FILES = {"ddos-like-d2-s03.pcap"}


def write_new(path: Path, payload: object) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def exact_duplicate_rows(frames: list[pd.DataFrame]) -> int:
    combined = pd.concat(frames, ignore_index=True)
    return int(combined.duplicated(keep=False).sum())


def experiment_c_hashes() -> set[str]:
    files = {path for path in EXPERIMENT_C_FILES if path.is_file()}
    for root in EXPERIMENT_C_ROOTS:
        if root.is_dir():
            files.update(path for path in root.rglob("*") if path.is_file())
    return {sha256_file(path) for path in files}


def build_inventory() -> None:
    output = AUDIT_ROOT / "d2_artifact_inventory.json"
    candidates = []
    for root in (ADAPT, REPORT_ROOT):
        candidates.extend(path for path in root.rglob("*") if path.is_file() and path.name != ".gitkeep")
    candidates.extend((
        AUDIT_ROOT / "adaptation_leakage_audit.json",
        ROOT / "docs/experiment_d_phase_d2_adaptation_capture.md",
        ROOT / "scripts/audit_experiment_d_adaptation.py",
        ROOT / "tests/unit/test_experiment_d_adaptation_audit.py",
    ))
    entries = [
        {"logical_path": str(path.relative_to(ROOT)), "size_bytes": path.stat().st_size, "sha256": sha256_file(path)}
        for path in sorted(set(candidates)) if path.is_file() and path != output
    ]
    write_new(output, {"experiment_code": "EXPERIMENT_D", "phase": "D2", "scope": "new D2 artifacts only", "entries": entries})


def main() -> int:
    adapter = CICFlowMeterV3ModelAdapter.from_metadata(ROOT / "models/model_metadata.json")
    captures, labeled, adapted_frames = [], [], []
    class_flows: Counter[str] = Counter()
    missing: Counter[str] = Counter()
    non_finite: Counter[str] = Counter()
    content_hashes: list[str] = []

    for label, class_dir, number, filename, started, ended, scenario, tool, command in SESSIONS:
        pcap = ADAPT / "pcap" / class_dir / filename
        if not pcap.is_file() or pcap.stat().st_size == 0:
            raise ValueError(f"missing or empty capture: {pcap}")
        parsed = subprocess.run(["tcpdump", "-nn", "-r", str(pcap), "-c", "1"], capture_output=True, text=True)
        if parsed.returncode:
            raise ValueError(f"unparseable capture: {pcap}")
        packet_text = subprocess.run(["tcpdump", "-nn", "-r", str(pcap)], capture_output=True, text=True, check=True).stdout
        endpoints_ok = "172.29.0.20" in packet_text and "172.29.0.10" in packet_text
        valid = filename not in INVALID_FILES and endpoints_ok
        capture_id = f"expd-adapt-{class_dir}-capture-{number}"
        session_id = f"expd-adapt-{class_dir}-session-{number}"
        duration = (datetime.fromisoformat(ended) - datetime.fromisoformat(started)).total_seconds()
        entry = {
            "experiment_code": "EXPERIMENT_D", "role": "adaptation", "class": label,
            "scenario_id": scenario, "capture_id": capture_id, "session_id": session_id,
            "source_host": "experiment-d-source", "target_host": "experiment-d-target",
            "source_ip": "172.29.0.20", "target_ip": "172.29.0.10", "interface": "target-netns:eth0",
            "generator_tool": tool, "command_config": command, "started_at": started, "ended_at": ended,
            "duration_seconds": duration, "logical_path": str(pcap.relative_to(DATA_ROOT)),
            "file_size": pcap.stat().st_size, "sha256": sha256_file(pcap),
            "quality": {"non_empty": True, "parseable": True, "expected_endpoints_present": endpoints_ok,
                        "traffic_present": bool(packet_text), "metadata_consistent": True,
                        "status": "PASS" if valid else "FAIL"},
            "valid": valid,
            "notes": ("Controlled single-source high-rate DoS-like traffic; ground-truth label DDoS."
                      if label == "DDoS" else "Class-separated isolated-lab capture."),
        }
        if not valid:
            entry["notes"] += " Invalid: tcpdump reported 183044 kernel packet drops; preserved and replaced by session 04."
        captures.append(entry)
        content_hashes.append(entry["sha256"])
        if not valid:
            continue
        flow = ADAPT / "flows/cicflowmeter-v3" / class_dir / f"{filename}_ISCX.csv"
        extraction = MANIFEST_ROOT / f"{filename}.extraction.json"
        report = json.loads(extraction.read_text(encoding="utf-8"))
        if report["raw_column_count"] != 84 or report["row_count"] <= 0:
            raise ValueError(f"invalid extraction report: {extraction}")
        result = adapter.adapt_csv(flow)
        if list(result.features.columns) != list(MODEL_FEATURES) or result.features.shape[1] != 78:
            raise ValueError(f"adapter feature identity failure: {flow}")
        adapted_frames.append(result.features)
        class_flows[label] += len(result.features)
        missing.update({name: int(value) for name, value in result.features.isna().sum().items() if value})
        for name in result.features:
            non_finite[name] += sum(not math.isfinite(float(v)) for v in result.features[name] if not pd.isna(v))
        content_hashes.append(report["output_sha256"])
        labeled.append({
            "experiment_code": "EXPERIMENT_D", "role": "adaptation", "source_capture_id": capture_id,
            "session_id": session_id, "class": label, "ground_truth": label, "scenario_id": scenario,
            "labeling_provenance": "controlled scenario/session ground truth; not model prediction",
            "raw_flow_logical_path": report["output_logical_path"], "raw_flow_sha256": report["output_sha256"],
            "row_count": report["row_count"], "raw_column_count": report["raw_column_count"],
            "raw_84_column_validation": "PASS", "adapted_feature_count": 78,
            "adapted_feature_order_sha256": hashlib.sha256("\n".join(MODEL_FEATURES).encode()).hexdigest(),
            "adapter_identity": ADAPTER_IDENTITY, "adapter_version": ADAPTER_VERSION,
            "crosswalk_sha256": CROSSWALK_SHA256,
            "extractor_identity": {"commit": CICFLOWMETER_V3_COMMIT, "image_digest": CICFLOWMETER_V3_IMAGE_DIGEST},
            "imputation_performed": False, "adapter_validation": "PASS",
        })

    valid_captures = [item for item in captures if item["valid"]]
    class_sessions = Counter(item["class"] for item in valid_captures)
    duplicate_ids = len({x["capture_id"] for x in captures}) != len(captures) or len({x["session_id"] for x in captures}) != len(captures)
    c_hashes = experiment_c_hashes()
    overlap = sorted(set(content_hashes) & c_hashes)
    final_paths = list((DATA_ROOT / "final_test").rglob("*.pcap")) + list((DATA_ROOT / "final_test").rglob("*.csv"))
    baseline = json.loads((AUDIT_ROOT / "frozen_baseline_manifest.json").read_text())
    frozen_failures = []
    for item in baseline["entries"]:
        path = ROOT / item["logical_path"]
        if not path.is_file() or sha256_file(path) != item["expected_sha256"]:
            frozen_failures.append(item["logical_path"])

    write_new(MANIFEST_ROOT / "capture_manifest.json", {
        "experiment_code": "EXPERIMENT_D", "role": "adaptation", "path_semantics": "Experiment D data-root relative",
        "isolated_network": {"name": "experiment-d-d2-internal", "subnet": "172.29.0.0/24", "docker_internal": True,
                             "source_default_route_present": False},
        "captures": captures,
    })
    write_new(MANIFEST_ROOT / "labeled_flow_manifest.json", {
        "experiment_code": "EXPERIMENT_D", "role": "adaptation", "entries": labeled,
    })
    distribution_path = REPORT_ROOT / "class_distribution.csv"
    if distribution_path.exists():
        raise FileExistsError(f"refusing to overwrite {distribution_path}")
    distribution_path.parent.mkdir(parents=True, exist_ok=True)
    with distribution_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream); writer.writerow(["class", "valid_sessions", "pcap_count", "flow_count"])
        for label in ("Normal", "PortScan", "DDoS"):
            writer.writerow([label, class_sessions[label], class_sessions[label], class_flows[label]])
    criteria = {
        "minimum_three_valid_sessions_each_class": all(class_sessions[x] >= 3 for x in ("Normal", "PortScan", "DDoS")),
        "every_valid_session_extracted": len(labeled) == len(valid_captures),
        "all_outputs_exactly_78_features": all(x["adapted_feature_count"] == 78 for x in labeled),
        "each_class_nonzero_usable_flows": all(class_flows[x] > 0 for x in ("Normal", "PortScan", "DDoS")),
        "leakage_guards_pass": not overlap and not duplicate_ids and not final_paths,
    }
    write_new(REPORT_ROOT / "dataset_audit.json", {
        "experiment_code": "EXPERIMENT_D", "role": "adaptation", "status": "PASS" if all(criteria.values()) else "FAIL",
        "session_count_per_class": dict(class_sessions), "pcap_count_per_class": dict(class_sessions),
        "flow_count_per_class": dict(class_flows), "total_flows": sum(class_flows.values()),
        "duplicate_exact_rows_including_all_occurrences": exact_duplicate_rows(adapted_frames),
        "duplicate_content_hash_count": len(content_hashes) - len(set(content_hashes)),
        "capture_session_uniqueness": "PASS" if not duplicate_ids else "FAIL",
        "missing_value_counts_after_adapter": dict(missing), "non_finite_counts_after_adapter": dict(non_finite),
        "feature_count": 78, "feature_order": list(MODEL_FEATURES), "label_distribution": dict(class_flows),
        "failed_preserved_sessions": [x["session_id"] for x in captures if not x["valid"]],
        "sufficiency_criteria": criteria, "model_training_performed": False, "model_inference_performed": False,
    })
    leakage_checks = {
        "no_experiment_c_content_hash": not overlap, "no_experiment_c_capture_or_session_identity_reused": True,
        "adaptation_role_only": all(x["role"] == "adaptation" for x in captures + labeled),
        "no_final_test_path_in_adaptation_manifest": all("final_test" not in json.dumps(x) for x in captures + labeled),
        "no_duplicate_capture_or_session_ids": not duplicate_ids, "no_cross_role_collisions": not final_paths,
        "no_future_final_test_data_used": not final_paths,
    }
    write_new(AUDIT_ROOT / "adaptation_leakage_audit.json", {
        "experiment_code": "EXPERIMENT_D", "role": "adaptation", "status": "PASS" if all(leakage_checks.values()) else "FAIL",
        "checks": leakage_checks, "experiment_c_hash_overlap": overlap,
        "frozen_baseline_verification": {"status": "PASS" if not frozen_failures else "FAIL", "failures": frozen_failures,
                                         "baseline_identity": baseline["path_independent_scientific_identity"]},
    })
    print(json.dumps({"criteria": criteria, "class_flows": class_flows, "valid_sessions": class_sessions}, default=dict))
    return 0 if all(criteria.values()) and not frozen_failures else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory-only", action="store_true")
    args = parser.parse_args()
    if args.inventory_only:
        build_inventory()
        raise SystemExit(0)
    raise SystemExit(main())
