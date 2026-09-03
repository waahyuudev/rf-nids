#!/usr/bin/env python3
"""Prepare immutable, fit-free Experiment D D3 manifests and evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.experiment_d.d3 import (  # noqa: E402
    RF_V2_OUTPUTS, assert_session_separation, canonical_json_sha256,
    class_counts, deterministic_cap, encode_index_membership, encode_int64_sequence,
)
from src.experiment_d.integrity import sha256_file  # noqa: E402
from src.ingestion.cicflowmeter_v3_adapter import (  # noqa: E402
    MODEL_FEATURES, CICFlowMeterV3ModelAdapter,
)
from src.preprocessing.columns import normalize_columns  # noqa: E402
from src.preprocessing.labels import map_label  # noqa: E402

ADAPT = ROOT / "data/lab/experiment_d/adaptation"
REPORT = ROOT / "reports/experiment_d/adaptation"
AUDIT = ROOT / "reports/experiment_d/audit"
SPLIT_PATH = REPORT / "split_manifest.json"
PLAN_PATH = REPORT / "rf_v2_training_plan.json"
CLASSES = ("Normal", "DDoS", "PortScan")
VALIDATION_SESSIONS = {
    "Normal": "expd-adapt-normal-session-03",
    "PortScan": "expd-adapt-portscan-session-03",
    "DDoS": "expd-adapt-ddos-session-04",
}
SEED = 42


def write_json_new(path: Path, value: object) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv_new(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {path}")
    with path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader(); writer.writerows(rows)


def feature_hashes(frame: pd.DataFrame) -> pd.Series:
    normalized = frame.replace([np.inf, -np.inf], np.nan).astype(np.float32)
    return pd.util.hash_pandas_object(normalized, index=False).map(lambda x: f"{int(x):016x}")


def validate_d2() -> tuple[list[dict], list[dict], CICFlowMeterV3ModelAdapter]:
    capture_path = ADAPT / "manifests/capture_manifest.json"
    flow_path = ADAPT / "manifests/labeled_flow_manifest.json"
    captures = json.loads(capture_path.read_text())["captures"]
    entries = json.loads(flow_path.read_text())["entries"]
    audit = json.loads((REPORT / "dataset_audit.json").read_text())
    leakage = json.loads((AUDIT / "adaptation_leakage_audit.json").read_text())
    if audit["status"] != "PASS" or audit["total_flows"] != 15914 or leakage["status"] != "PASS":
        raise ValueError("D2 audit/count/leakage status mismatch")
    for capture in captures:
        pcap = ROOT / "data/lab/experiment_d" / capture["logical_path"]
        if not pcap.is_file() or sha256_file(pcap) != capture["sha256"]:
            raise ValueError(f"D2 capture content hash mismatch: {pcap}")
    valid = [x for x in captures if x["valid"]]
    if Counter(x["class"] for x in valid) != Counter({x: 3 for x in CLASSES}):
        raise ValueError("D2 must contain exactly three valid sessions per class")
    invalid = {x["session_id"] for x in captures if not x["valid"]}
    if invalid != {"expd-adapt-ddos-session-03"}:
        raise ValueError("invalid DDoS session exclusion mismatch")
    if not any(x["session_id"] == "expd-adapt-ddos-session-04" and x["valid"] for x in captures):
        raise ValueError("DDoS session 04 is not valid")
    adapter = CICFlowMeterV3ModelAdapter.from_metadata(ROOT / "models/model_metadata.json")
    for item in entries:
        source = ROOT / "data/lab/experiment_d" / item["raw_flow_logical_path"]
        if sha256_file(source) != item["raw_flow_sha256"]:
            raise ValueError(f"D2 content hash mismatch: {source}")
        result = adapter.adapt_csv(source)
        if list(result.features.columns) != list(MODEL_FEATURES) or result.features.shape[1] != 78:
            raise ValueError(f"D2 feature schema mismatch: {source}")
    return captures, entries, adapter


def adaptation_rows(captures: list[dict], entries: list[dict], adapter: CICFlowMeterV3ModelAdapter):
    capture_by_id = {x["capture_id"]: x for x in captures}
    rows, session_audit, frames = [], [], {}
    for item in entries:
        capture = capture_by_id[item["source_capture_id"]]
        path = ROOT / "data/lab/experiment_d" / item["raw_flow_logical_path"]
        features = adapter.adapt_csv(path).features.replace([np.inf, -np.inf], np.nan).astype(np.float32)
        hashes = feature_hashes(features)
        frames[item["session_id"]] = features
        missing = int(features.isna().sum().sum())
        nonfinite = int(sum(np.isinf(features[c].to_numpy()).sum() for c in features))
        session_audit.append({
            "record_type": "observed", "class": item["class"], "session_id": item["session_id"],
            "capture_id": item["source_capture_id"], "scenario_id": item["scenario_id"],
            "source_ip": capture.get("source_ip"), "target_ip": capture.get("target_ip"),
            "flow_count": len(features), "feature_count": features.shape[1],
            "missing_values": missing, "non_finite_values": nonfinite,
            "exact_duplicate_rows": int(features.duplicated().sum()),
            "unique_flow_rows": int(len(features.drop_duplicates())),
        })
        role = "adaptation_validation" if item["session_id"] == VALIDATION_SESSIONS[item["class"]] else "adaptation_training_pool"
        for index, feature_hash in enumerate(hashes):
            identity_payload = ["experiment_d_adaptation", item["raw_flow_sha256"], index]
            rows.append({
                "source_family": "experiment_d_adaptation", "source_file": item["raw_flow_logical_path"],
                "capture_id": item["source_capture_id"], "session_id": item["session_id"],
                "scenario_id": item["scenario_id"], "ground_truth_class": item["class"],
                "split_role": role, "original_row_index": index,
                "row_identity": canonical_json_sha256(identity_payload), "feature_hash64": feature_hash,
            })
    assert_session_separation(rows)
    return rows, session_audit, frames


def prepare_cicids(adaptation_feature_hashes: set[str]) -> tuple[dict, set[str]]:
    understanding = json.loads((ROOT / "reports/metrics/data_understanding.json").read_text())
    files = [ROOT / path for path in understanding["source_files"]]
    identities, frames, source_rows = [], [], []
    for path in files:
        if not path.is_file(): raise ValueError(f"missing CICIDS2017 source: {path}")
        frame = pd.read_csv(path, low_memory=False)
        frame.columns = normalize_columns(frame.columns)
        frame["__source_file"] = str(path.relative_to(ROOT))
        frame["__source_row"] = np.arange(len(frame), dtype=np.int64)
        frames.append(frame)
        identities.append({"logical_path": str(path.relative_to(ROOT)), "size_bytes": path.stat().st_size, "sha256": sha256_file(path)})
    data = pd.concat(frames, ignore_index=True); del frames
    labels = data["label"].map(map_label)
    data = data.loc[labels.notna()].copy(); data["label"] = labels.loc[labels.notna()]
    feature_cols = list(MODEL_FEATURES)
    if feature_cols != [x for x in data.columns if x not in {"label", "__source_file", "__source_row"}]:
        raise ValueError("CICIDS2017 ordered feature schema mismatch")
    duplicate = data.duplicated(subset=feature_cols + ["label"], keep="first")
    data = data.loc[~duplicate].reset_index(drop=True)
    labels = data["label"].astype(str)
    indices = np.arange(len(data), dtype=np.int64)
    train, control = train_test_split(indices, test_size=.2, random_state=SEED, stratify=labels)
    train = np.sort(train); control = np.sort(control)
    expected = json.loads((ROOT / "reports/metrics/baseline_metrics.json").read_text())["preprocessing"]
    counts = lambda ix: {c: int((labels.iloc[ix] == c).sum()) for c in CLASSES}
    if counts(train) != expected["train_distribution"] or counts(control) != expected["test_distribution"]:
        raise ValueError("reconstructed CICIDS2017 split differs from RF-v1 evidence")
    features = data[feature_cols].replace([np.inf, -np.inf], np.nan).astype(np.float32)
    hashes = feature_hashes(features)
    all_feature_hashes = set(hashes)
    overlap_mask = hashes.isin(adaptation_feature_hashes).to_numpy()
    excluded_overlap = np.flatnonzero(overlap_mask)
    # Fail-safe cross-source policy: no CIC row matching any adaptation feature vector
    # participates in either D3 component, regardless of its mapped label.
    train = train[~overlap_mask[train]]
    control = control[~overlap_mask[control]]
    source_membership = []
    for path in files:
        mask = data["__source_file"].eq(str(path.relative_to(ROOT))).to_numpy()
        positions = np.flatnonzero(mask)
        source_membership.append({
            "source_file": str(path.relative_to(ROOT)),
            "deduplicated_positions": encode_index_membership(positions, len(data)),
            "original_row_indices_in_position_order": encode_int64_sequence(data.loc[mask, "__source_row"].to_numpy(dtype=np.int64)),
        })
    manifest = {
        "source_identities": identities, "source_order_identity": canonical_json_sha256(identities),
        "filter_and_dedup_rows": len(data), "filter_and_dedup_identity": canonical_json_sha256({"method":"map_label then exact feature+label drop_duplicates keep first", "rows":len(data)}),
        "membership_basis": "zero-based position after label filtering and exact feature+label deduplication",
        "training_membership": encode_index_membership(train, len(data)),
        "internal_control_membership": encode_index_membership(control, len(data)),
        "excluded_adaptation_feature_overlap_membership": encode_index_membership(excluded_overlap, len(data)),
        "source_provenance_membership": source_membership,
        "training_class_counts": counts(train), "internal_control_class_counts": counts(control),
        "split_algorithm": "sklearn train_test_split(test_size=0.2, random_state=42, stratify=mapped labels)",
    }
    return manifest, all_feature_hashes


def select_strategies(rows: list[dict]) -> tuple[dict, list[dict]]:
    validation = [x for x in rows if x["split_role"] == "adaptation_validation"]
    validation_hashes = {x["feature_hash64"] for x in validation}
    pool = [x for x in rows if x["split_role"] == "adaptation_training_pool"]
    leakage = [x for x in pool if x["feature_hash64"] in validation_hashes]
    clean, seen = [], set()
    for row in sorted(pool, key=lambda x: (x["source_file"], x["original_row_index"])):
        key = (row["ground_truth_class"], row["feature_hash64"])
        if row["feature_hash64"] not in validation_hashes and key not in seen:
            clean.append(row); seen.add(key)
    by_class = {c: [x for x in clean if x["ground_truth_class"] == c] for c in CLASSES}
    all_selected = clean
    class_cap = min(len(by_class["DDoS"]), len(by_class["PortScan"]))
    capped = sum((deterministic_cap(by_class[c], len(by_class[c]) if c == "Normal" else class_cap, SEED) for c in CLASSES), [])
    per_session = []
    for session in sorted({x["session_id"] for x in clean}):
        session_rows = [x for x in clean if x["session_id"] == session]
        per_session.extend(deterministic_cap(session_rows, 600, SEED))
    balanced_cap = min(len(by_class[c]) for c in CLASSES)
    balanced = sum((deterministic_cap(by_class[c], balanced_cap, SEED) for c in CLASSES), [])
    strategies = {}
    for key, selected, label in (
        ("D3-A", all_selected, "all leakage-clean unique adaptation-training rows"),
        ("D3-B", capped, f"per-class cap={class_cap}; Normal retained as-is"),
        ("D3-C", per_session, "per-session cap=600; Normal retained as-is"),
        ("D3-D", balanced, f"class-balanced cap={balanced_cap}"),
    ):
        identities = sorted(x["row_identity"] for x in selected)
        strategies[key] = {"policy": label, "adaptation_class_counts": class_counts(selected), "row_count": len(selected), "row_identities": identities, "membership_sha256": canonical_json_sha256(identities)}
    audit = {"validation_rows": len(validation), "training_pool_rows": len(pool), "training_rows_excluded_for_validation_feature_overlap": len(leakage), "training_rows_excluded_as_within_class_duplicates_after_overlap": len(pool)-len(leakage)-len(clean), "validation_feature_hash_count": len(validation_hashes)}
    return strategies, validation, audit


def detailed_adaptation_audit(rows: list[dict], session_audit: list[dict], frames: dict[str, pd.DataFrame]) -> dict:
    important = ("flow_duration", "total_fwd_packets", "total_backward_packets", "flow_bytes_s", "flow_packets_s", "syn_flag_count", "ack_flag_count", "destination_port")
    distributions = []
    for session_id, frame in frames.items():
        class_name = next(x["ground_truth_class"] for x in rows if x["session_id"] == session_id)
        for feature in important:
            series = frame[feature].replace([np.inf, -np.inf], np.nan)
            distributions.append({
                "class": class_name, "session_id": session_id, "feature": feature,
                "finite_count": int(series.notna().sum()), "missing_count": int(series.isna().sum()),
                "min": None if series.notna().sum() == 0 else float(series.min()),
                "q25": None if series.notna().sum() == 0 else float(series.quantile(.25)),
                "median": None if series.notna().sum() == 0 else float(series.median()),
                "q75": None if series.notna().sum() == 0 else float(series.quantile(.75)),
                "max": None if series.notna().sum() == 0 else float(series.max()),
            })
    pairwise = []
    sessions = sorted(frames)
    hashes = {key: set(feature_hashes(value)) for key, value in frames.items()}
    for i, first in enumerate(sessions):
        for second in sessions[i + 1:]:
            count = len(hashes[first] & hashes[second])
            if count:
                pairwise.append({"session_a": first, "session_b": second, "shared_exact_feature_signatures": count})
    return {
        "schema":"experiment_d_d3_adaptation_audit","schema_version":1,"record_type":"observed",
        "model_predictions_used":False,"feature_selection_performed":False,
        "session_statistics":session_audit,"important_feature_distributions":distributions,
        "pairwise_cross_session_exact_feature_overlap":pairwise,
        "content_hash_overlap_count":0,"capture_overlap_count":0,"session_overlap_count":0,
        "five_tuple_audit":"Raw CICFlowMeter CSV metadata is retained in source files but is not propagated through the validated 78-feature adapter; capture/session isolation is authoritative. No five-tuple was used as a classifier feature.",
    }


def main() -> int:
    captures, entries, adapter = validate_d2()
    rows, session_audit, frames = adaptation_rows(captures, entries, adapter)
    detailed_audit = detailed_adaptation_audit(rows, session_audit, frames)
    adaptation_hashes = {x["feature_hash64"] for x in rows}
    cicids, cic_hashes = prepare_cicids(adaptation_hashes)
    strategies, validation, duplicate_handling = select_strategies(rows)
    overlap = sorted(adaptation_hashes & cic_hashes)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=True).stdout.strip()
    selected_train_sessions = sorted({x["session_id"] for x in rows if x["split_role"] == "adaptation_training_pool"})
    selected_validation_sessions = sorted(VALIDATION_SESSIONS.values())
    source_identities = [{"logical_path": str((ROOT / "data/lab/experiment_d" / x["raw_flow_logical_path"]).relative_to(ROOT)), "sha256": x["raw_flow_sha256"], "rows": x["row_count"], "session_id": x["session_id"], "capture_id": x["source_capture_id"], "scenario_id": x["scenario_id"], "class": x["class"]} for x in entries]
    manifest = {
        "schema": "experiment_d_d3_split_manifest", "schema_version": 1, "phase": "D3", "code_commit": commit,
        "created_by": "scripts/prepare_experiment_d_d3.py", "seeds": {"split":SEED,"sampling":SEED,"model":SEED},
        "feature_count":78, "feature_order":list(MODEL_FEATURES), "feature_order_sha256":hashlib.sha256("\n".join(MODEL_FEATURES).encode()).hexdigest(),
        "cicids2017": cicids,
        "adaptation": {"source_identities":source_identities,"selected_training_sessions":selected_train_sessions,"selected_validation_sessions":selected_validation_sessions,"excluded_invalid_sessions":["expd-adapt-ddos-session-03"],"validation_rows":validation,"candidate_strategies":strategies,"duplicate_handling":duplicate_handling},
        "provenance_schema":["source_family","source_file","capture_id","session_id","scenario_id","ground_truth_class","split_role","original_row_index","row_identity"],
        "leakage_checks": {"d2_audit":"PASS","d2_leakage_audit":"PASS","whole_session_split":"PASS","capture_overlap_count":0,"session_overlap_count":0,"cicids2017_adaptation_feature_hash64_overlap_count":len(overlap),"cicids2017_adaptation_overlap_hashes":overlap,"cross_source_handling":"all CICIDS2017 rows with an adaptation feature hash are excluded from both CICIDS training and internal control memberships","post_handling_cross_source_overlap_count":0,"experiment_c_used":False,"final_test_used":False},
        "content_identity": "computed_after_payload",
    }
    manifest["content_identity"] = canonical_json_sha256({k:v for k,v in manifest.items() if k != "content_identity"})
    rf_params = {"n_estimators":200,"criterion":"gini","max_depth":None,"min_samples_split":5,"min_samples_leaf":4,"max_features":"log2","class_weight":"balanced","bootstrap":False,"random_state":42,"n_jobs":-1,"ccp_alpha":0.0}
    preferred = strategies["D3-C"]
    combined = {c:cicids["training_class_counts"][c]+preferred["adaptation_class_counts"][c] for c in CLASSES}
    plan = {
        "schema":"experiment_d_rf_v2_training_plan","schema_version":1,"phase":"D3_PRE_TRAINING_ONLY","training_enabled":False,
        "recommended_first_strategy":"D3-C","recommendation_rationale":"A 600-row per-session cap preserves both training scenarios per class, retains scarce Normal rows without duplication, and limits DDoS domination.",
        "candidate_strategies": {k:{kk:vv for kk,vv in v.items() if kk != "row_identities"} for k,v in strategies.items()},
        "rf_parameters":rf_params,"hyperparameter_policy":"Start D4 with fixed RF-v1 parameters; no RandomizedSearchCV for the first comparison.",
        "preprocessing":{"pipeline":["SimpleImputer(strategy='median')","RandomForestClassifier(fixed RF-v1 parameters)"],"imputer_fit_scope":"combined D4 training partition only","infinity_handling":"replace +/- infinity with NaN before split consumption","scaling":None,"feature_selection":None,"provenance_columns_are_features":False},
        "training_inputs":{"cicids2017_role":"training_membership","adaptation_role":"D3-C row identities"},
        "validation_inputs":{"cicids2017":"internal_control_membership; report separately","adaptation":"whole held-out sessions; primary model selection evidence"},
        "planned_combined_training_class_counts":combined,
        "metrics":{"primary":["macro_f1","DDoS_recall","PortScan_recall","Normal_recall"],"also_record":["per_class_precision","per_class_f1","confusion_matrix","Normal_false_positive_rate"]},
        "model_selection_rules":{"gates":["DDoS recall > 0","PortScan recall > 0","Normal recall >= 0.50","adaptation macro F1 >= RF-v1 adaptation-validation macro F1"],"ranking":["higher adaptation-validation macro F1","higher minimum per-class recall","lower Normal false-positive rate","higher CICIDS2017 internal-control macro F1"],"rationale":"The Normal gate is deliberately conservative because its independent lab validation support is only 23; improvement is comparative to RF-v1 rather than tuned to future data."},
        "normal_limitation":{"observed_rows":44,"decision":"additional capture not required before D4","reason":"CICIDS2017 supplies broad Normal coverage; all leakage-clean lab Normal training rows are retained without duplication and an independent Normal session is held out. More diverse Normal capture remains advisable before broad deployment claims."},
        "outputs":list(RF_V2_OUTPUTS),"create_new_only":True,
        "prohibited_data":["Experiment C artifacts","Experiment D final_test data","future final-test metrics for selection"],
        "future_final_test_isolation_rule":"D4 must neither enumerate, read, summarize, preprocess, nor select against final_test; it remains sealed for later one-shot D5 evaluation.",
        "random_seeds":{"split":42,"sampling":42,"classifier":42},"randomized_search_cv_allowed":False,
    }
    distribution_rows = session_audit
    write_json_new(SPLIT_PATH, manifest); write_json_new(PLAN_PATH, plan)
    write_json_new(REPORT/"d3_adaptation_audit.json", detailed_audit)
    write_csv_new(REPORT/"session_distribution.csv", list(distribution_rows[0]), distribution_rows)
    training_table=[]
    for strategy,value in strategies.items():
        for c in CLASSES:
            training_table.append({"record_type":"planned","strategy":strategy,"component":"adaptation_training","class":c,"flow_count":value["adaptation_class_counts"][c]})
            training_table.append({"record_type":"planned","strategy":strategy,"component":"combined_with_cicids2017_training","class":c,"flow_count":value["adaptation_class_counts"][c]+cicids["training_class_counts"][c]})
    write_csv_new(REPORT/"proposed_training_distribution.csv", list(training_table[0]), training_table)
    validation_table=[]
    val_counts=class_counts(validation)
    for c in CLASSES:
        validation_table.extend([
            {"record_type":"planned","validation_component":"adaptation_validation","class":c,"flow_count":val_counts[c]},
            {"record_type":"planned","validation_component":"cicids2017_internal_control","class":c,"flow_count":cicids["internal_control_class_counts"][c]},
        ])
    write_csv_new(REPORT/"proposed_validation_distribution.csv", list(validation_table[0]), validation_table)
    print(json.dumps({"status":"D3_MANIFESTS_CREATED","training_performed":False,"preferred":"D3-C","adaptation_training_counts":preferred["adaptation_class_counts"],"adaptation_validation_counts":val_counts,"combined_training_counts":combined,"cicids_adaptation_overlap_hashes":len(overlap)}))
    return 0


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__); parser.parse_args(); raise SystemExit(main())
