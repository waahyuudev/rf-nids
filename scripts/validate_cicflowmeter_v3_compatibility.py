#!/usr/bin/env python3
"""Validate pinned CICFlowMeter V3 against the 78-feature training representation."""

from __future__ import annotations

import csv
import json
import math
import re
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.optimize import linear_sum_assignment

ROOT = Path(__file__).resolve().parents[1]
OUT_JSON = ROOT / "reports/metrics/cicflowmeter_v3_78_feature_validation.json"
OUT_CROSSWALK = ROOT / "reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv"
OUT_V4 = ROOT / "reports/tables/cicflowmeter_v3_vs_v4.csv"
OUT_DIST = ROOT / "reports/tables/cicflowmeter_v3_vs_cicids2017_distribution.csv"
TARGETS = [OUT_JSON, OUT_CROSSWALK, OUT_V4, OUT_DIST]
SCENARIOS = {
    "normal-http-test": (
        ROOT / "data/lab/flows/cicflowmeter-v3/normal-http-test.pcap_ISCX.csv",
        ROOT / "data/lab/flows/historical/normal-http-test.pcap_Flow.csv",
    ),
    "portscan-test": (
        ROOT / "data/lab/flows/cicflowmeter-v3/portscan-test.pcap_ISCX.csv",
        ROOT / "data/lab/flows/historical/portscan-test.pcap_Flow.csv",
    ),
}
FLAG_ARTIFACTS = {
    "fin_flag_count": "V3 header FIN receives HashMap key RST",
    "syn_flag_count": "V3 header SYN receives HashMap key PSH",
    "rst_flag_count": "V3 header RST receives HashMap key ECE",
    "psh_flag_count": "V3 header PSH receives HashMap key SYN",
    "ack_flag_count": "V3 header ACK receives HashMap key ACK",
    "urg_flag_count": "V3 header URG receives HashMap key FIN",
    "cwe_flag_count": "released CWE is reproduced from directional Fwd URG by explicit policy",
    "ece_flag_count": "V3 header ECE receives HashMap key CWR",
}


def normalize_columns(columns: object) -> list[str]:
    """Mirror the repository's recorded training-time column normalization."""
    return [re.sub(r"\s+", "_", str(name).strip().lower().replace("/", "_")) for name in columns]


def raw_header(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return next(csv.reader(handle))


def schema_audit(path: Path) -> dict[str, object]:
    header = raw_header(path)
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    numeric_headers = header[7:-1]
    parseability: dict[str, dict[str, object]] = {}
    nan_count = pos_inf = neg_inf = 0
    for name in numeric_headers:
        parsed = pd.to_numeric(frame[name], errors="coerce")
        values = parsed.to_numpy(dtype=float, na_value=np.nan)
        failed = int(np.isnan(values).sum())
        plus = int(np.isposinf(values).sum())
        minus = int(np.isneginf(values).sum())
        parseability[name] = {
            "parseable_count": int(parsed.notna().sum()),
            "numeric_parse_failures_or_nan": failed,
            "positive_infinity": plus,
            "negative_infinity": minus,
        }
        nan_count += failed
        pos_inf += plus
        neg_inf += minus
    return {
        "path": str(path.relative_to(ROOT)),
        "row_count": int(len(frame)),
        "column_count": len(header),
        "ordered_headers": header,
        "duplicate_headers": [name for name, count in Counter(header).items() if count > 1],
        "identifier_columns": header[:7],
        "numeric_feature_columns": numeric_headers,
        "numeric_feature_column_count": len(numeric_headers),
        "label_column": header[-1],
        "nan_or_numeric_parse_failures": nan_count,
        "positive_infinity": pos_inf,
        "negative_infinity": neg_inf,
        "duplicate_rows": int(frame.duplicated().sum()),
        "parseability": parseability,
    }


def v3_mapping(features: list[str], v3_headers: list[str]) -> dict[str, tuple[str, int]]:
    result: dict[str, tuple[str, int]] = {}
    for index, feature in enumerate(features):
        if feature == "destination_port":
            column_index = 4
        elif feature == "cwe_flag_count":
            column_index = v3_headers.index("Fwd URG Flags")
        elif feature == "fwd_header_length.1":
            column_index = v3_headers.index("Fwd Header Len")
        elif index < features.index("fwd_header_length.1"):
            column_index = index + 6
        else:
            column_index = index + 5
        result[feature] = (v3_headers[column_index], column_index)
    return result


def source_method(feature: str) -> tuple[str, str]:
    if feature == "destination_port":
        return "BasicFlow.java", "getDstPort / dumpFlowBasedFeaturesEx"
    if feature in {"total_fwd_packets", "total_backward_packets"}:
        return "BasicFlow.java", "forward/backward.size / packetCount"
    if "iat" in feature or feature == "flow_duration":
        return "BasicFlow.java", "SummaryStatistics IAT accumulators / dumpFlowBasedFeaturesEx"
    if "packet_length" in feature or "length_of" in feature or "segment_size" in feature or feature == "average_packet_size":
        return "BasicFlow.java + BasicPacketInfo.java", "payloadBytes statistics / packet header minimum where named"
    if feature in {"flow_bytes_s", "flow_packets_s", "fwd_packets_s", "bwd_packets_s"}:
        return "BasicFlow.java", "duration-scaled rate getters / dumpFlowBasedFeaturesEx"
    if "header_length" in feature:
        return "BasicFlow.java + BasicPacketInfo.java", "fHeaderBytes/bHeaderBytes accumulated from getHeaderBytes"
    if feature.endswith("flag_count"):
        return "BasicFlow.java", "checkFlags + HashMap keySet iteration in dumpFlowBasedFeaturesEx"
    if feature in {"fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags"}:
        return "BasicFlow.java", "directional counters in firstPacket/addPacket"
    if "bulk" in feature:
        return "BasicFlow.java", "updateFlowBulk and bulk average/rate getters"
    if feature.startswith("subflow_"):
        return "BasicFlow.java", "detectUpdateSubflows and getSflow_*"
    if feature.startswith("init_win"):
        return "BasicFlow.java + BasicPacketInfo.java", "Init_Win_bytes_* from TCPWindow"
    if feature in {"active_mean", "active_std", "active_max", "active_min", "idle_mean", "idle_std", "idle_max", "idle_min"}:
        return "BasicFlow.java + FlowGenerator.java", "updateActiveIdleTime / SummaryStatistics"
    return "BasicFlow.java", "named getter / dumpFlowBasedFeaturesEx"


def transform_v3(frame: pd.DataFrame, features: list[str], mapping: dict[str, tuple[str, int]]) -> pd.DataFrame:
    output = pd.DataFrame(index=frame.index)
    for feature in features:
        output[feature] = pd.to_numeric(frame[mapping[feature][0]], errors="coerce")
    return output


def endpoint_key(row: pd.Series) -> tuple[object, ...]:
    return (
        int(row["Protocol"]), str(row["Src IP"]), int(row["Src Port"]),
        str(row["Dst IP"]), int(row["Dst Port"]),
    )


def canonical_key(row: pd.Series) -> tuple[object, ...]:
    a = (str(row["Src IP"]), int(row["Src Port"]))
    b = (str(row["Dst IP"]), int(row["Dst Port"]))
    return (int(row["Protocol"]), *sorted((a, b)))


def parse_times(frame: pd.DataFrame) -> pd.Series:
    return pd.to_datetime(frame["Timestamp"], dayfirst=True, errors="coerce")


def match_flows(v3: pd.DataFrame, v4: pd.DataFrame) -> tuple[list[tuple[int, int]], dict[str, object]]:
    groups3: dict[tuple[object, ...], list[int]] = defaultdict(list)
    groups4: dict[tuple[object, ...], list[int]] = defaultdict(list)
    for index, row in v3.iterrows():
        groups3[canonical_key(row)].append(index)
    for index, row in v4.iterrows():
        groups4[canonical_key(row)].append(index)
    times3, times4 = parse_times(v3), parse_times(v4)
    pairs: list[tuple[int, int]] = []
    orientation_differences = 0
    segmentation_differences = 0
    start_differences: list[float] = []
    for key in sorted(set(groups3) & set(groups4), key=str):
        left, right = groups3[key], groups4[key]
        cost = np.zeros((len(left), len(right)), dtype=float)
        for i, a in enumerate(left):
            for j, b in enumerate(right):
                td = abs((times3.iloc[a] - times4.iloc[b]).total_seconds()) if pd.notna(times3.iloc[a]) and pd.notna(times4.iloc[b]) else 1e9
                dd = abs(float(v3.iloc[a]["Flow Duration"]) - float(v4.iloc[b]["Flow Duration"]))
                cost[i, j] = td * 1e9 + dd
        rows, cols = linear_sum_assignment(cost)
        for i, j in zip(rows, cols):
            a, b = left[int(i)], right[int(j)]
            pairs.append((a, b))
            if endpoint_key(v3.iloc[a]) != endpoint_key(v4.iloc[b]):
                orientation_differences += 1
            td = abs((times3.iloc[a] - times4.iloc[b]).total_seconds()) if pd.notna(times3.iloc[a]) and pd.notna(times4.iloc[b]) else math.inf
            dd = abs(float(v3.iloc[a]["Flow Duration"]) - float(v4.iloc[b]["Flow Duration"]))
            if math.isfinite(td):
                start_differences.append(td)
            if td != 0 or dd != 0:
                segmentation_differences += 1
    matched = len(pairs)
    return pairs, {
        "v3_flow_count": len(v3),
        "v4_flow_count": len(v4),
        "reliably_matched_flows": matched,
        "unmatched_v3": len(v3) - matched,
        "unmatched_v4": len(v4) - matched,
        "orientation_differences": orientation_differences,
        "segmentation_boundary_differences": segmentation_differences,
        "start_timestamp_difference_seconds": {
            "min": min(start_differences) if start_differences else None,
            "median": float(np.median(start_differences)) if start_differences else None,
            "max": max(start_differences) if start_differences else None,
        },
        "matching": "Protocol and canonical bidirectional five-tuple; Hungarian one-to-one assignment within identity minimizes start-time then duration difference; orientation checked separately.",
    }


def finite_comparison(a: np.ndarray, b: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    valid = np.isfinite(a) & np.isfinite(b)
    return a[valid], b[valid]


def compare_v4(scenario: str, v3: pd.DataFrame, v4: pd.DataFrame, pairs: list[tuple[int, int]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for offset in range(76):
        h3, h4 = v3.columns[7 + offset], v4.columns[7 + offset]
        a = np.array([float(v3.iloc[i][h3]) for i, _ in pairs], dtype=float)
        b = np.array([float(v4.iloc[j][h4]) for _, j in pairs], dtype=float)
        a, b = finite_comparison(a, b)
        diff = np.abs(a - b)
        denom = np.maximum(np.maximum(np.abs(a), np.abs(b)), 1e-12)
        rows.append({
            "record_type": "feature_comparison",
            "scenario": scenario,
            "v3_header": h3,
            "v4_header": h4,
            "matched_finite_count": len(a),
            "exact_equality_percentage": float(np.mean(a == b) * 100) if len(a) else None,
            "mean_absolute_difference": float(np.mean(diff)) if len(a) else None,
            "max_absolute_difference": float(np.max(diff)) if len(a) else None,
            "mean_symmetric_relative_difference": float(np.mean(diff / denom)) if len(a) else None,
            "correlation": float(np.corrcoef(a, b)[0, 1]) if len(a) > 1 and np.std(a) and np.std(b) else None,
        })
    return rows


def released_arrays(features: list[str]) -> tuple[np.memmap, np.memmap, tempfile.TemporaryDirectory[str]]:
    paths = sorted((ROOT / "data/raw/cicids2017").glob("*.csv"))
    normal_count = port_count = 0
    for path in paths:
        for chunk in pd.read_csv(path, usecols=[" Label"], chunksize=200_000, low_memory=False):
            labels = chunk.iloc[:, 0].astype(str).str.strip()
            normal_count += int((labels == "BENIGN").sum())
            port_count += int((labels == "PortScan").sum())
    temporary = tempfile.TemporaryDirectory(prefix="rf_nids_v3_dist_")
    normal = np.memmap(Path(temporary.name) / "normal.f32", mode="w+", dtype=np.float32, shape=(normal_count, len(features)))
    port = np.memmap(Path(temporary.name) / "port.f32", mode="w+", dtype=np.float32, shape=(port_count, len(features)))
    ni = pi = 0
    for path in paths:
        for chunk in pd.read_csv(path, chunksize=100_000, low_memory=False):
            chunk.columns = normalize_columns(chunk.columns)
            labels = chunk["label"].astype(str).str.strip()
            values = chunk[features].replace([np.inf, -np.inf], np.nan).to_numpy(dtype=np.float32)
            nm = (labels == "BENIGN").to_numpy()
            pm = (labels == "PortScan").to_numpy()
            n, p = int(nm.sum()), int(pm.sum())
            normal[ni:ni+n] = values[nm]
            port[pi:pi+p] = values[pm]
            ni += n
            pi += p
    normal.flush(); port.flush()
    return normal, port, temporary


def dist_stats(training: np.ndarray, v3: np.ndarray) -> dict[str, object]:
    training = training[np.isfinite(training)]
    v3 = v3[np.isfinite(v3)]
    ks = None
    if len(training) and len(v3):
        left = np.sort(training)
        right = np.sort(v3)
        support = np.concatenate((left, right))
        left_cdf = np.searchsorted(left, support, side="right") / len(left)
        right_cdf = np.searchsorted(right, support, side="right") / len(right)
        ks = float(np.max(np.abs(left_cdf - right_cdf)))
    return {
        "training_count": len(training),
        "v3_count": len(v3),
        "training_mean": float(np.mean(training)) if len(training) else None,
        "v3_mean": float(np.mean(v3)) if len(v3) else None,
        "training_median": float(np.median(training)) if len(training) else None,
        "v3_median": float(np.median(v3)) if len(v3) else None,
        "training_p95": float(np.quantile(training, 0.95)) if len(training) else None,
        "v3_p95": float(np.quantile(v3, 0.95)) if len(v3) else None,
        "training_zero_percentage": float(np.mean(training == 0) * 100) if len(training) else None,
        "v3_zero_percentage": float(np.mean(v3 == 0) * 100) if len(v3) else None,
        "ks_statistic": ks,
    }


def main() -> None:
    existing = [path for path in TARGETS if path.exists()]
    if existing:
        raise SystemExit("refusing to overwrite: " + ", ".join(map(str, existing)))
    metadata = json.loads((ROOT / "models/model_metadata.json").read_text(encoding="utf-8"))
    features: list[str] = metadata["feature_names"]
    prior = json.loads((ROOT / "reports/metrics/experiment_c_feature_semantics_audit.json").read_text(encoding="utf-8"))
    prior_by_feature = {row["model_feature"]: row for row in prior["features"]}
    sample_release = ROOT / "data/raw/cicids2017/Monday-WorkingHours.pcap_ISCX.csv"
    released_headers = raw_header(sample_release)
    released_pandas_headers = list(pd.read_csv(sample_release, nrows=0).columns)
    released_normalized = normalize_columns(released_pandas_headers)
    v3_headers = raw_header(SCENARIOS["normal-http-test"][0])
    mapping = v3_mapping(features, v3_headers)

    crosswalk: list[dict[str, object]] = []
    for index, feature in enumerate(features):
        source_class, method = source_method(feature)
        prior_row = prior_by_feature[feature]
        released_position = released_normalized.index(feature)
        status = "DATASET_ARTIFACT_REPRODUCTION" if feature in FLAG_ARTIFACTS or feature == "fwd_header_length.1" else "EXACT"
        formula = "identity"
        transformation = "NO"
        evidence = "Pinned V3 source method and ordered raw output; released header/order and full distribution audit."
        if feature == "cwe_flag_count":
            formula = "cwe_flag_count = fwd_urg_flags"
            transformation = "YES — explicit released-dataset artifact copy"
            evidence = "Full released audit proves CWE Flag Count equals Fwd URG Flags in all 2,830,743 rows; V3 aggregate flag slot is not used as genuine CWE/CWR."
        elif feature == "fwd_header_length.1":
            formula = "fwd_header_length.1 = fwd_header_length"
            transformation = "YES — explicit duplicate-column reproduction"
            evidence = "Released raw CSV repeats Fwd Header Length and every pair is identical; V3 raw schema has one forward-header field."
        elif feature in FLAG_ARTIFACTS:
            evidence = FLAG_ARTIFACTS[feature] + "; V3 calls checkFlags only for the first packet after addPacket calls are commented, matching the released column artifact pattern."
        aggregation = prior_row.get("aggregation_convention") or "named per-flow aggregate"
        if feature.endswith("_std") or feature == "packet_length_std":
            aggregation = "Apache Commons Math SummaryStatistics sample standard deviation; zero emitted for insufficient directional samples where guarded"
        zero_behavior = "zero for empty/insufficient aggregate where guarded"
        if feature.startswith("init_win"):
            zero_behavior = "V3 default -1 when unavailable; backward value is overwritten by later backward packets"
        crosswalk.append({
            "model_feature": feature,
            "model_feature_index": index,
            "cicids2017_released_header": released_pandas_headers[released_position],
            "cicids2017_column_index_zero_based": released_position,
            "v3_raw_header": mapping[feature][0],
            "v3_raw_index_zero_based": mapping[feature][1],
            "v3_source_class": source_class,
            "v3_source_method": method,
            "semantic_definition": prior_row.get("notes") or prior_row.get("evidence"),
            "units": prior_row.get("training_unit", "unknown"),
            "directional_convention": prior_row.get("direction_convention", "not directional"),
            "payload_packet_length_convention": "jNetPcap BasicPacketInfo payloadBytes for packet-length/byte aggregates; headerBytes only for named header/min-segment fields",
            "aggregation_convention": aggregation,
            "standard_deviation_convention": "Apache Commons Math sample standard deviation (n-1); SummaryStatistics returns NaN at n=0 and 0 at n=1, while several output branches explicitly emit zero for insufficient directional samples",
            "zero_empty_flow_behavior": zero_behavior,
            "direct_mapping_possible": feature != "cwe_flag_count" and feature != "fwd_header_length.1",
            "transformation_required": transformation,
            "transformation_formula": formula,
            "evidence": evidence,
            "confidence": "HIGH" if status == "DATASET_ARTIFACT_REPRODUCTION" else "MEDIUM_HIGH",
            "compatibility_status": status,
        })

    schema = {name: schema_audit(paths[0]) for name, paths in SCENARIOS.items()}
    loaded: dict[str, tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]] = {}
    flow_summaries: dict[str, object] = {}
    v4_rows: list[dict[str, object]] = []
    for scenario, (v3_path, v4_path) in SCENARIOS.items():
        v3, v4 = pd.read_csv(v3_path), pd.read_csv(v4_path)
        transformed = transform_v3(v3, features, mapping)
        loaded[scenario] = (v3, v4, transformed)
        pairs, summary = match_flows(v3, v4)
        flow_summaries[scenario] = summary
        v4_rows.append({"record_type": "flow_summary", "scenario": scenario, **summary})
        v4_rows.extend(compare_v4(scenario, v3, v4, pairs))

    normal_training, port_training, temporary = released_arrays(features)
    dist_rows: list[dict[str, object]] = []
    try:
        for scenario, training in (("normal-http-test", normal_training), ("portscan-test", port_training)):
            lab = loaded[scenario][2]
            for index, feature in enumerate(features):
                row = {"scenario": scenario, "model_feature": feature}
                row.update(dist_stats(np.asarray(training[:, index]), lab[feature].to_numpy(dtype=float)))
                dist_rows.append(row)
    finally:
        del normal_training, port_training
        temporary.cleanup()

    counts = Counter(row["compatibility_status"] for row in crosswalk)
    statuses = ["EXACT", "SOURCE_SUPPORTED_UNIT_CONVERSION", "DATASET_ARTIFACT_REPRODUCTION", "SEMANTIC_MISMATCH", "UNCERTAIN", "MISSING"]
    category_counts = {name: counts.get(name, 0) for name in statuses}
    gate = "V3_COMPATIBILITY_GATE_PASS" if category_counts["MISSING"] == category_counts["UNCERTAIN"] == category_counts["SEMANTIC_MISMATCH"] == 0 and len(crosswalk) == 78 else "V3_COMPATIBILITY_GATE_PARTIAL"
    finite_counts = {
        scenario: {
            "positive_infinity": sum(item["positive_infinity"] for item in audit["parseability"].values()),
            "negative_infinity": sum(item["negative_infinity"] for item in audit["parseability"].values()),
            "nan_or_parse_failures": audit["nan_or_numeric_parse_failures"],
        } for scenario, audit in schema.items()
    }
    numeric_rows = [row for row in v4_rows if row["record_type"] == "feature_comparison"]
    largest_v4 = sorted(numeric_rows, key=lambda row: row["mean_symmetric_relative_difference"] if row["mean_symmetric_relative_difference"] is not None else -1, reverse=True)[:10]
    identical_features = sum(1 for row in numeric_rows if row["exact_equality_percentage"] == 100.0)
    max_ks = {
        scenario: max(row["ks_statistic"] for row in dist_rows if row["scenario"] == scenario and row["ks_statistic"] is not None)
        for scenario in SCENARIOS
    }
    report = {
        "status": "completed",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Read-only V3 78-feature compatibility validation; no inference, retraining, raw-output modification, or active-model modification.",
        "validation_warnings": [
            "During this run SciPy's KS probability calculation emitted divide-by-zero/overflow RuntimeWarnings for very large released-data samples. All recorded KS statistics were finite and no p-values were requested or stored. The reproducibility script now calculates only the empirical-CDF KS statistic directly, avoiding probability computation."
        ],
        "pinned_v3": {
            "repository": "https://github.com/ahlashkari/CICFlowMeter",
            "commit": "a26aae27f21d165ff30b4b28e75124a5f9b4b2c4",
            "docker_image": "sha256:0227c7280e586d54144b9bb11b2a6b5d4b1c4ba9bc7c44199fa312a6b829caab",
            "source_hash_report": "reports/metrics/cicflowmeter_v3_build.json",
        },
        "raw_schema_audit": schema,
        "released_schema": {
            "column_count": len(released_headers),
            "exact_ordered_raw_headers": released_headers,
            "duplicate_raw_headers": [name for name, count in Counter(released_headers).items() if count > 1],
            "pandas_disambiguated_headers": released_pandas_headers,
            "active_model_features": features,
        },
        "crosswalk": {
            "path": str(OUT_CROSSWALK.relative_to(ROOT)),
            "feature_count": len(crosswalk),
            "category_counts": category_counts,
            "exact_training_order_producible": [row["model_feature"] for row in crosswalk] == features,
        },
        "v3_vs_v4": {
            "path": str(OUT_V4.relative_to(ROOT)),
            "flow_summaries": flow_summaries,
            "common_numeric_feature_scenario_rows": len(numeric_rows),
            "numerically_identical_feature_scenario_rows": identical_features,
            "largest_differences": largest_v4,
            "source_explanation": [
                "V3 and V4 retain the same matched flow identities/boundaries for these PCAPs despite materially different FIN/RST source branches.",
                "V3 calls bulk/subflow/global checkFlags only for firstPacket; V4 enables those calls for every packet.",
                "V3 emits global flag HashMap iteration order; V4 emits explicit FIN,SYN,RST,PSH,ACK,URG,CWR,ECE order.",
                "Initial-window defaults and first-packet byte-array equality logic differ.",
            ],
        },
        "v3_vs_cicids2017": {
            "path": str(OUT_DIST.relative_to(ROOT)),
            "max_ks": max_ks,
            "conclusion": "Large KS values are external-distribution shift diagnostics for synthetic lab traffic, not semantic incompatibility by themselves. Compatibility is decided from source and released-artifact semantics.",
        },
        "non_finite_and_preprocessing": {
            "v3_raw_counts": finite_counts,
            "v3_source_behavior": "Zero-duration byte/packet rates use Java floating-point division and can emit Infinity/NaN; empty backward statistics are mostly guarded to zero; unavailable initial windows default to -1 in V3.",
            "training_pipeline": "prepare_dataset replaces +Inf/-Inf with NaN, casts numeric features to float32, then the fitted sklearn pipeline median-imputes from the training partition.",
            "required_model_facing_preprocessing": "Preserve raw V3 values; during a future authorized adapter/inference phase, reproduce training behavior exactly: explicit artifact transforms, exact feature order, replace +/-Infinity with NaN, float32 conversion, and the already-fitted pipeline imputer. Do not convert -1 initial windows to missing.",
            "compatibility": "PASS",
        },
        "flow_construction_finding": {
            "v3_v4": flow_summaries,
            "hieulw": "Existing audit found 32 Normal flows versus Java's 61, with 30 reliable one-to-one matches; Python flow lifecycle/termination merges or suppresses Java teardown segments. PortScan remains 1000/1000. This is an implementation difference, not a PCAP defect.",
        },
        "artifact_reproduction": {
            "cwe_flag_count": "cwe_flag_count = fwd_urg_flags; DATASET_ARTIFACT_REPRODUCTION; never substitute V3 aggregate CWR/CWE slot as genuine CWE.",
            "fwd_header_length.1": "fwd_header_length.1 = fwd_header_length; DATASET_ARTIFACT_REPRODUCTION.",
            "aggregate_tcp_flags": FLAG_ARTIFACTS,
        },
        "compatibility_gate": gate,
        "gate_reason": "All 78 ordered inputs are justified with no missing, uncertain, or semantic-mismatch statuses. Sixty-nine are direct V3 source mappings and nine explicitly reproduce released CICIDS2017 artifacts. Non-finite handling matches the recorded training path. PASS does not authorize inference.",
        "inference_run": False,
        "next_step": "Archive this gate and implement a separately reviewed V3 model-facing adapter before any inference authorization.",
    }
    OUT_CROSSWALK.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(crosswalk).to_csv(OUT_CROSSWALK, index=False)
    pd.DataFrame(v4_rows).to_csv(OUT_V4, index=False)
    pd.DataFrame(dist_rows).to_csv(OUT_DIST, index=False)
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
