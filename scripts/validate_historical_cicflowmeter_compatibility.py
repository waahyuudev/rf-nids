#!/usr/bin/env python3
"""Generate read-only Experiment C Java compatibility evidence; never run inference."""

from __future__ import annotations

import csv
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import ks_2samp


ROOT = Path(__file__).resolve().parents[1]
OUT_JSON = ROOT / "reports/metrics/historical_cicflowmeter_compatibility_validation.json"
OUT_CROSSWALK = ROOT / "reports/tables/historical_cicflowmeter_78_feature_crosswalk.csv"
OUT_FLOW = ROOT / "reports/tables/historical_vs_hieulw_flow_comparison.csv"
OUT_DIST = ROOT / "reports/tables/historical_vs_cicids2017_distribution.csv"
TARGETS = [OUT_JSON, OUT_CROSSWALK, OUT_FLOW, OUT_DIST]

SCENARIOS = {
    "normal-http-test": (
        ROOT / "data/lab/flows/historical/normal-http-test.pcap_Flow.csv",
        ROOT / "data/lab/flows/normal-http-test.csv",
    ),
    "portscan-test": (
        ROOT / "data/lab/flows/historical/portscan-test.pcap_Flow.csv",
        ROOT / "data/lab/flows/portscan-test.csv",
    ),
}


def finite_float(value: object) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def raw_header(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return next(csv.reader(handle))


def schema_audit(path: Path) -> dict[str, object]:
    header = raw_header(path)
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    duplicates = [name for name, count in Counter(header).items() if count > 1]
    numeric_headers = header[7:-1]
    parseability = {}
    nan_count = 0
    infinity_count = 0
    for name in numeric_headers:
        parsed = pd.to_numeric(frame[name], errors="coerce")
        failed = int(parsed.isna().sum())
        inf = int(np.isinf(parsed.to_numpy(dtype=float, na_value=np.nan)).sum())
        parseability[name] = {
            "dtype": str(parsed.dtype),
            "parseable_count": int(parsed.notna().sum()),
            "unparseable_count": failed,
        }
        nan_count += failed
        infinity_count += inf
    return {
        "path": str(path.relative_to(ROOT)),
        "row_count": len(frame),
        "column_count": len(header),
        "ordered_column_names": header,
        "duplicate_column_names": duplicates,
        "identifier_columns": header[:7],
        "label_column": header[-1],
        "numeric_feature_columns": numeric_headers,
        "numeric_feature_column_count": len(numeric_headers),
        "nan_or_unparseable_numeric_values": nan_count,
        "infinity_values": infinity_count,
        "duplicate_rows": int(frame.duplicated().sum()),
        "parseability": parseability,
    }


def endpoint(ip: object, port: object) -> tuple[str, int]:
    return str(ip), int(port)


def canonical_key(row: pd.Series, historical: bool) -> tuple[object, ...]:
    if historical:
        a = endpoint(row["Src IP"], row["Src Port"])
        b = endpoint(row["Dst IP"], row["Dst Port"])
        proto = int(row["Protocol"])
    else:
        a = endpoint(row["src_ip"], row["src_port"])
        b = endpoint(row["dst_ip"], row["dst_port"])
        proto = int(row["protocol"])
    return (proto, *sorted((a, b)))


def directional_key(row: pd.Series, historical: bool) -> tuple[object, ...]:
    if historical:
        return (
            int(row["Protocol"]), str(row["Src IP"]), int(row["Src Port"]),
            str(row["Dst IP"]), int(row["Dst Port"]),
        )
    return (
        int(row["protocol"]), str(row["src_ip"]), int(row["src_port"]),
        str(row["dst_ip"]), int(row["dst_port"]),
    )


def timestamps(frame: pd.DataFrame, historical: bool) -> pd.Series:
    column = "Timestamp" if historical else "timestamp"
    return pd.to_datetime(frame[column], dayfirst=historical, errors="coerce")


def flow_groups(frame: pd.DataFrame, historical: bool) -> dict[tuple[object, ...], list[int]]:
    result: dict[tuple[object, ...], list[int]] = defaultdict(list)
    for index, row in frame.iterrows():
        result[canonical_key(row, historical)].append(index)
    return result


def flow_comparison(
    scenario: str, hist: pd.DataFrame, hieu: pd.DataFrame, metric_map: dict[str, str]
) -> tuple[dict[str, object], list[dict[str, object]]]:
    hg, pg = flow_groups(hist, True), flow_groups(hieu, False)
    shared = set(hg) & set(pg)
    matched = sum(min(len(hg[key]), len(pg[key])) for key in shared)
    unmatched_h = len(hist) - matched
    unmatched_p = len(hieu) - matched
    split_groups = [key for key in shared if len(hg[key]) > len(pg[key])]
    merged_groups = [key for key in shared if len(hg[key]) < len(pg[key])]

    hist_ts, py_ts = timestamps(hist, True), timestamps(hieu, False)
    orientation_differences = 0
    ts_diffs: list[float] = []
    reliable_pairs: list[tuple[int, int]] = []
    for key in shared:
        hi, pi = hg[key], pg[key]
        if len(hi) == len(pi) == 1:
            reliable_pairs.append((hi[0], pi[0]))
        remaining = set(hi)
        for pidx in pi:
            if not remaining:
                break
            hidx = min(
                remaining,
                key=lambda value: abs((hist_ts.iloc[value] - py_ts.iloc[pidx]).total_seconds()),
            )
            remaining.remove(hidx)
            if directional_key(hist.iloc[hidx], True) != directional_key(hieu.iloc[pidx], False):
                orientation_differences += 1
            if pd.notna(hist_ts.iloc[hidx]) and pd.notna(py_ts.iloc[pidx]):
                ts_diffs.append(abs((hist_ts.iloc[hidx] - py_ts.iloc[pidx]).total_seconds()))

    summary = {
        "scenario": scenario,
        "historical_flow_count": len(hist),
        "hieulw_flow_count": len(hieu),
        "matched_flows_by_bidirectional_identity": matched,
        "reliably_one_to_one_matched_flows": len(reliable_pairs),
        "unmatched_historical_flows": unmatched_h,
        "unmatched_hieulw_flows": unmatched_p,
        "split_identity_groups_historical_gt_hieulw": len(split_groups),
        "extra_historical_segments_in_split_groups": sum(
            len(hg[key]) - len(pg[key]) for key in split_groups
        ),
        "merged_identity_groups_hieulw_gt_historical": len(merged_groups),
        "extra_hieulw_segments_in_merged_groups": sum(
            len(pg[key]) - len(hg[key]) for key in merged_groups
        ),
        "orientation_differences": orientation_differences,
        "timestamp_difference_seconds": {
            "count": len(ts_diffs),
            "min": min(ts_diffs) if ts_diffs else None,
            "median": float(np.median(ts_diffs)) if ts_diffs else None,
            "max": max(ts_diffs) if ts_diffs else None,
        },
        "matching_definition": "Protocol plus canonicalized endpoint(IP,port) pair; nearest timestamps only pair rows within an already-matching bidirectional identity.",
    }
    rows: list[dict[str, object]] = [{"record_type": "flow_summary", **summary}]
    for model_feature, hist_header in metric_map.items():
        py_header = HIEULW_HEADERS.get(model_feature)
        if not py_header or hist_header not in hist or py_header not in hieu or not reliable_pairs:
            continue
        a = np.array([float(hist.iloc[i][hist_header]) for i, _ in reliable_pairs], dtype=float)
        b = np.array([float(hieu.iloc[j][py_header]) for _, j in reliable_pairs], dtype=float)
        valid = np.isfinite(a) & np.isfinite(b)
        a, b = a[valid], b[valid]
        if not len(a):
            continue
        diff = np.abs(a - b)
        denominator = np.maximum(np.maximum(np.abs(a), np.abs(b)), 1e-12)
        rows.append({
            "record_type": "feature_comparison",
            "scenario": scenario,
            "model_feature": model_feature,
            "historical_header": hist_header,
            "hieulw_header": py_header,
            "count": len(a),
            "exact_match_percentage": float(np.mean(a == b) * 100),
            "mean_absolute_difference": float(np.mean(diff)),
            "median_absolute_difference": float(np.median(diff)),
            "mean_symmetric_relative_difference": float(np.mean(diff / denominator)),
            "correlation": float(np.corrcoef(a, b)[0, 1]) if len(a) > 1 and np.std(a) and np.std(b) else None,
        })
    return summary, rows


HIEULW_HEADERS = {
    "destination_port": "dst_port", "flow_duration": "flow_duration",
    "total_fwd_packets": "tot_fwd_pkts", "total_backward_packets": "tot_bwd_pkts",
    "total_length_of_fwd_packets": "totlen_fwd_pkts", "total_length_of_bwd_packets": "totlen_bwd_pkts",
    "fwd_packet_length_max": "fwd_pkt_len_max", "fwd_packet_length_min": "fwd_pkt_len_min",
    "fwd_packet_length_mean": "fwd_pkt_len_mean", "fwd_packet_length_std": "fwd_pkt_len_std",
    "bwd_packet_length_max": "bwd_pkt_len_max", "bwd_packet_length_min": "bwd_pkt_len_min",
    "bwd_packet_length_mean": "bwd_pkt_len_mean", "bwd_packet_length_std": "bwd_pkt_len_std",
    "flow_bytes_s": "flow_byts_s", "flow_packets_s": "flow_pkts_s",
    "flow_iat_mean": "flow_iat_mean", "flow_iat_std": "flow_iat_std",
    "flow_iat_max": "flow_iat_max", "flow_iat_min": "flow_iat_min",
    "fwd_iat_total": "fwd_iat_tot", "fwd_iat_mean": "fwd_iat_mean",
    "fwd_iat_std": "fwd_iat_std", "fwd_iat_max": "fwd_iat_max", "fwd_iat_min": "fwd_iat_min",
    "bwd_iat_total": "bwd_iat_tot", "bwd_iat_mean": "bwd_iat_mean",
    "bwd_iat_std": "bwd_iat_std", "bwd_iat_max": "bwd_iat_max", "bwd_iat_min": "bwd_iat_min",
    "fwd_psh_flags": "fwd_psh_flags", "bwd_psh_flags": "bwd_psh_flags",
    "fwd_urg_flags": "fwd_urg_flags", "bwd_urg_flags": "bwd_urg_flags",
    "fwd_header_length": "fwd_header_len", "bwd_header_length": "bwd_header_len",
    "fwd_packets_s": "fwd_pkts_s", "bwd_packets_s": "bwd_pkts_s",
    "min_packet_length": "pkt_len_min", "max_packet_length": "pkt_len_max",
    "packet_length_mean": "pkt_len_mean", "packet_length_std": "pkt_len_std",
    "packet_length_variance": "pkt_len_var", "fin_flag_count": "fin_flag_cnt",
    "syn_flag_count": "syn_flag_cnt", "rst_flag_count": "rst_flag_cnt",
    "psh_flag_count": "psh_flag_cnt", "ack_flag_count": "ack_flag_cnt",
    "urg_flag_count": "urg_flag_cnt", "ece_flag_count": "ece_flag_cnt",
    "down_up_ratio": "down_up_ratio", "average_packet_size": "pkt_size_avg",
    "avg_fwd_segment_size": "fwd_seg_size_avg", "avg_bwd_segment_size": "bwd_seg_size_avg",
    "fwd_avg_bytes_bulk": "fwd_byts_b_avg", "fwd_avg_packets_bulk": "fwd_pkts_b_avg",
    "fwd_avg_bulk_rate": "fwd_blk_rate_avg", "bwd_avg_bytes_bulk": "bwd_byts_b_avg",
    "bwd_avg_packets_bulk": "bwd_pkts_b_avg", "bwd_avg_bulk_rate": "bwd_blk_rate_avg",
    "subflow_fwd_packets": "subflow_fwd_pkts", "subflow_fwd_bytes": "subflow_fwd_byts",
    "subflow_bwd_packets": "subflow_bwd_pkts", "subflow_bwd_bytes": "subflow_bwd_byts",
    "init_win_bytes_forward": "init_fwd_win_byts", "init_win_bytes_backward": "init_bwd_win_byts",
    "act_data_pkt_fwd": "fwd_act_data_pkts", "min_seg_size_forward": "fwd_seg_size_min",
    "active_mean": "active_mean", "active_std": "active_std", "active_max": "active_max",
    "active_min": "active_min", "idle_mean": "idle_mean", "idle_std": "idle_std",
    "idle_max": "idle_max", "idle_min": "idle_min",
}


def stats(values: pd.Series) -> dict[str, float | int | None]:
    numeric = pd.to_numeric(values, errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
    return {
        "count": int(len(numeric)),
        "median": float(numeric.median()) if len(numeric) else None,
        "mean": float(numeric.mean()) if len(numeric) else None,
        "p95": float(numeric.quantile(0.95)) if len(numeric) else None,
        "percentage_zero": float((numeric == 0).mean() * 100) if len(numeric) else None,
    }


def main() -> None:
    existing = [path for path in TARGETS if path.exists()]
    if existing:
        raise SystemExit("refusing to overwrite: " + ", ".join(map(str, existing)))
    metadata = json.loads((ROOT / "models/model_metadata.json").read_text())
    features = metadata["feature_names"]
    audit = json.loads((ROOT / "reports/metrics/experiment_c_feature_semantics_audit.json").read_text())
    audit_by_feature = {item["model_feature"]: item for item in audit["features"]}
    cic_sample_path = ROOT / "data/raw/cicids2017/Monday-WorkingHours.pcap_ISCX.csv"
    cic_headers = [name.strip() for name in raw_header(cic_sample_path)]
    assert len(cic_headers) == 79 and cic_headers[-1] == "Label"
    hist_headers = raw_header(SCENARIOS["normal-http-test"][0])

    crosswalk = []
    java_map: dict[str, str] = {}
    for index, model_feature in enumerate(features):
        cic_header = cic_headers[index]
        if model_feature == "cwe_flag_count":
            java_header, java_index = "Fwd URG Flags", hist_headers.index("Fwd URG Flags")
            status, mapping = "DATASET_ARTIFACT_REPRODUCTION", "released_dataset_artifact"
            evidence = "All-row audit established released CWE Flag Count equals Fwd URG Flags; Java CWR Flag Count is explicitly not substituted."
        elif model_feature == "fwd_header_length.1":
            java_header, java_index = "Fwd Header Length", hist_headers.index("Fwd Header Length")
            status, mapping = "DATASET_ARTIFACT_REPRODUCTION", "released_duplicate_column_artifact"
            evidence = "Released CICIDS2017 repeats Fwd Header Length with identical values; current Java schema omits that duplicate."
        else:
            offset = 4 if index == 0 else index + 6
            if index > features.index("fwd_header_length.1"):
                offset -= 1
            java_header, java_index = hist_headers[offset], offset
            status, mapping = "EXACT", "direct_historical_java_column"
            evidence = (
                "Direct ordered Java FlowFeature column corresponding to the released CICIDS2017 header; "
                "reviewed Java source is the prior semantics reference. Exact V3 binary identity remains unproven."
            )
        java_map[model_feature] = java_header
        prior = audit_by_feature[model_feature]
        crosswalk.append({
            "model_feature": model_feature,
            "cicids2017_raw_header": cic_header,
            "historical_java_raw_header": java_header,
            "historical_java_column_index_zero_based": java_index,
            "mapping_type": mapping,
            "unit": prior.get("training_unit", "unknown"),
            "semantic_definition": prior.get("notes") or prior.get("evidence"),
            "direction_convention": prior.get("direction_convention", "unknown"),
            "aggregation_convention": prior.get("aggregation_convention", "unknown"),
            "conversion_required": "NO",
            "conversion_formula": "identity" if status == "EXACT" else (
                "cwe_flag_count = fwd_urg_flags" if model_feature == "cwe_flag_count"
                else "fwd_header_length.1 = fwd_header_length"
            ),
            "confidence": "HIGH" if status == "DATASET_ARTIFACT_REPRODUCTION" else "MEDIUM_HIGH",
            "evidence": evidence,
            "compatibility_status": status,
        })

    schema = {name: schema_audit(paths[0]) for name, paths in SCENARIOS.items()}
    schema_comparison = {
        "cicids2017_column_count": len(cic_headers),
        "cicids2017_ordered_headers": cic_headers,
        "active_model_feature_count": len(features),
        "active_model_ordered_features": features,
        "historical_java_differences": [
            "Historical Java has 7 flow identifier/timestamp columns plus 76 numeric columns and Label (84 total).",
            "Released MachineLearningCSV has 78 numeric model features plus Label (79 total).",
            "Java CWR Flag Count is not the released CWE artifact and is excluded from the model crosswalk.",
            "Released Fwd Header Length.1 is absent from current Java and is reproduced only as an explicit dataset artifact.",
        ],
    }

    flow_summaries, flow_rows = {}, []
    loaded = {}
    for scenario, (hist_path, py_path) in SCENARIOS.items():
        hist, hieu = pd.read_csv(hist_path), pd.read_csv(py_path)
        loaded[scenario] = hist
        summary, rows = flow_comparison(scenario, hist, hieu, java_map)
        flow_summaries[scenario] = summary
        flow_rows.extend(rows)

    numeric_rows = [row for row in flow_rows if row["record_type"] == "feature_comparison"]
    largest_numeric = sorted(
        numeric_rows,
        key=lambda row: finite_float(row.get("mean_symmetric_relative_difference")) or -1,
        reverse=True,
    )[:10]

    diagnostic = json.loads((ROOT / "reports/metrics/experiment_c_portscan_diagnostic.json").read_text())
    top_features = [item["feature"] for item in diagnostic["model_feature_importances"][:10]]
    needed_cic = [cic_headers[features.index(feature)] for feature in top_features] + ["Label"]
    normal_parts, portscan_parts = [], []
    for path in sorted((ROOT / "data/raw/cicids2017").glob("*.csv")):
        chunk = pd.read_csv(path, usecols=needed_cic, skipinitialspace=True, low_memory=False)
        chunk.columns = [name.strip() for name in chunk.columns]
        labels = chunk["Label"].astype(str).str.strip()
        normal_parts.append(chunk.loc[labels == "BENIGN"])
        portscan_parts.append(chunk.loc[labels.str.casefold() == "portscan"])
    cic_normal = pd.concat(normal_parts, ignore_index=True)
    cic_portscan = pd.concat(portscan_parts, ignore_index=True)

    dist_rows = []
    for comparison, cic_frame, historical in [
        ("CICIDS2017_BENIGN_vs_historical_normal_http", cic_normal, loaded["normal-http-test"]),
        ("CICIDS2017_PortScan_vs_historical_portscan", cic_portscan, loaded["portscan-test"]),
    ]:
        for rank, feature in enumerate(top_features, 1):
            cic_header = cic_headers[features.index(feature)]
            hist_header = java_map[feature]
            cic_values = pd.to_numeric(cic_frame[cic_header], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
            hist_values = pd.to_numeric(historical[hist_header], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
            ks = float(ks_2samp(cic_values, hist_values, method="asymp").statistic) if len(cic_values) and len(hist_values) else None
            dist_rows.append({
                "comparison": comparison, "importance_rank": rank, "model_feature": feature,
                "cicids2017_header": cic_header, "historical_java_header": hist_header,
                **{f"cicids2017_{key}": value for key, value in stats(cic_values).items()},
                **{f"historical_{key}": value for key, value in stats(hist_values).items()},
                "ks_statistic": ks,
                "shift_interpretation": "large" if ks is not None and ks >= 0.5 else "moderate" if ks is not None and ks >= 0.2 else "small",
                "warning": "KS indicates distribution difference, not semantic incompatibility by itself.",
            })

    status_counts = Counter(row["compatibility_status"] for row in crosswalk)
    gate_checks = {
        "all_78_have_justified_source_mappings": len(crosswalk) == 78 and not status_counts["MISSING"],
        "no_semantic_mismatch": not status_counts["SEMANTIC_MISMATCH"],
        "no_uncertain": not status_counts["UNCERTAIN"],
        "only_supported_unit_conversion": not status_counts["SOURCE_SUPPORTED_UNIT_CONVERSION"],
        "dataset_artifacts_explicit": status_counts["DATASET_ARTIFACT_REPRODUCTION"] == 2,
        "flow_accounting_understood": False,
        "raw_outputs_archived": all(path.exists() for path, _ in SCENARIOS.values()),
        "v3_v4_limitation_documented": True,
    }
    decision = "COMPATIBILITY_GATE_PARTIAL"
    reason = (
        "All 78 columns have direct Java-source or explicit artifact mappings and no value conversion is required, "
        "but current V4 source is not proven to be the exact CICIDS2017 V3 generator. Normal HTTP also demonstrates "
        "material flow segmentation differences (61 Java rows versus 32 hieulw rows), including unresolved parser/eligibility differences, so compatibility is not yet sufficient for inference."
    )
    report = {
        "status": "completed",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Read-only schema, flow, source-mapping, numerical, and distribution validation; no inference or raw CSV transformation.",
        "provenance": {
            "source_commit": "98a5ebad0df579cc8b43eedd3421b3ae87699901",
            "java": "1.8.0_492", "platform": "linux/amd64",
            "docker_image": "sha256:c76ee60a99fe974fa6140a09609a576afd72a2e7712a5ad14dbecbb41982155f",
            "limitation": "Pinned public source identifies as V4; exact CICIDS2017 V3 binary identity is not established.",
        },
        "raw_schema_audit": schema,
        "schema_comparison": schema_comparison,
        "flow_construction_comparison": flow_summaries,
        "normal_http_count_investigation": {
            "finding": "Thirty bidirectional identities are shared. For every shared identity Java emits two rows while hieulw emits one (60 versus 30 rows). Java also emits one unmatched protocol-0 identity; hieulw emits two unmatched UDP broadcast/multicast identities (NBNS and mDNS).",
            "likely_mechanism": "Current Java FlowGenerator FIN/RST/timeout termination differs from hieulw session assembly, producing two partial Java segments per shared HTTP identity. The Java protocol-0 artifact and absence of the two hieulw UDP identities show an additional parser/flow-eligibility difference whose exact cause is unresolved.",
            "portscan_contrast": "Each scan identity is a short independent connection; both extractors emit one row for each of 1000 identities, so persistent-connection teardown differences do not accumulate.",
        },
        "same_flow_numerical_comparison": {
            "reliable_pair_rule": "Only identity groups containing exactly one Java and one hieulw row are used numerically.",
            "largest_discrepancies": largest_numeric,
            "table": str(OUT_FLOW.relative_to(ROOT)),
        },
        "crosswalk": {
            "feature_count": len(crosswalk), "status_counts": dict(status_counts),
            "table": str(OUT_CROSSWALK.relative_to(ROOT)),
            "v3_v4_warning": "EXACT denotes a direct mapping to the reviewed pinned Java computation/released header, not proof that this commit is the original V3 binary.",
        },
        "dataset_artifacts": {
            "cwe_flag_count": "DATASET_ARTIFACT_REPRODUCTION: cwe_flag_count = fwd_urg_flags; Java CWR is excluded.",
            "fwd_header_length.1": "DATASET_ARTIFACT_REPRODUCTION: duplicate fwd_header_length.",
        },
        "distribution_check": {
            "top_feature_count": len(top_features), "top_features": top_features,
            "normal_max_ks": max(row["ks_statistic"] for row in dist_rows if "BENIGN" in row["comparison"]),
            "portscan_max_ks": max(row["ks_statistic"] for row in dist_rows if "PortScan" in row["comparison"]),
            "interpretation": "Large shifts exist, but external lab traffic is not expected to reproduce training distributions; shifts cannot alone distinguish semantics from environment without a V3 reference PCAP/CSV pair.",
            "table": str(OUT_DIST.relative_to(ROOT)),
        },
        "validation_gate": {"checks": gate_checks, "decision": decision, "reason": reason},
        "safety": {"model_inference_run": False, "model_retrained": False, "raw_csv_modified": False},
    }

    for path in TARGETS:
        path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(crosswalk).to_csv(OUT_CROSSWALK, index=False)
    pd.DataFrame(flow_rows).to_csv(OUT_FLOW, index=False)
    pd.DataFrame(dist_rows).to_csv(OUT_DIST, index=False)
    OUT_JSON.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")

    print("Historical CICFlowMeter Compatibility")
    print("======================================")
    print("Normal flows:")
    print("historical:", flow_summaries["normal-http-test"]["historical_flow_count"])
    print("hieulw:", flow_summaries["normal-http-test"]["hieulw_flow_count"])
    print("matched:", flow_summaries["normal-http-test"]["matched_flows_by_bidirectional_identity"])
    print("PortScan flows:")
    print("historical:", flow_summaries["portscan-test"]["historical_flow_count"])
    print("hieulw:", flow_summaries["portscan-test"]["hieulw_flow_count"])
    print("matched:", flow_summaries["portscan-test"]["matched_flows_by_bidirectional_identity"])
    print("78-feature crosswalk:")
    for name in ["EXACT", "SOURCE_SUPPORTED_UNIT_CONVERSION", "DATASET_ARTIFACT_REPRODUCTION", "SEMANTIC_MISMATCH", "UNCERTAIN", "MISSING"]:
        print(f"{name}: {status_counts[name]}")
    print("Largest flow-construction difference: Normal HTTP Java emits two segments for each of 30 shared identities; two hieulw UDP identities and one Java protocol-0 identity remain unmatched.")
    print("Largest semantic differences: Java payload/termination/statistical conventions differ materially from hieulw; Java CWR is not CICIDS2017 CWE.")
    print("CICIDS2017 distribution shift:")
    print("Normal: max top-feature KS", report["distribution_check"]["normal_max_ks"])
    print("PortScan: max top-feature KS", report["distribution_check"]["portscan_max_ks"])
    print("Compatibility gate:", decision)
    print("Reason:", reason)
    print("Do not run model inference.")


if __name__ == "__main__":
    main()
