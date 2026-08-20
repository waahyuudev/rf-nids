"""Audit extractor CSV headers against active-model metadata."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ingestion.feature_adapter import FeatureAdapter
from src.ingestion.cicflowmeter_mapping import (
    ALIAS_EVIDENCE,
    EXTRACTOR_TO_MODEL_FEATURE,
    INCOMPATIBLE_MODEL_FEATURES,
)
from src.ingestion.flow_extractor import FlowCsvExtractor
from src.preprocessing.columns import normalize_column_name


def _identical_percentage(path: Path, first: str, second: str) -> float | None:
    """Return equality percentage for two independently present raw CSV columns."""
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return None
        normalized_to_raw = {
            normalize_column_name(raw): raw for raw in reader.fieldnames
        }
        if first not in normalized_to_raw or second not in normalized_to_raw:
            return None
        pairs = [
            (row[normalized_to_raw[first]], row[normalized_to_raw[second]])
            for row in reader
        ]
    if not pairs:
        return None
    return round(100 * sum(left == right for left, right in pairs) / len(pairs), 4)


def build_report(input_path: Path, metadata_path: Path) -> dict:
    adapter = FeatureAdapter.from_metadata(metadata_path)
    report = adapter.compatibility(FlowCsvExtractor.field_names(input_path))
    report["status"] = "completed"
    report["fwd_header_length_audit"]["identical_value_percentage"] = (
        _identical_percentage(input_path, "fwd_header_length", "fwd_header_length.1")
    )
    report["fwd_header_length_audit"]["treated_as_independent_model_features"] = True
    report["exact_match_count"] = len(report["exact_matches"])
    report["verified_alias_count"] = len(report["mapped_matches"])
    report["unresolved_features"] = [
        name for name in report["missing_features"]
        if name not in INCOMPATIBLE_MODEL_FEATURES
    ]
    report["unresolved_count"] = len(report["unresolved_features"])
    report["incompatible_count"] = len(report["incompatible_features"])
    return report


def build_mapping_audit(report: dict) -> dict:
    present_aliases = set(report["mapped_matches"])
    entries = []
    for extractor, model in EXTRACTOR_TO_MODEL_FEATURE.items():
        if model in present_aliases:
            entries.append({
                "model_feature": model,
                "extractor_candidate": extractor,
                "status": "alias_verified",
                "reason": ALIAS_EVIDENCE[extractor],
            })
    for model, detail in INCOMPATIBLE_MODEL_FEATURES.items():
        if model in report["missing_features"]:
            entries.append({
                "model_feature": model,
                "extractor_candidate": detail["extractor_candidate"],
                "status": "incompatible",
                "reason": detail["reason"],
            })
    for model in report["unresolved_features"]:
        entries.append({
            "model_feature": model,
            "extractor_candidate": None,
            "status": "unresolved",
            "reason": "No explicit verified alias is registered.",
        })
    return {
        "extractor": report.get("extractor"),
        "audited_feature_count": len(entries),
        "categories": ["exact", "alias_verified", "unresolved", "incompatible"],
        "features": sorted(entries, key=lambda item: item["model_feature"]),
    }


def _print_summary(report: dict) -> None:
    mapped = len(report["normalized_matches"]) + len(report["mapped_matches"])
    print("RF-NIDS Live Feature Compatibility\n")
    print(f"Extractor             : {report['extractor']['name']} {report['extractor']['version']}")
    print(f"Active model features : {report['active_model_feature_count']}")
    print(f"Extractor features    : {report['extractor_feature_count']}")
    print(f"Exact matches         : {len(report['exact_matches'])}")
    print(f"Normalized/mapped     : {mapped}")
    print(f"Missing               : {len(report['missing_features'])}")
    print(f"Extra                 : {len(report['extra_features'])}\n")
    print(f"Compatible            : {'YES' if report['compatible'] else 'NO'}")
    if report["missing_features"]:
        print("\nMissing required features:")
        for name in report["missing_features"]:
            print(f"- {name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", "--extractor-csv", dest="input", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, default=ROOT / "models/model_metadata.json")
    parser.add_argument(
        "--output", type=Path,
        default=ROOT / "reports/metrics/live_feature_compatibility.json",
    )
    parser.add_argument(
        "--mapping-audit-output", type=Path,
        default=ROOT / "reports/metrics/live_feature_mapping_audit.json",
    )
    args = parser.parse_args()
    report = build_report(args.input, args.metadata)
    report.update({
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "extractor_csv": str(args.input),
        "model_metadata": str(args.metadata),
        "extractor": {
            "name": "hieulw/cicflowmeter",
            "version": "0.4.2",
            "source": "https://github.com/hieulw/cicflowmeter",
            "runtime": "Docker (Python 3.12)",
            "platform": "container-native linux/arm64 or linux/amd64",
        },
        "limitations": [
            "Python compatible implementation; not identical to the original Java CICFlowMeter used for CICIDS2017.",
            "Compatibility describes the observed CSV schema, not numerical equivalence with CICIDS2017 extraction.",
        ],
    })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    mapping_audit = build_mapping_audit(report)
    args.mapping_audit_output.parent.mkdir(parents=True, exist_ok=True)
    args.mapping_audit_output.write_text(
        json.dumps(mapping_audit, indent=2) + "\n", encoding="utf-8"
    )
    _print_summary(report)
    return 0 if report["compatible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
