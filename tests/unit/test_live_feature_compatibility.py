from __future__ import annotations

import csv
import json
from pathlib import Path

from scripts.check_live_feature_compatibility import build_report
from src.ingestion.cicflowmeter_mapping import STRICT_SEMANTIC


FEATURES = [
    "destination_port",
    "flow_duration",
    "fwd_header_length",
    "fwd_header_length.1",
]


def _metadata(path: Path) -> Path:
    path.write_text(json.dumps({"feature_names": FEATURES}), encoding="utf-8")
    return path


def _csv(path: Path, fields: list[str], rows: list[list[object]] | None = None) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(fields)
        writer.writerows(rows or [[1] * len(fields)])
    return path


def test_exact_compatibility_and_header_value_audit(tmp_path: Path) -> None:
    report = build_report(
        _csv(tmp_path / "flows.csv", FEATURES, [[443, 10, 20, 20], [80, 5, 30, 40]]),
        _metadata(tmp_path / "metadata.json"),
    )
    assert report["compatible"] is True
    assert len(report["exact_matches"]) == 4
    assert report["fwd_header_length_audit"]["identical_value_percentage"] == 50.0


def test_missing_header_length_1_is_incompatible(tmp_path: Path) -> None:
    report = build_report(
        _csv(tmp_path / "flows.csv", FEATURES[:-1]),
        _metadata(tmp_path / "metadata.json"),
        compatibility_policy=STRICT_SEMANTIC,
    )
    assert report["compatible"] is False
    assert report["missing_features"] == ["fwd_header_length.1"]


def test_extra_column_does_not_hide_complete_required_mapping(tmp_path: Path) -> None:
    report = build_report(
        _csv(tmp_path / "flows.csv", FEATURES + ["Label"]),
        _metadata(tmp_path / "metadata.json"),
    )
    assert report["compatible"] is True
    assert report["extra_features"] == ["label"]


def test_human_readable_names_normalize_consistently(tmp_path: Path) -> None:
    fields = ["Destination Port", "Flow Duration", "Fwd Header Length", "Fwd Header Length.1"]
    report = build_report(
        _csv(tmp_path / "flows.csv", fields),
        _metadata(tmp_path / "metadata.json"),
    )
    assert report["compatible"] is True
    assert set(report["normalized_matches"]) == set(FEATURES)


def test_normalized_duplicate_is_detected(tmp_path: Path) -> None:
    fields = FEATURES + [" Fwd Header Length"]
    report = build_report(
        _csv(tmp_path / "flows.csv", fields),
        _metadata(tmp_path / "metadata.json"),
    )
    assert report["compatible"] is False
    assert report["duplicate_features"] == ["fwd_header_length"]
    assert report["duplicate_feature_audit"]["normalized_names"] == ["fwd_header_length"]


def test_report_distinguishes_exact_alias_and_artifact_categories(tmp_path: Path) -> None:
    metadata = tmp_path / "metadata.json"
    metadata.write_text(
        json.dumps({
            "feature_names": [
                "flow_duration",
                "fwd_urg_flags",
                "fwd_header_length",
                "fwd_header_length.1",
                "cwe_flag_count",
            ]
        }),
        encoding="utf-8",
    )
    report = build_report(
        _csv(
            tmp_path / "flows.csv",
            ["flow_duration", "fwd_urg_flags", "fwd_header_len"],
        ),
        metadata,
    )
    assert report["exact_match_count"] == 2
    assert report["verified_alias_count"] == 1
    assert report["artifact_reproduced_count"] == 2
    assert report["missing_count"] == 0
    assert report["compatible"] is True
