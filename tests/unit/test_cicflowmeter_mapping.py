from __future__ import annotations

from src.ingestion.cicflowmeter_mapping import (
    EXTRACTOR_TO_MODEL_FEATURE,
    INCOMPATIBLE_MODEL_FEATURES,
)
from src.ingestion.feature_adapter import FeatureAdapter


def test_verified_aliases_include_destination_port() -> None:
    report = FeatureAdapter(["destination_port"]).compatibility(["dst_port"])
    assert report["compatible"] is True
    assert report["mapped_matches"] == ["destination_port"]


def test_unknown_alias_is_rejected() -> None:
    report = FeatureAdapter(["destination_port"]).compatibility(["dest_port_guess"])
    assert report["compatible"] is False
    assert report["missing_features"] == ["destination_port"]


def test_bulk_and_segment_aliases_are_explicit() -> None:
    expected = {
        "fwd_byts_b_avg": "fwd_avg_bytes_bulk",
        "fwd_pkts_b_avg": "fwd_avg_packets_bulk",
        "fwd_blk_rate_avg": "fwd_avg_bulk_rate",
        "bwd_byts_b_avg": "bwd_avg_bytes_bulk",
        "bwd_pkts_b_avg": "bwd_avg_packets_bulk",
        "bwd_blk_rate_avg": "bwd_avg_bulk_rate",
        "fwd_seg_size_avg": "avg_fwd_segment_size",
        "bwd_seg_size_avg": "avg_bwd_segment_size",
        "fwd_seg_size_min": "min_seg_size_forward",
    }
    assert {key: EXTRACTOR_TO_MODEL_FEATURE[key] for key in expected} == expected
    assert FeatureAdapter(list(expected.values())).compatibility(list(expected))["compatible"]


def test_cwe_does_not_map_from_broken_cwr_output() -> None:
    report = FeatureAdapter(["cwe_flag_count"]).compatibility(["cwr_flag_count"])
    assert report["compatible"] is False
    assert report["mapped_matches"] == []
    assert report["incompatible_features"] == ["cwe_flag_count"]
    assert "fwd_urg_flags" in INCOMPATIBLE_MODEL_FEATURES["cwe_flag_count"]["reason"]


def test_header_length_1_requires_independent_field() -> None:
    report = FeatureAdapter(
        ["fwd_header_length", "fwd_header_length.1"]
    ).compatibility(["fwd_header_len"])
    assert report["compatible"] is False
    assert report["mapped_matches"] == ["fwd_header_length"]
    assert report["missing_features"] == ["fwd_header_length.1"]


def test_77_of_78_remains_incompatible_and_78_of_78_is_compatible() -> None:
    features = [f"feature_{index}" for index in range(78)]
    adapter = FeatureAdapter(features)
    assert adapter.compatibility(features[:-1])["compatible"] is False
    assert adapter.compatibility(features)["compatible"] is True
