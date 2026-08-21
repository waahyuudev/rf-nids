from __future__ import annotations

from src.ingestion.cicflowmeter_mapping import (
    ARTIFACT_REPRODUCTIONS,
    CICIDS2017_DATASET_ARTIFACT_REPRODUCTION,
    EXTRACTOR_TO_MODEL_FEATURE,
    INCOMPATIBLE_MODEL_FEATURES,
    STRICT_SEMANTIC,
)
from src.ingestion.feature_adapter import FeatureAdapter, FeatureCompatibilityError
from src.ingestion.models import ExtractedFlow
from src.ingestion.feature_adapter import load_feature_names
from pathlib import Path

import pytest


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
    report = FeatureAdapter(
        ["cwe_flag_count"], compatibility_policy=STRICT_SEMANTIC
    ).compatibility(["cwr_flag_count"])
    assert report["compatible"] is False
    assert report["mapped_matches"] == []
    assert report["incompatible_features"] == ["cwe_flag_count"]
    assert "fwd_urg_flags" in INCOMPATIBLE_MODEL_FEATURES["cwe_flag_count"]["reason"]


def test_header_length_1_requires_independent_field() -> None:
    report = FeatureAdapter(
        ["fwd_header_length", "fwd_header_length.1"],
        compatibility_policy=STRICT_SEMANTIC,
    ).compatibility(["fwd_header_len"])
    assert report["compatible"] is False
    assert report["mapped_matches"] == ["fwd_header_length"]
    assert report["missing_features"] == ["fwd_header_length.1"]


def test_77_of_78_remains_incompatible_and_78_of_78_is_compatible() -> None:
    features = [f"feature_{index}" for index in range(78)]
    adapter = FeatureAdapter(features)
    assert adapter.compatibility(features[:-1])["compatible"] is False
    assert adapter.compatibility(features)["compatible"] is True


def test_artifacts_are_reproduced_only_from_allowlisted_sources() -> None:
    adapter = FeatureAdapter(
        ["fwd_header_length", "fwd_header_length.1", "fwd_urg_flags", "cwe_flag_count"]
    )
    adapted = adapter.adapt(
        ExtractedFlow(fields={"fwd_header_len": 40, "fwd_urg_flags": 3})
    )
    assert adapted.features == {
        "fwd_header_length": 40.0,
        "fwd_header_length.1": 40.0,
        "fwd_urg_flags": 3.0,
        "cwe_flag_count": 3.0,
    }
    assert set(ARTIFACT_REPRODUCTIONS) == {
        "fwd_header_length.1",
        "cwe_flag_count",
    }


def test_artifact_source_must_exist_and_unknown_missing_still_fails() -> None:
    adapter = FeatureAdapter(["fwd_header_length.1", "unknown_required_feature"])
    report = adapter.compatibility(["some_other_feature"])
    assert report["compatible"] is False
    assert report["artifact_reproduced_count"] == 0
    with pytest.raises(FeatureCompatibilityError, match="Missing required features"):
        adapter.adapt(ExtractedFlow(fields={"some_other_feature": 1}))


def test_artifact_reproduction_can_be_disabled() -> None:
    adapter = FeatureAdapter(
        ["fwd_header_length", "fwd_header_length.1", "fwd_urg_flags", "cwe_flag_count"],
        compatibility_policy=STRICT_SEMANTIC,
    )
    report = adapter.compatibility(["fwd_header_len", "fwd_urg_flags"])
    assert report["compatible"] is False
    assert report["artifact_reproduced_count"] == 0
    assert report["missing_features"] == ["fwd_header_length.1", "cwe_flag_count"]


def test_active_model_vector_is_exactly_78_numeric_ordered_features() -> None:
    root = Path(__file__).resolve().parents[2]
    features = load_feature_names(root / "models/model_metadata.json")
    inverse_alias = {target: source for source, target in EXTRACTOR_TO_MODEL_FEATURE.items()}
    artifact_targets = set(ARTIFACT_REPRODUCTIONS)
    fields = {
        inverse_alias.get(name, name): index + 1
        for index, name in enumerate(features)
        if name not in artifact_targets
    }
    adapter = FeatureAdapter(
        features,
        compatibility_policy=CICIDS2017_DATASET_ARTIFACT_REPRODUCTION,
    )
    adapted = adapter.adapt(ExtractedFlow(fields=fields))
    assert len(adapted.features) == 78
    assert list(adapted.features) == features
    assert all(isinstance(value, float) for value in adapted.features.values())
    assert adapted.features["fwd_header_length.1"] == adapted.features["fwd_header_length"]
    assert adapted.features["cwe_flag_count"] == adapted.features["fwd_urg_flags"]
