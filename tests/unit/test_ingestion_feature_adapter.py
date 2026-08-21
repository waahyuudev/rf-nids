from __future__ import annotations

import math

import pytest

from src.ingestion.feature_adapter import FeatureAdapter, FeatureCompatibilityError
from src.ingestion.cicflowmeter_mapping import STRICT_SEMANTIC
from src.ingestion.models import ExtractedFlow


FEATURES = [
    "destination_port",
    "flow_duration",
    "fwd_header_length",
    "fwd_header_length.1",
]


def test_adapter_maps_orders_and_normalizes_numbers() -> None:
    adapter = FeatureAdapter(FEATURES)
    flow = ExtractedFlow(
        fields={
            " Fwd Header Length.1": "40",
            "Flow Duration": "12.5",
            "Destination Port": 443,
            "Fwd Header Length": float("inf"),
            "Source IP": "192.168.56.20",
        }
    )

    adapted = adapter.adapt(flow)

    assert list(adapted.features) == FEATURES
    assert adapted.features == {
        "destination_port": 443.0,
        "flow_duration": 12.5,
        "fwd_header_length": None,
        "fwd_header_length.1": 40.0,
    }
    assert adapted.metadata["source_ip"] == "192.168.56.20"
    assert adapted.fingerprint


def test_adapter_rejects_missing_feature_without_zero_fill() -> None:
    with pytest.raises(FeatureCompatibilityError, match="fwd_header_length.1"):
        FeatureAdapter(FEATURES, compatibility_policy=STRICT_SEMANTIC).adapt(
            ExtractedFlow(fields={name: 1 for name in FEATURES[:-1]})
        )


def test_adapter_rejects_non_numeric_and_boolean() -> None:
    values = {name: 1 for name in FEATURES}
    values["flow_duration"] = "not-a-number"
    with pytest.raises(FeatureCompatibilityError, match="flow_duration"):
        FeatureAdapter(FEATURES).adapt(ExtractedFlow(fields=values))
    values["flow_duration"] = True
    with pytest.raises(FeatureCompatibilityError, match="flow_duration"):
        FeatureAdapter(FEATURES).adapt(ExtractedFlow(fields=values))


def test_compatibility_audits_header_pair_and_duplicate_normalization() -> None:
    report = FeatureAdapter(
        FEATURES, compatibility_policy=STRICT_SEMANTIC
    ).compatibility(
        ["Destination Port", "Flow Duration", "Fwd Header Length", " fwd header length"]
    )
    assert report["compatible"] is False
    assert report["duplicate_fields"] == ["fwd_header_length"]
    assert report["missing_fields"] == ["fwd_header_length.1"]
    assert "fwd_header_length pair is incomplete" in report["suspicious_fields"]


def test_nan_becomes_null_representation() -> None:
    adapted = FeatureAdapter(FEATURES).adapt(
        ExtractedFlow(fields={name: math.nan for name in FEATURES})
    )
    assert all(value is None for value in adapted.features.values())
