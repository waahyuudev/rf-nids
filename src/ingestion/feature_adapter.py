"""Strict adapter from CICFlowMeter-style rows to active-model features."""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from src.preprocessing.columns import normalize_column_name

from .cicflowmeter_mapping import (
    EXTRACTOR_TO_MODEL_FEATURE,
    INCOMPATIBLE_MODEL_FEATURES,
)
from .models import AdaptedFlow, ExtractedFlow


class FeatureCompatibilityError(ValueError):
    """Raised when extractor output cannot defensibly satisfy the active model."""


METADATA_ALIASES = {
    "timestamp": "capture_time",
    "src_ip": "source_ip",
    "source_ip": "source_ip",
    "src_port": "source_port",
    "source_port": "source_port",
    "dst_ip": "destination_ip",
    "destination_ip": "destination_ip",
    "dst_port": "destination_port",
    "destination_port": "destination_port",
    "protocol": "protocol",
}


def load_feature_names(metadata_path: Path) -> list[str]:
    data = json.loads(metadata_path.read_text(encoding="utf-8"))
    names = data.get("feature_names")
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise ValueError("Model metadata must contain a string feature_names list")
    return names


class FeatureAdapter:
    """Normalize, validate, order, and numerically coerce one extracted flow."""

    def __init__(self, feature_names: list[str]) -> None:
        if len(feature_names) != len(set(feature_names)):
            raise ValueError("Active model feature names contain duplicates")
        self.feature_names = list(feature_names)

    @classmethod
    def from_metadata(cls, metadata_path: Path) -> "FeatureAdapter":
        return cls(load_feature_names(metadata_path))

    @staticmethod
    def _normalized(fields: Mapping[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for raw_name, value in fields.items():
            normalized_name = normalize_column_name(raw_name)
            name = EXTRACTOR_TO_MODEL_FEATURE.get(normalized_name, normalized_name)
            if name in result:
                raise FeatureCompatibilityError(
                    f"Duplicate field after normalization: {name}"
                )
            result[name] = value
        return result

    def compatibility(self, extractor_names: list[str]) -> dict[str, Any]:
        normalized = [normalize_column_name(name) for name in extractor_names]
        mapped_names = [EXTRACTOR_TO_MODEL_FEATURE.get(name, name) for name in normalized]
        counts = Counter(mapped_names)
        duplicates = sorted(name for name, count in counts.items() if count > 1)
        raw_duplicates = sorted(
            name for name, count in Counter(extractor_names).items() if count > 1
        )
        available = set(mapped_names)
        required = set(self.feature_names)
        exact = sorted(name for name in required if name in extractor_names)
        alias_matches = sorted(
            target
            for source, target in EXTRACTOR_TO_MODEL_FEATURE.items()
            if source in normalized and target in required
        )
        normalized_matches = sorted((set(normalized) & required) - set(exact))
        suspicious = list(duplicates)
        if ("fwd_header_length" in available) != ("fwd_header_length.1" in available):
            suspicious.append("fwd_header_length pair is incomplete")
        return {
            "compatible": not (required - available) and not duplicates,
            "active_model_feature_count": len(self.feature_names),
            "extractor_feature_count": len(extractor_names),
            "exact_matches": exact,
            "normalized_matches": normalized_matches,
            "mapped_matches": alias_matches,
            "missing_features": [name for name in self.feature_names if name not in available],
            "extra_features": sorted(set(normalized) - set(EXTRACTOR_TO_MODEL_FEATURE) - required - set(METADATA_ALIASES)),
            "duplicate_features": sorted(set(raw_duplicates + duplicates)),
            "duplicate_feature_audit": {
                "raw_names": raw_duplicates,
                "normalized_names": duplicates,
            },
            # Backward-compatible names used by the ingestion runner and earlier callers.
            "model_feature_count": len(self.feature_names),
            "extractor_field_count": len(extractor_names),
            "exact_match": exact,
            "mapped_fields": alias_matches + normalized_matches,
            "missing_fields": [name for name in self.feature_names if name not in available],
            "extra_fields": sorted(available - required - set(METADATA_ALIASES)),
            "duplicate_fields": duplicates,
            "suspicious_fields": sorted(set(suspicious)),
            "fwd_header_length_audit": {
                "policy": (
                    "Both fwd_header_length and fwd_header_length.1 are independent required "
                    "model inputs. The adapter never copies one into the other."
                ),
                "fwd_header_length_present": "fwd_header_length" in available,
                "fwd_header_length_1_present": "fwd_header_length.1" in available,
            },
            "incompatible_features": [
                name for name in self.feature_names
                if name in INCOMPATIBLE_MODEL_FEATURES and name not in available
            ],
        }

    def adapt(self, flow: ExtractedFlow) -> AdaptedFlow:
        normalized = self._normalized(flow.fields)
        missing = [name for name in self.feature_names if name not in normalized]
        if missing:
            raise FeatureCompatibilityError(f"Missing required features: {missing}")

        features: dict[str, float | None] = {}
        for name in self.feature_names:
            value = normalized[name]
            if value is None or (isinstance(value, str) and not value.strip()):
                features[name] = None
                continue
            if isinstance(value, bool):
                raise FeatureCompatibilityError(f"Feature '{name}' must be numeric")
            try:
                number = float(value)
            except (TypeError, ValueError) as exc:
                raise FeatureCompatibilityError(f"Feature '{name}' must be numeric") from exc
            features[name] = None if math.isnan(number) or math.isinf(number) else number

        metadata = dict(flow.metadata)
        for source_name, target_name in METADATA_ALIASES.items():
            if source_name in normalized and normalized[source_name] not in (None, ""):
                metadata.setdefault(target_name, normalized[source_name])
        fingerprint = flow.flow_id or self._fingerprint(metadata, features)
        return AdaptedFlow(features=features, metadata=metadata, fingerprint=fingerprint)

    @staticmethod
    def _fingerprint(metadata: Mapping[str, Any], features: Mapping[str, Any]) -> str:
        # Metadata identifies the 5-tuple/time where available; duration and packet counts
        # reduce collisions without making the fingerprint an ML feature.
        identity = {key: metadata.get(key) for key in sorted(METADATA_ALIASES.values())}
        for key in ("flow_duration", "total_fwd_packets", "total_backward_packets"):
            identity[key] = features.get(key)
        encoded = json.dumps(identity, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
