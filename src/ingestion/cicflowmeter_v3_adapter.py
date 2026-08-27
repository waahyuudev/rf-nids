"""Fail-closed CICFlowMeter V3 adapter for the active CICIDS2017 model schema."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


ADAPTER_IDENTITY = "CICFLOWMETER_V3_CICIDS2017_MODEL_ADAPTER"
ADAPTER_VERSION = "1.0.0"
CICFLOWMETER_V3_COMMIT = "a26aae27f21d165ff30b4b28e75124a5f9b4b2c4"
CICFLOWMETER_V3_IMAGE_DIGEST = (
    "sha256:0227c7280e586d54144b9bb11b2a6b5d4b1c4ba9bc7c44199fa312a6b829caab"
)
CROSSWALK_PATH = "reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv"
CROSSWALK_SHA256 = "66e517cdcea217f19de4d0a2cd45302ede999388393f539fb8ca4a2c68b74cf4"

EXACT = "EXACT"
DATASET_ARTIFACT_REPRODUCTION = "DATASET_ARTIFACT_REPRODUCTION"

# Static by design. This is the reviewed Experiment C crosswalk, not a runtime
# normalization or fuzzy-matching table.
MAPPING_RULES: tuple[tuple[str, str, str], ...] = (
    ("destination_port", "Dst Port", EXACT),
    ("flow_duration", "Flow Duration", EXACT),
    ("total_fwd_packets", "Tot Fwd Pkts", EXACT),
    ("total_backward_packets", "Tot Bwd Pkts", EXACT),
    ("total_length_of_fwd_packets", "TotLen Fwd Pkts", EXACT),
    ("total_length_of_bwd_packets", "TotLen Bwd Pkts", EXACT),
    ("fwd_packet_length_max", "Fwd Pkt Len Max", EXACT),
    ("fwd_packet_length_min", "Fwd Pkt Len Min", EXACT),
    ("fwd_packet_length_mean", "Fwd Pkt Len Mean", EXACT),
    ("fwd_packet_length_std", "Fwd Pkt Len Std", EXACT),
    ("bwd_packet_length_max", "Bwd Pkt Len Max", EXACT),
    ("bwd_packet_length_min", "Bwd Pkt Len Min", EXACT),
    ("bwd_packet_length_mean", "Bwd Pkt Len Mean", EXACT),
    ("bwd_packet_length_std", "Bwd Pkt Len Std", EXACT),
    ("flow_bytes_s", "Flow Byts/s", EXACT),
    ("flow_packets_s", "Flow Pkts/s", EXACT),
    ("flow_iat_mean", "Flow IAT Mean", EXACT),
    ("flow_iat_std", "Flow IAT Std", EXACT),
    ("flow_iat_max", "Flow IAT Max", EXACT),
    ("flow_iat_min", "Flow IAT Min", EXACT),
    ("fwd_iat_total", "Fwd IAT Tot", EXACT),
    ("fwd_iat_mean", "Fwd IAT Mean", EXACT),
    ("fwd_iat_std", "Fwd IAT Std", EXACT),
    ("fwd_iat_max", "Fwd IAT Max", EXACT),
    ("fwd_iat_min", "Fwd IAT Min", EXACT),
    ("bwd_iat_total", "Bwd IAT Tot", EXACT),
    ("bwd_iat_mean", "Bwd IAT Mean", EXACT),
    ("bwd_iat_std", "Bwd IAT Std", EXACT),
    ("bwd_iat_max", "Bwd IAT Max", EXACT),
    ("bwd_iat_min", "Bwd IAT Min", EXACT),
    ("fwd_psh_flags", "Fwd PSH Flags", EXACT),
    ("bwd_psh_flags", "Bwd PSH Flags", EXACT),
    ("fwd_urg_flags", "Fwd URG Flags", EXACT),
    ("bwd_urg_flags", "Bwd URG Flags", EXACT),
    ("fwd_header_length", "Fwd Header Len", EXACT),
    ("bwd_header_length", "Bwd Header Len", EXACT),
    ("fwd_packets_s", "Fwd Pkts/s", EXACT),
    ("bwd_packets_s", "Bwd Pkts/s", EXACT),
    ("min_packet_length", "Pkt Len Min", EXACT),
    ("max_packet_length", "Pkt Len Max", EXACT),
    ("packet_length_mean", "Pkt Len Mean", EXACT),
    ("packet_length_std", "Pkt Len Std", EXACT),
    ("packet_length_variance", "Pkt Len Var", EXACT),
    ("fin_flag_count", "FIN Flag Cnt", DATASET_ARTIFACT_REPRODUCTION),
    ("syn_flag_count", "SYN Flag Cnt", DATASET_ARTIFACT_REPRODUCTION),
    ("rst_flag_count", "RST Flag Cnt", DATASET_ARTIFACT_REPRODUCTION),
    ("psh_flag_count", "PSH Flag Cnt", DATASET_ARTIFACT_REPRODUCTION),
    ("ack_flag_count", "ACK Flag Cnt", DATASET_ARTIFACT_REPRODUCTION),
    ("urg_flag_count", "URG Flag Cnt", DATASET_ARTIFACT_REPRODUCTION),
    ("cwe_flag_count", "Fwd URG Flags", DATASET_ARTIFACT_REPRODUCTION),
    ("ece_flag_count", "ECE Flag Cnt", DATASET_ARTIFACT_REPRODUCTION),
    ("down_up_ratio", "Down/Up Ratio", EXACT),
    ("average_packet_size", "Pkt Size Avg", EXACT),
    ("avg_fwd_segment_size", "Fwd Seg Size Avg", EXACT),
    ("avg_bwd_segment_size", "Bwd Seg Size Avg", EXACT),
    ("fwd_header_length.1", "Fwd Header Len", DATASET_ARTIFACT_REPRODUCTION),
    ("fwd_avg_bytes_bulk", "Fwd Byts/b Avg", EXACT),
    ("fwd_avg_packets_bulk", "Fwd Pkts/b Avg", EXACT),
    ("fwd_avg_bulk_rate", "Fwd Blk Rate Avg", EXACT),
    ("bwd_avg_bytes_bulk", "Bwd Byts/b Avg", EXACT),
    ("bwd_avg_packets_bulk", "Bwd Pkts/b Avg", EXACT),
    ("bwd_avg_bulk_rate", "Bwd Blk Rate Avg", EXACT),
    ("subflow_fwd_packets", "Subflow Fwd Pkts", EXACT),
    ("subflow_fwd_bytes", "Subflow Fwd Byts", EXACT),
    ("subflow_bwd_packets", "Subflow Bwd Pkts", EXACT),
    ("subflow_bwd_bytes", "Subflow Bwd Byts", EXACT),
    ("init_win_bytes_forward", "Init Fwd Win Byts", EXACT),
    ("init_win_bytes_backward", "Init Bwd Win Byts", EXACT),
    ("act_data_pkt_fwd", "Fwd Act Data Pkts", EXACT),
    ("min_seg_size_forward", "Fwd Seg Size Min", EXACT),
    ("active_mean", "Active Mean", EXACT),
    ("active_std", "Active Std", EXACT),
    ("active_max", "Active Max", EXACT),
    ("active_min", "Active Min", EXACT),
    ("idle_mean", "Idle Mean", EXACT),
    ("idle_std", "Idle Std", EXACT),
    ("idle_max", "Idle Max", EXACT),
    ("idle_min", "Idle Min", EXACT),
)

MODEL_FEATURES = tuple(rule[0] for rule in MAPPING_RULES)
REQUIRED_V3_HEADERS = tuple(dict.fromkeys(rule[1] for rule in MAPPING_RULES))
ARTIFACT_FIELDS = tuple(rule[0] for rule in MAPPING_RULES if rule[2] == DATASET_ARTIFACT_REPRODUCTION)


class CICFlowMeterV3AdapterError(ValueError):
    """Raised when V3 data cannot satisfy the audited model-facing contract."""


@dataclass(frozen=True)
class AdaptationResult:
    features: pd.DataFrame
    provenance: dict[str, Any]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CICFlowMeterV3ModelAdapter:
    """Map official V3 rows to exactly the active model's 78 input features."""

    def __init__(self, feature_names: list[str] | tuple[str, ...] | None = None) -> None:
        active = tuple(feature_names) if feature_names is not None else MODEL_FEATURES
        duplicates = sorted(name for name, count in Counter(active).items() if count > 1)
        if duplicates:
            raise CICFlowMeterV3AdapterError(f"Active model features contain duplicates: {duplicates}")
        if active != MODEL_FEATURES:
            raise CICFlowMeterV3AdapterError("Active model feature names/order differ from audited V3 mapping")
        self.feature_names = active

    @classmethod
    def from_metadata(cls, metadata_path: Path) -> "CICFlowMeterV3ModelAdapter":
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            names = metadata["feature_names"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise CICFlowMeterV3AdapterError(f"Unable to load model feature metadata: {exc}") from exc
        if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
            raise CICFlowMeterV3AdapterError("Model metadata feature_names must be a string list")
        return cls(names)

    def adapt(
        self,
        data: pd.DataFrame | Mapping[str, Any],
        *,
        raw_input_path: Path | None = None,
        raw_input_sha256: str | None = None,
    ) -> AdaptationResult:
        frame = pd.DataFrame([dict(data)]) if isinstance(data, Mapping) else data
        if not isinstance(frame, pd.DataFrame):
            raise CICFlowMeterV3AdapterError("Input must be a mapping or pandas DataFrame")
        raw_duplicates = list(frame.columns[frame.columns.duplicated()])
        if raw_duplicates:
            raise CICFlowMeterV3AdapterError(f"Duplicate V3 headers: {raw_duplicates}")
        missing = [name for name in REQUIRED_V3_HEADERS if name not in frame.columns]
        if missing:
            raise CICFlowMeterV3AdapterError(f"Missing required V3 source fields: {missing}")

        output: dict[str, pd.Series] = {}
        for target, source, _status in MAPPING_RULES:
            try:
                output[target] = pd.to_numeric(frame[source], errors="raise").copy()
            except (TypeError, ValueError) as exc:
                raise CICFlowMeterV3AdapterError(
                    f"V3 source field '{source}' for '{target}' must be numeric"
                ) from exc
        adapted = pd.DataFrame(output, index=frame.index)
        if tuple(adapted.columns) != self.feature_names or adapted.shape[1] != 78:
            raise CICFlowMeterV3AdapterError("Adapter output violated exact 78-feature schema/order")
        if adapted.columns.duplicated().any():
            raise CICFlowMeterV3AdapterError("Adapter output contains duplicate features")

        numeric = adapted.to_numpy(dtype=np.float64, copy=True)
        counts = {
            "positive_infinity": int(np.isposinf(numeric).sum()),
            "negative_infinity": int(np.isneginf(numeric).sum()),
            "nan": int(np.isnan(numeric).sum()),
            "total": int((~np.isfinite(numeric)).sum()),
        }
        # This is the same boundary used by training before the fitted pipeline's
        # existing imputer. The adapter must not fit or perform imputation itself.
        adapted = adapted.replace([np.inf, -np.inf], np.nan).astype(np.float32)
        after = adapted.to_numpy(dtype=np.float64, copy=False)
        provenance = {
            "adapter_identity": ADAPTER_IDENTITY,
            "adapter_version": ADAPTER_VERSION,
            "cicflowmeter_v3_commit": CICFLOWMETER_V3_COMMIT,
            "cicflowmeter_v3_image_digest": CICFLOWMETER_V3_IMAGE_DIGEST,
            "crosswalk_path": CROSSWALK_PATH,
            "crosswalk_sha256": CROSSWALK_SHA256,
            "raw_input_path": str(raw_input_path) if raw_input_path else None,
            "raw_input_sha256": raw_input_sha256,
            "raw_row_count": len(frame),
            "output_row_count": len(adapted),
            "output_feature_count": adapted.shape[1],
            "artifact_reproduction_fields": list(ARTIFACT_FIELDS),
            "non_finite_before": counts,
            "non_finite_after": {
                "positive_infinity": int(np.isposinf(after).sum()),
                "negative_infinity": int(np.isneginf(after).sum()),
                "nan": int(np.isnan(after).sum()),
                "total": int((~np.isfinite(after)).sum()),
            },
            "imputation_performed": False,
            "schema_validation": "PASS",
        }
        return AdaptationResult(features=adapted, provenance=provenance)

    def adapt_csv(self, path: Path) -> AdaptationResult:
        return self.adapt(
            pd.read_csv(path), raw_input_path=path, raw_input_sha256=sha256_file(path)
        )

