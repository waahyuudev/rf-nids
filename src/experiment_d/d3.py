"""Deterministic, fit-free Experiment D D3 dataset planning helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import zlib
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import numpy as np

PROVENANCE_COLUMNS = frozenset({
    "source_family", "source_file", "capture_id", "session_id", "scenario_id",
    "ground_truth_class", "split_role", "original_row_index", "row_identity",
})
RF_V2_OUTPUTS = (
    "models/experiment_d/random_forest_rf_v2.joblib",
    "models/experiment_d/random_forest_rf_v2_metadata.json",
    "models/experiment_d/training_manifest.json",
)
RF_V1_FORBIDDEN_NAMES = frozenset({
    "random_forest_active.joblib", "random_forest_tuned.joblib",
    "random_forest_baseline.joblib", "model_metadata.json",
})


def canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def encode_index_membership(indices: Iterable[int], row_count: int) -> dict[str, Any]:
    """Encode exact index membership as a portable compressed bitset."""
    if row_count < 0:
        raise ValueError("row_count cannot be negative")
    bits = np.zeros(row_count, dtype=np.uint8)
    values = np.asarray(list(indices), dtype=np.int64)
    if len(values) and (values.min() < 0 or values.max() >= row_count):
        raise ValueError("membership index outside row_count")
    if len(np.unique(values)) != len(values):
        raise ValueError("membership indices must be unique")
    bits[values] = 1
    packed = np.packbits(bits, bitorder="little").tobytes()
    compressed = zlib.compress(packed, level=9)
    return {
        "encoding": "zlib+base64+numpy-packbits-little",
        "row_count": row_count,
        "member_count": int(len(values)),
        "packed_sha256": hashlib.sha256(packed).hexdigest(),
        "data": base64.b64encode(compressed).decode("ascii"),
    }


def decode_index_membership(spec: dict[str, Any]) -> np.ndarray:
    if spec.get("encoding") != "zlib+base64+numpy-packbits-little":
        raise ValueError("unsupported membership encoding")
    packed = zlib.decompress(base64.b64decode(spec["data"], validate=True))
    if hashlib.sha256(packed).hexdigest() != spec["packed_sha256"]:
        raise ValueError("membership checksum mismatch")
    bits = np.unpackbits(np.frombuffer(packed, dtype=np.uint8), bitorder="little")
    result = np.flatnonzero(bits[: int(spec["row_count"])]).astype(np.int64)
    if len(result) != int(spec["member_count"]):
        raise ValueError("membership count mismatch")
    return result


def encode_int64_sequence(values: Iterable[int]) -> dict[str, Any]:
    array = np.asarray(list(values), dtype="<i8")
    raw = array.tobytes()
    return {
        "encoding": "zlib+base64+little-endian-int64",
        "count": int(len(array)),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "data": base64.b64encode(zlib.compress(raw, level=9)).decode("ascii"),
    }


def decode_int64_sequence(spec: dict[str, Any]) -> np.ndarray:
    if spec.get("encoding") != "zlib+base64+little-endian-int64":
        raise ValueError("unsupported int64 sequence encoding")
    raw = zlib.decompress(base64.b64decode(spec["data"], validate=True))
    if hashlib.sha256(raw).hexdigest() != spec["raw_sha256"]:
        raise ValueError("int64 sequence checksum mismatch")
    result = np.frombuffer(raw, dtype="<i8").copy()
    if len(result) != int(spec["count"]):
        raise ValueError("int64 sequence count mismatch")
    return result


def deterministic_rank(row_identity: str, seed: int) -> str:
    return hashlib.sha256(f"experiment-d-d3|{seed}|{row_identity}".encode()).hexdigest()


def deterministic_cap(rows: list[dict[str, Any]], cap: int, seed: int) -> list[dict[str, Any]]:
    if cap < 0:
        raise ValueError("cap cannot be negative")
    return sorted(rows, key=lambda x: (deterministic_rank(x["row_identity"], seed), x["row_identity"]))[:cap]


def assert_session_separation(rows: Iterable[dict[str, Any]]) -> None:
    roles: dict[str, set[str]] = {}
    captures: dict[str, set[str]] = {}
    for row in rows:
        roles.setdefault(row["session_id"], set()).add(row["split_role"])
        captures.setdefault(row["capture_id"], set()).add(row["split_role"])
    bad = sorted(k for k, v in {**roles, **captures}.items() if len(v) > 1)
    if bad:
        raise ValueError(f"session/capture split leakage: {bad}")


def assert_provenance_not_features(feature_names: Iterable[str]) -> None:
    overlap = sorted(PROVENANCE_COLUMNS & set(feature_names))
    if overlap:
        raise ValueError(f"provenance columns cannot be model features: {overlap}")


def validate_output_contract(paths: Iterable[str | Path]) -> None:
    normalized = {Path(path).as_posix() for path in paths}
    if any(Path(path).name in RF_V1_FORBIDDEN_NAMES for path in normalized):
        raise ValueError("RF-v1 output destination is immutable/prohibited")
    if normalized != set(RF_V2_OUTPUTS):
        raise ValueError(f"RF-v2 outputs must be exactly {RF_V2_OUTPUTS}")


def class_counts(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(row["ground_truth_class"] for row in rows)
    return {name: int(counts[name]) for name in ("Normal", "DDoS", "PortScan")}
