"""Path-independent Experiment D scientific manifests."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.experiment_d.integrity import sha256_file


Role = Literal["adaptation", "final_test"]
ClassName = Literal["Normal", "DDoS", "PortScan"]


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")
    experiment_code: Literal["EXPERIMENT_D"] = "EXPERIMENT_D"
    role: Role
    class_name: ClassName = Field(alias="class")
    capture_id: str | None = None
    session_id: str | None = None
    source_host: str | None = None
    target_host: str | None = None
    capture_started_at: datetime | None = None
    capture_ended_at: datetime | None = None
    scenario_id: str | None = None

    @model_validator(mode="after")
    def time_order(self) -> "Provenance":
        if self.capture_started_at and self.capture_ended_at:
            if self.capture_ended_at <= self.capture_started_at:
                raise ValueError("capture_ended_at must follow capture_started_at")
        return self

    def require_complete(self) -> None:
        fields = ("capture_id", "session_id", "source_host", "target_host",
                  "capture_started_at", "capture_ended_at", "scenario_id")
        missing = [name for name in fields if getattr(self, name) in (None, "")]
        if missing:
            raise ValueError(f"dataset preparation requires provenance fields: {missing}")


class ManifestEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    logical_path: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provenance: Provenance

    @model_validator(mode="after")
    def logical_path_is_portable(self) -> "ManifestEntry":
        logical = PurePosixPath(self.logical_path)
        if logical.is_absolute() or ".." in logical.parts or not logical.parts:
            raise ValueError("logical_path must be a safe relative POSIX path")
        return self


class ScientificManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    experiment_code: Literal["EXPERIMENT_D"] = "EXPERIMENT_D"
    role: Role
    entries: list[ManifestEntry]
    sealed: bool = False
    scientific_identity: str | None = None

    @model_validator(mode="after")
    def validate_role_and_identity(self) -> "ScientificManifest":
        if any(entry.provenance.role != self.role for entry in self.entries):
            raise ValueError("all entries must match the manifest role")
        paths = [entry.logical_path for entry in self.entries]
        if len(paths) != len(set(paths)):
            raise ValueError("manifest logical paths must be unique")
        expected = scientific_identity(self.entries)
        if self.scientific_identity is not None and self.scientific_identity != expected:
            raise ValueError("scientific manifest identity mismatch")
        self.scientific_identity = expected
        return self


def _identity_record(entry: ManifestEntry) -> dict[str, object]:
    p = entry.provenance
    return {
        "logical_path": entry.logical_path,
        "size_bytes": entry.size_bytes,
        "sha256": entry.sha256,
        "role": p.role,
        "class": p.class_name,
        "capture_id": p.capture_id,
        "session_id": p.session_id,
    }


def scientific_identity(entries: list[ManifestEntry]) -> str:
    """Hash portable scientific fields; absolute machine paths never participate."""
    records = [_identity_record(entry) for entry in sorted(entries, key=lambda x: x.logical_path)]
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def entry_from_file(path: Path, logical_path: str, provenance: Provenance) -> ManifestEntry:
    if not path.is_file():
        raise ValueError(f"manifest file does not exist: {path}")
    return ManifestEntry(
        logical_path=logical_path,
        size_bytes=path.stat().st_size,
        sha256=sha256_file(path),
        provenance=provenance,
    )


def load_manifest(path: Path) -> ScientificManifest:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read manifest {path}: {exc}") from exc
    return ScientificManifest.model_validate(raw)


def verify_manifest_files(manifest: ScientificManifest, data_root: Path) -> None:
    """Recheck every manifest entry against its Experiment D-relative artifact."""
    from src.experiment_d.paths import require_under

    role_root = data_root / manifest.role
    for entry in manifest.entries:
        artifact = data_root / entry.logical_path
        require_under(artifact, role_root, f"{manifest.role} artifact")
        if not artifact.is_file():
            raise ValueError(f"manifest artifact does not exist: {entry.logical_path}")
        if artifact.stat().st_size != entry.size_bytes or sha256_file(artifact) != entry.sha256:
            raise ValueError(f"manifest artifact integrity failure: {entry.logical_path}")
