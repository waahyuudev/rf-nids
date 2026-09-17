"""Fail-closed registry of provenance-qualified runtime extractors."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from src.common.hashing import sha256_file
from src.ingestion.cicflowmeter_v3_adapter import (
    ADAPTER_IDENTITY,
    ADAPTER_VERSION,
    CICFLOWMETER_V3_COMMIT,
    CROSSWALK_SHA256,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
HISTORICAL_IMAGE_DIGEST = (
    "sha256:0227c7280e586d54144b9bb11b2a6b5d4b1c4ba9bc7c44199fa312a6b829caab"
)
APPROVED_CANDIDATE_IMAGE_DIGEST = (
    "sha256:b12b3a4a4218968aba2436685a4eb113473e5681de70705409e834e4613a879b"
)
RUNTIME_DEFAULT_IMAGE_DIGEST = APPROVED_CANDIDATE_IMAGE_DIGEST


class RuntimeExtractorVerificationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ApprovedRuntimeExtractor:
    image_digest: str
    source_commit: str
    adapter_identity: str
    adapter_version: str
    crosswalk_sha256: str
    equivalence_verdict: str
    evidence_path: Path
    evidence_sha256: str
    evidence_kind: str


APPROVED_RUNTIME_EXTRACTORS = (
    ApprovedRuntimeExtractor(
        HISTORICAL_IMAGE_DIGEST,
        CICFLOWMETER_V3_COMMIT,
        ADAPTER_IDENTITY,
        ADAPTER_VERSION,
        CROSSWALK_SHA256,
        "HISTORICAL_FROZEN_PROVENANCE",
        PROJECT_ROOT / "config/experiment_d.yaml",
        "e127fcdaf86a9e8934db89c04318f3eece8695c40a1ab7518d1af593dd3a51d6",
        "historical",
    ),
    ApprovedRuntimeExtractor(
        APPROVED_CANDIDATE_IMAGE_DIGEST,
        CICFLOWMETER_V3_COMMIT,
        ADAPTER_IDENTITY,
        ADAPTER_VERSION,
        CROSSWALK_SHA256,
        "BYTE_IDENTICAL_ON_NINE_NON_FINAL_EXPERIMENT_D_ADAPTATION_REFERENCE_PCAPS",
        PROJECT_ROOT / "reports/experiment_e/audit/e3_provenance_amendment_a1.json",
        "5267b0195b0ebded335df8f306e3abecef2b2b369bd5934e553dc9cba8b913a5",
        "approved_replacement",
    ),
)


class RuntimeExtractorRegistry:
    """Resolve only complete, repository-backed extractor identities."""

    def __init__(self, approved=APPROVED_RUNTIME_EXTRACTORS):
        self._approved = {item.image_digest: item for item in approved}

    def verify(
        self, image_digest: str, *, source_commit: str,
        adapter_identity: str = ADAPTER_IDENTITY,
        adapter_version: str = ADAPTER_VERSION,
        crosswalk_sha256: str = CROSSWALK_SHA256,
    ) -> ApprovedRuntimeExtractor:
        approved = self._approved.get(image_digest)
        if approved is None:
            raise RuntimeExtractorVerificationError(
                f"extractor image identity is not approved: {image_digest or '(empty)'}"
            )
        supplied = (source_commit, adapter_identity, adapter_version, crosswalk_sha256)
        expected = (
            approved.source_commit, approved.adapter_identity,
            approved.adapter_version, approved.crosswalk_sha256,
        )
        if supplied != expected:
            raise RuntimeExtractorVerificationError(
                "extractor source commit or compatibility identity mismatch"
            )
        self._verify_repository_evidence(approved)
        return approved

    @staticmethod
    def _verify_repository_evidence(approved: ApprovedRuntimeExtractor) -> None:
        crosswalk = PROJECT_ROOT / "reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv"
        if not crosswalk.is_file() or sha256_file(crosswalk) != approved.crosswalk_sha256:
            raise RuntimeExtractorVerificationError("extractor crosswalk evidence mismatch")
        if (
            not approved.evidence_path.is_file()
            or sha256_file(approved.evidence_path) != approved.evidence_sha256
        ):
            raise RuntimeExtractorVerificationError("extractor provenance evidence mismatch")
        if approved.evidence_kind == "approved_replacement":
            evidence = json.loads(approved.evidence_path.read_text(encoding="utf-8"))
            replacement = evidence.get("approved_replacement", {})
            gate = evidence.get("compatibility_gate", {})
            if (
                evidence.get("status") != "APPROVED"
                or not evidence.get("e3_extraction_authorized")
                or replacement.get("image_digest") != approved.image_digest
                or gate.get("verdict") != approved.equivalence_verdict
            ):
                raise RuntimeExtractorVerificationError(
                    "extractor approval/equivalence evidence is invalid"
                )
