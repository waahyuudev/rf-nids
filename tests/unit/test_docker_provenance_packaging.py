"""Build-context contract for immutable runtime extractor evidence."""

from pathlib import Path

from src.common.hashing import sha256_file


ROOT = Path(__file__).resolve().parents[2]
REQUIRED_EVIDENCE = {
    "reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv":
        "66e517cdcea217f19de4d0a2cd45302ede999388393f539fb8ca4a2c68b74cf4",
    "reports/experiment_e/audit/e3_provenance_amendment_a1.json":
        "5267b0195b0ebded335df8f306e3abecef2b2b369bd5934e553dc9cba8b913a5",
}


def test_api_image_packages_exact_verified_extractor_evidence() -> None:
    dockerfile_text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    dockerfile = dockerfile_text.splitlines()
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

    for relative_path, expected_sha256 in REQUIRED_EVIDENCE.items():
        source = ROOT / relative_path
        assert source.is_file()
        assert sha256_file(source) == expected_sha256
        assert f"COPY {relative_path} ./{relative_path}" in dockerfile
        assert f"!{relative_path}" in dockerignore
        assert f"{expected_sha256}  {relative_path}" in dockerfile_text
