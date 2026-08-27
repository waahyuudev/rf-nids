#!/usr/bin/env python3
"""Review and dry-run the Experiment C V3 adapter without model inference."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ingestion.cicflowmeter_v3_adapter import (  # noqa: E402
    ADAPTER_IDENTITY,
    ADAPTER_VERSION,
    ARTIFACT_FIELDS,
    CICFLOWMETER_V3_COMMIT,
    CICFLOWMETER_V3_IMAGE_DIGEST,
    CROSSWALK_PATH,
    CROSSWALK_SHA256,
    MAPPING_RULES,
    CICFlowMeterV3ModelAdapter,
    sha256_file,
)

NORMAL = ROOT / "data/lab/flows/cicflowmeter-v3/normal-http-test.pcap_ISCX.csv"
PORTSCAN = ROOT / "data/lab/flows/cicflowmeter-v3/portscan-test.pcap_ISCX.csv"
REVIEW_OUT = ROOT / "reports/tables/cicflowmeter_v3_adapter_mapping_review.csv"
VALIDATION_OUT = ROOT / "reports/metrics/cicflowmeter_v3_adapter_validation.json"
TEST_FILE = ROOT / "tests/unit/test_cicflowmeter_v3_adapter.py"


def review_mapping() -> tuple[list[dict[str, object]], str]:
    crosswalk_file = ROOT / CROSSWALK_PATH
    source_hash_ok = sha256_file(crosswalk_file) == CROSSWALK_SHA256
    crosswalk = pd.read_csv(crosswalk_file)
    rules = list(MAPPING_RULES)
    rows: list[dict[str, object]] = []
    for index in range(max(len(crosswalk), len(rules))):
        expected = crosswalk.iloc[index] if index < len(crosswalk) else None
        actual = rules[index] if index < len(rules) else (None, None, None)
        checks = {
            "model_feature_match": expected is not None and expected.model_feature == actual[0],
            "v3_raw_header_match": expected is not None and expected.v3_raw_header == actual[1],
            "compatibility_status_match": expected is not None and expected.compatibility_status == actual[2],
            "model_index_match": expected is not None and int(expected.model_feature_index) == index,
        }
        rows.append(
            {
                "model_feature_index": index,
                "expected_model_feature": None if expected is None else expected.model_feature,
                "implemented_model_feature": actual[0],
                "expected_v3_raw_header": None if expected is None else expected.v3_raw_header,
                "implemented_v3_raw_header": actual[1],
                "expected_compatibility_status": None if expected is None else expected.compatibility_status,
                "implemented_compatibility_status": actual[2],
                **checks,
                "review_status": "PASS" if all(checks.values()) else "FAIL",
            }
        )
    passed = source_hash_ok and len(crosswalk) == len(rules) == 78 and all(
        row["review_status"] == "PASS" for row in rows
    )
    return rows, "ADAPTER_REVIEW_PASS" if passed else "ADAPTER_REVIEW_FAIL"


def run_tests() -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", str(TEST_FILE), "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    output = (completed.stdout + completed.stderr).strip()
    passed = 0
    failed = 0
    for token in output.replace(",", "").split():
        if token.isdigit():
            continue
    import re

    passed_match = re.search(r"(\d+) passed", output)
    failed_match = re.search(r"(\d+) failed", output)
    if passed_match:
        passed = int(passed_match.group(1))
    if failed_match:
        failed = int(failed_match.group(1))
    return {"passed": passed, "failed": failed, "exit_code": completed.returncode, "output": output}


def main() -> int:
    adapter = CICFlowMeterV3ModelAdapter.from_metadata(ROOT / "models/model_metadata.json")
    dry_runs = {}
    for name, path in (("normal", NORMAL), ("portscan", PORTSCAN)):
        result = adapter.adapt_csv(path)
        dry_runs[name] = {
            "raw_input_path": str(path.relative_to(ROOT)),
            "raw_input_sha256": result.provenance["raw_input_sha256"],
            "raw_rows": result.provenance["raw_row_count"],
            "output_rows": result.provenance["output_row_count"],
            "output_feature_count": result.provenance["output_feature_count"],
            "non_finite_before": result.provenance["non_finite_before"],
            "non_finite_after": result.provenance["non_finite_after"],
            "schema_validation": result.provenance["schema_validation"],
        }

    review_rows, review_result = review_mapping()
    REVIEW_OUT.parent.mkdir(parents=True, exist_ok=True)
    with REVIEW_OUT.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(review_rows[0]))
        writer.writeheader()
        writer.writerows(review_rows)

    tests = run_tests()
    overall = review_result == "ADAPTER_REVIEW_PASS" and tests["exit_code"] == 0
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "adapter_identity": ADAPTER_IDENTITY,
        "adapter_version": ADAPTER_VERSION,
        "cicflowmeter_v3_commit": CICFLOWMETER_V3_COMMIT,
        "cicflowmeter_v3_image_digest": CICFLOWMETER_V3_IMAGE_DIGEST,
        "crosswalk_path": CROSSWALK_PATH,
        "crosswalk_sha256": CROSSWALK_SHA256,
        "mapping_review_path": str(REVIEW_OUT.relative_to(ROOT)),
        "mapping_review_result": review_result,
        "mapping_review_rows": len(review_rows),
        "artifact_reproduction_fields": list(ARTIFACT_FIELDS),
        "dry_runs": dry_runs,
        "tests": tests,
        "model_inference_performed": False,
        "model_retraining_performed": False,
        "validation_status": "PASS" if overall else "FAIL",
    }
    VALIDATION_OUT.parent.mkdir(parents=True, exist_ok=True)
    VALIDATION_OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())

