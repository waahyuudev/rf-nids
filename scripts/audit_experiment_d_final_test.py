#!/usr/bin/env python3
"""Run the D5 cross-role leakage audit without loading models or predicting."""

import json
from datetime import datetime, timezone
from pathlib import Path

from scripts.verify_experiment_d_frozen_baseline import build_manifest as frozen_baseline
from src.common.config import PROJECT_ROOT as ROOT
from src.experiment_d.d5 import verify_frozen_manifest
from src.experiment_d.integrity import require_create_new
from src.experiment_d.manifest import load_manifest


def main() -> int:
    output = ROOT / "reports/experiment_d/audit/final_test_leakage_audit.json"
    require_create_new(output)
    final = load_manifest(ROOT / "data/lab/experiment_d/final_test/manifests/labeled_flow_manifest.json")
    capture = json.loads((ROOT / "data/lab/experiment_d/final_test/manifests/capture_manifest.json").read_text())
    adapt_capture = json.loads((ROOT / "data/lab/experiment_d/adaptation/manifests/capture_manifest.json").read_text())
    adapt_flow = json.loads((ROOT / "data/lab/experiment_d/adaptation/manifests/labeled_flow_manifest.json").read_text())
    freeze = verify_frozen_manifest(ROOT / "reports/experiment_d/audit/rf_v2_frozen_manifest.json", ROOT / "models/experiment_d/random_forest_rf_v2.joblib")
    final_hashes = {x.sha256 for x in final.entries}
    experiment_c_hashes = {x["sha256"] for x in frozen_baseline()["entries"]}
    adaptation_hashes = {x["sha256"] for x in adapt_capture["captures"]} | {x["raw_flow_sha256"] for x in adapt_flow["entries"]}
    adaptation_ids = {x["capture_id"] for x in adapt_capture["captures"]} | {x["session_id"] for x in adapt_capture["captures"]}
    final_ids = {x["capture_id"] for x in capture["sessions"]} | {x["session_id"] for x in capture["sessions"]}
    training_text = (ROOT / "models/experiment_d/training_manifest.json").read_text()
    checks = {
        "no_experiment_c_content_hash_overlap": not bool(final_hashes & experiment_c_hashes),
        "no_adaptation_content_hash_overlap": not bool(final_hashes & adaptation_hashes),
        "no_adaptation_identity_overlap": not bool(adaptation_ids & final_ids),
        "no_final_test_path_in_training_manifest": not any(x.logical_path in training_text for x in final.entries),
        "rf_v2_frozen_hash_unchanged": freeze["model_sha256"] == "fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31",
        "model_artifacts_predate_freeze": all(datetime.fromtimestamp((ROOT/p).stat().st_mtime, timezone.utc) <= datetime.fromisoformat(freeze["frozen_at"]) for p in ("models/experiment_d/random_forest_rf_v2.joblib", "models/experiment_d/random_forest_rf_v2_metadata.json", "models/experiment_d/training_manifest.json")),
        "no_prediction_or_metrics_outputs_exist": not any((ROOT / "reports/experiment_d/final_test").glob("*prediction*")) and not any((ROOT / "reports/experiment_d/final_test").glob("*metrics*")),
    }
    if not all(checks.values()): raise ValueError(f"leakage audit failed: {checks}")
    payload = {"schema":"experiment_d_final_test_leakage_audit", "status":"PASS", "checks":checks,
               "final_test_manifest_identity":final.scientific_identity, "rf_v2_frozen_identity":freeze["frozen_identity"],
               "audited_at":datetime.now(timezone.utc).isoformat()}
    output.write_text(json.dumps(payload, indent=2, sort_keys=True)+"\n")
    print("FINAL_TEST_LEAKAGE_AUDIT_PASS")
    return 0


if __name__ == "__main__": raise SystemExit(main())
