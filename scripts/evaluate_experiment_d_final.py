#!/usr/bin/env python3
"""D1 guard-only final evaluation entrypoint; inference is intentionally unavailable."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.common.config import PROJECT_ROOT
from src.experiment_d.integrity import RF_V1_FILES, reject_experiment_c_path
from src.experiment_d.manifest import load_manifest, verify_manifest_files
from src.experiment_d.paths import ExperimentDPaths, require_under
from src.experiment_d.protocol import validate_final_evaluation_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--final-test-manifest", type=Path, required=True)
    parser.add_argument("--rf-v1-model", type=Path, required=True)
    parser.add_argument("--rf-v2-model", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    paths = ExperimentDPaths()
    require_under(args.final_test_manifest, paths.manifest_root("final_test"), "final_test manifest")
    if args.rf_v1_model.resolve(strict=False) not in {p.resolve(strict=False) for p in RF_V1_FILES[:3]}:
        raise ValueError("RF-v1 model must be a frozen RF-v1 artifact")
    require_under(args.rf_v2_model, paths.model_root, "RF-v2 model")
    reject_experiment_c_path(args.final_test_manifest)
    if not args.final_test_manifest.is_file():
        raise ValueError(f"sealed final_test manifest does not exist: {args.final_test_manifest}")
    manifest = load_manifest(args.final_test_manifest)
    validate_final_evaluation_manifest(manifest)
    verify_manifest_files(manifest, paths.data_root)
    identity = manifest.scientific_identity
    if not args.dry_run:
        raise SystemExit("D1 guard: final inference is not implemented; use --dry-run")
    print(json.dumps({"status": "DRY_RUN_VALID", "inference_performed": False,
                      "shared_final_test_identity": identity}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
