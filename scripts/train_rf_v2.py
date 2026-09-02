#!/usr/bin/env python3
"""D1 guard-only RF-v2 entrypoint; model fitting is intentionally unavailable."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.common.config import PROJECT_ROOT
from src.experiment_d.integrity import reject_experiment_c_path, require_create_new
from src.experiment_d.manifest import load_manifest
from src.experiment_d.paths import ExperimentDPaths, require_under
from src.experiment_d.protocol import validate_training_request


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adaptation-manifest", type=Path, required=True)
    parser.add_argument("--output-model", type=Path, required=True)
    parser.add_argument("--output-metadata", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    paths = ExperimentDPaths()
    require_under(args.adaptation_manifest, paths.manifest_root("adaptation"), "adaptation manifest")
    reject_experiment_c_path(args.adaptation_manifest)
    for output in (args.output_model, args.output_metadata):
        require_create_new(output)
    if not args.adaptation_manifest.is_file():
        raise ValueError(f"adaptation manifest does not exist: {args.adaptation_manifest}")
    validate_training_request(
        load_manifest(args.adaptation_manifest), args.output_model, args.output_metadata
    )
    if not args.dry_run:
        raise SystemExit("D1 guard: RF-v2 training is not implemented; use --dry-run")
    print(json.dumps({"status": "DRY_RUN_VALID", "training_performed": False, "seed": args.seed}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
