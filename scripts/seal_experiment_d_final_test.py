#!/usr/bin/env python3
"""Verify and seal an Experiment D final-test manifest using create-new semantics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.common.config import PROJECT_ROOT
from src.experiment_d.integrity import require_create_new
from src.experiment_d.manifest import ScientificManifest, load_manifest, verify_manifest_files
from src.experiment_d.paths import ExperimentDPaths, require_under
from src.experiment_d.split import validate_dataset_ready


def seal_manifest(
    source: Path, output: Path, paths: ExperimentDPaths | None = None
) -> ScientificManifest:
    paths = paths or ExperimentDPaths()
    require_under(source, paths.manifest_root("final_test"), "final_test manifest")
    require_under(output, paths.manifest_root("final_test"), "sealed final_test manifest")
    require_create_new(output)
    manifest = load_manifest(source)
    if manifest.role != "final_test" or manifest.sealed:
        raise ValueError("only an unsealed final_test manifest may be sealed")
    validate_dataset_ready(manifest)
    verify_manifest_files(manifest, paths.data_root)
    sealed = manifest.model_copy(update={"sealed": True})
    # Revalidate after update so identity and role invariants remain enforced.
    sealed = ScientificManifest.model_validate(sealed.model_dump(by_alias=True))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(sealed.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return sealed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    seal_manifest(args.manifest, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
