#!/usr/bin/env python3
"""Safely extract one Experiment D PCAP with the pinned CICFlowMeter V3 image."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
from pathlib import Path

from src.common.config import PROJECT_ROOT
from src.experiment_d.config import load_experiment_d_config
from src.experiment_d.integrity import GLOBAL_EXTRACTION_REPORT, require_create_new, sha256_file
from src.experiment_d.paths import ExperimentDPaths


CONFIG = PROJECT_ROOT / "config/experiment_d.yaml"
PLATFORM = "linux/amd64"


def validate_request(role: str, class_dir: str, input_path: Path, output_path: Path, report: Path):
    paths = ExperimentDPaths()
    source = paths.validate_input(input_path, role, class_dir)
    output = paths.validate_output(output_path, role, class_dir)
    report = paths.manifest_root(role).joinpath(report.name).resolve(strict=False) if not report.is_absolute() else report.resolve(strict=False)
    from src.experiment_d.paths import require_under
    require_under(report, paths.manifest_root(role), "extraction report")
    if report == GLOBAL_EXTRACTION_REPORT.resolve(strict=False):
        raise ValueError("global CICFlowMeter extraction report is prohibited")
    if output.suffix.lower() != ".csv":
        raise ValueError("output must be a CSV")
    if source.suffix.lower() not in {".pcap", ".pcapng"}:
        raise ValueError("input must be a PCAP or PCAPNG")
    require_create_new(output)
    require_create_new(report)
    return source, output, report


def csv_shape(path: Path) -> tuple[int, int]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader)
        return len(header), sum(1 for _ in reader)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=("adaptation", "final_test"))
    parser.add_argument("--class", dest="class_dir", required=True, choices=("normal", "ddos", "portscan"))
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    config = load_experiment_d_config(CONFIG)
    source, output, report = validate_request(
        args.role, args.class_dir, args.input, args.output, args.report
    )
    if args.dry_run:
        print(json.dumps({"status": "DRY_RUN_VALID", "input": str(source), "output": str(output), "report": str(report)}))
        return 0
    if not source.is_file():
        raise SystemExit(f"input PCAP does not exist: {source}")
    output.parent.mkdir(parents=True, exist_ok=True)
    inspected = subprocess.run(
        ["docker", "image", "inspect", config.cicflowmeter_v3.image_tag, "--format", "{{.Id}}"],
        text=True, capture_output=True, check=False,
    )
    if inspected.returncode or inspected.stdout.strip() != config.cicflowmeter_v3.image_digest:
        raise RuntimeError("pinned CICFlowMeter V3 Docker image digest is unavailable or mismatched")
    command = [
        "docker", "run", "--rm", "--platform", PLATFORM, "--network", "none",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
        "--tmpfs", "/work:rw,noexec,nosuid,size=64m,uid=10001,gid=10001",
        "--mount", f"type=bind,src={source},dst=/input/{source.name},readonly",
        "--mount", f"type=bind,src={output.parent},dst=/output",
        config.cicflowmeter_v3.image_tag, f"/input/{source.name}", "/output",
    ]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    generated = output.parent / f"{source.name}_ISCX.csv"
    if completed.returncode or not generated.is_file():
        raise RuntimeError(f"CICFlowMeter V3 extraction failed: {completed.stderr[-2000:]}")
    if generated.resolve() != output.resolve():
        raise RuntimeError(f"extractor generated unexpected path: {generated}")
    columns, rows = csv_shape(output)
    report.parent.mkdir(parents=True, exist_ok=True)
    require_create_new(report)
    payload = {
        "experiment_code": config.experiment_code, "role": args.role, "class": args.class_dir,
        "input_logical_path": str(source.relative_to(ExperimentDPaths().data_root)),
        "input_sha256": sha256_file(source), "output_logical_path": str(output.relative_to(ExperimentDPaths().data_root)),
        "output_sha256": sha256_file(output), "row_count": rows, "raw_column_count": columns,
        "extractor": {"repository": config.cicflowmeter_v3.repository, "commit": config.cicflowmeter_v3.commit,
                      "source_archive_sha256": config.cicflowmeter_v3.source_archive_sha256,
                      "image_tag": config.cicflowmeter_v3.image_tag,
                      "image_digest": inspected.stdout.strip()},
        "adapter": config.adapter.model_dump(), "network_access": False,
    }
    report.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
