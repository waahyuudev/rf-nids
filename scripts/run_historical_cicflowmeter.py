#!/usr/bin/env python3
"""Run raw offline Java CICFlowMeter extraction without adapting its CSV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PCAP_ROOT = (ROOT / "data" / "lab" / "pcap").resolve()
OUTPUT_ROOT = (ROOT / "data" / "lab" / "flows" / "historical").resolve()
REPORT = ROOT / "reports" / "metrics" / "historical_cicflowmeter_extraction.json"
BUILD_REPORT = ROOT / "reports" / "metrics" / "historical_cicflowmeter_build.json"
IMAGE = "rf-nids-historical-cicflowmeter:98a5ebad"
PLATFORM = "linux/amd64"
DEFAULT_PCAPS = ["normal-http-test.pcap", "portscan-test.pcap"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def contained(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def inspect_csv(path: Path) -> tuple[int | None, int | None, str | None]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = csv.reader(handle)
            header = next(rows)
            count = sum(1 for _ in rows)
        return len(header), count, None
    except Exception as exc:  # raw file is never rewritten on inspection failure
        return None, None, f"{type(exc).__name__}: {exc}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcaps", nargs="*", default=DEFAULT_PCAPS)
    parser.add_argument("--image", default=IMAGE)
    args = parser.parse_args()
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    results = []
    previous_results: list[dict[str, object]] = []
    if REPORT.is_file():
        try:
            previous_results = json.loads(REPORT.read_text(encoding="utf-8")).get(
                "extractions", []
            )
        except (json.JSONDecodeError, OSError, AttributeError):
            previous_results = []

    for supplied in args.pcaps:
        candidate = Path(supplied)
        input_path = (candidate if candidate.is_absolute() else PCAP_ROOT / candidate).resolve()
        if not contained(input_path, PCAP_ROOT) or input_path.parent != PCAP_ROOT:
            raise SystemExit(f"refusing input outside {PCAP_ROOT}: {input_path}")
        if not input_path.is_file():
            raise SystemExit(f"PCAP does not exist: {input_path}")

        output_path = OUTPUT_ROOT / f"{input_path.name}_Flow.csv"
        if output_path.exists():
            raise SystemExit(
                f"refusing to overwrite raw historical output: {output_path}; move it explicitly first"
            )

        command = [
            "docker",
            "run",
            "--rm",
            "--platform",
            PLATFORM,
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
            "--tmpfs",
            "/work:rw,noexec,nosuid,size=64m,uid=10001,gid=10001",
            "--mount",
            f"type=bind,src={PCAP_ROOT},dst=/input,readonly",
            "--mount",
            f"type=bind,src={OUTPUT_ROOT},dst=/output",
            args.image,
            f"/input/{input_path.name}",
            "/output",
        ]
        started = time.monotonic()
        process = subprocess.run(command, text=True, capture_output=True, check=False)
        runtime = time.monotonic() - started
        exists = output_path.is_file()
        columns, rows, csv_error = inspect_csv(output_path) if exists else (None, None, None)
        success = process.returncode == 0 and exists and columns is not None
        results.append(
            {
                "input_path": str(input_path.relative_to(ROOT)),
                "input_sha256": sha256(input_path),
                "output_path": str(output_path.relative_to(ROOT)),
                "output_sha256": sha256(output_path) if exists else None,
                "output_column_count": columns,
                "row_flow_count": rows,
                "exit_status": process.returncode,
                "runtime_seconds": round(runtime, 3),
                "stdout": process.stdout,
                "stderr_summary": process.stderr[-4000:],
                "csv_inspection_error": csv_error,
                "success": success,
            }
        )

    image = subprocess.run(
        ["docker", "image", "inspect", args.image, "--format", "{{.Id}}"],
        text=True,
        capture_output=True,
        check=False,
    )
    merged = {str(item["input_path"]): item for item in previous_results}
    merged.update({str(item["input_path"]): item for item in results})
    all_results = list(merged.values())
    report = {
        "status": "success" if all(item["success"] for item in all_results) else "failure",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": PLATFORM,
        "image": {"tag": args.image, "id": image.stdout.strip() or None},
        "build_report": str(BUILD_REPORT.relative_to(ROOT)),
        "jni_load_success": all(item["success"] for item in all_results),
        "extractions": all_results,
        "validation_warning": "Successful extraction proves runtime/JNI feasibility only. It does not establish semantic compatibility with CICIDS2017 and no model inference or feature adaptation was performed.",
        "raw_output_policy": "Generated Java CSV bytes are preserved without normalization or transformation and existing files are never overwritten.",
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["jni_load_success"] and BUILD_REPORT.is_file():
        build_data = json.loads(BUILD_REPORT.read_text(encoding="utf-8"))
        build_data.setdefault("jni", {})["offline_load_success"] = True
        build_data["jni"]["offline_load_evidence"] = str(REPORT.relative_to(ROOT))
        BUILD_REPORT.write_text(json.dumps(build_data, indent=2) + "\n", encoding="utf-8")

    print("Extraction")
    print("----------")
    by_name = {Path(str(item["input_path"])).name: item for item in all_results}
    for name in DEFAULT_PCAPS:
        item = by_name.get(name)
        if item is None:
            summary = "NOT RUN"
        elif item["success"]:
            summary = f"SUCCESS ({item['row_flow_count']} flows, {item['runtime_seconds']}s)"
        else:
            summary = f"FAILURE (exit {item['exit_status']})"
        print(f"{name}: {summary}")
    return 0 if all(item["success"] for item in all_results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
