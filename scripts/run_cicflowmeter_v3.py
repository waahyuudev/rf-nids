#!/usr/bin/env python3
"""Extract raw PCAP flows with pinned official CICFlowMeter V3 only."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PCAP_ROOT = (ROOT / "data" / "lab" / "pcap").resolve()
OUTPUT_ROOT = (ROOT / "data" / "lab" / "flows" / "cicflowmeter-v3").resolve()
REPORT = ROOT / "reports" / "metrics" / "cicflowmeter_v3_extraction.json"
BUILD_REPORT = ROOT / "reports" / "metrics" / "cicflowmeter_v3_build.json"
IMAGE = "rf-nids-cicflowmeter-v3:a26aae27"
PLATFORM = "linux/amd64"
DEFAULT_PCAPS = ["normal-http-test.pcap", "portscan-test.pcap"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_csv(path: Path) -> tuple[int | None, int | None, str | None]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle)
            header = next(reader)
            rows = sum(1 for _ in reader)
        return len(header), rows, None
    except Exception as exc:
        return None, None, f"{type(exc).__name__}: {exc}"


def packet_accounting(text: str) -> dict[str, int] | None:
    matches = {
        "total": re.search(r"Total packets:\s*(\d+)", text),
        "valid": re.search(r"Valid packets:\s*(\d+)", text),
        "ignored": re.search(r"Ignored packets:\s*(\d+)", text),
    }
    if not all(matches.values()):
        return None
    return {name: int(match.group(1)) for name, match in matches.items() if match}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcaps", nargs="*", default=DEFAULT_PCAPS)
    parser.add_argument("--image", default=IMAGE)
    args = parser.parse_args()
    if REPORT.exists():
        raise SystemExit(f"refusing to overwrite existing report: {REPORT}")
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, object]] = []
    for supplied in args.pcaps:
        candidate = Path(supplied)
        input_path = (candidate if candidate.is_absolute() else PCAP_ROOT / candidate).resolve()
        try:
            relative = input_path.relative_to(PCAP_ROOT)
        except ValueError:
            raise SystemExit(f"refusing input outside {PCAP_ROOT}: {input_path}")
        if input_path.parent != PCAP_ROOT or not input_path.is_file():
            raise SystemExit(f"input must be an existing PCAP directly under {PCAP_ROOT}: {input_path}")

        output_path = OUTPUT_ROOT / f"{input_path.name}_ISCX.csv"
        if output_path.exists():
            raise SystemExit(f"refusing to overwrite raw V3 output: {output_path}")

        command = [
            "docker", "run", "--rm", "--platform", PLATFORM,
            "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--read-only",
            "--tmpfs", "/work:rw,noexec,nosuid,size=64m,uid=10001,gid=10001",
            "--mount", f"type=bind,src={input_path},dst=/input/{relative.name},readonly",
            "--mount", f"type=bind,src={OUTPUT_ROOT},dst=/output",
            args.image, f"/input/{relative.name}", "/output",
        ]
        started = time.monotonic()
        process = subprocess.run(command, text=True, capture_output=True, check=False)
        runtime = time.monotonic() - started
        exists = output_path.is_file()
        columns, rows, csv_error = inspect_csv(output_path) if exists else (None, None, None)
        combined = process.stdout + "\n" + process.stderr
        results.append({
            "input_path": str(input_path.relative_to(ROOT)),
            "input_sha256": sha256(input_path),
            "output_path": str(output_path.relative_to(ROOT)),
            "output_sha256": sha256(output_path) if exists else None,
            "generated_filename": output_path.name if exists else None,
            "row_flow_count": rows,
            "output_column_count": columns,
            "packet_accounting": packet_accounting(combined),
            "exit_code": process.returncode,
            "runtime_seconds": round(runtime, 3),
            "stdout": process.stdout,
            "stderr": process.stderr,
            "parser_warnings_errors": [line for line in combined.splitlines() if re.search(r"warn|error|exception", line, re.I)],
            "csv_inspection_error": csv_error,
            "success": process.returncode == 0 and exists and columns is not None,
        })
        if not results[-1]["success"]:
            break

    inspected = subprocess.run(
        ["docker", "image", "inspect", args.image, "--format", "{{.Id}}"],
        text=True, capture_output=True, check=False,
    )
    success = len(results) == len(args.pcaps) and all(bool(item["success"]) for item in results)
    report = {
        "status": "success" if success else "failure",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": PLATFORM,
        "image": {"tag": args.image, "id": inspected.stdout.strip() or None},
        "build_report": str(BUILD_REPORT.relative_to(ROOT)),
        "jni_load_success": success,
        "cli_success": success,
        "offline_pcap_reading_success": success,
        "extractions": results,
        "flow_count_comparison": {
            "normal-http-test": {"hieulw": 32, "v4_candidate": 61, "v3": next((x["row_flow_count"] for x in results if str(x["input_path"]).endswith("normal-http-test.pcap")), None)},
            "portscan-test": {"hieulw": 1000, "v4_candidate": 1000, "v3": next((x["row_flow_count"] for x in results if str(x["input_path"]).endswith("portscan-test.pcap")), None)},
        },
        "raw_output_policy": "Raw V3 CSV bytes are preserved unchanged and existing outputs are never overwritten.",
        "scientific_warning": "Extraction feasibility is not 78-feature compatibility. No feature adaptation, model inference, or retraining was performed.",
        "inference_run": False,
        "next_required_phase": "V3_78_FEATURE_COMPATIBILITY_VALIDATION",
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if BUILD_REPORT.is_file():
        build = json.loads(BUILD_REPORT.read_text(encoding="utf-8"))
        build["jni_load_success"] = success
        build["cli_success"] = success
        build["offline_pcap_reading_success"] = success
        build["runtime_evidence"] = str(REPORT.relative_to(ROOT))
        BUILD_REPORT.write_text(json.dumps(build, indent=2) + "\n", encoding="utf-8")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
