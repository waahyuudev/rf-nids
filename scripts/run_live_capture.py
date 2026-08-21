#!/usr/bin/env python3
"""Run the macOS RF-NIDS near-real-time normal-traffic pipeline."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.common.logging import configure_logging
from src.ingestion.live_capture import PROJECT_ROOT, list_interfaces, run_live_capture


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Capture normal macOS traffic in short PCAP segments")
    value.add_argument("--interface", default=os.getenv("RF_NIDS_CAPTURE_INTERFACE"))
    value.add_argument("--list-interfaces", action="store_true")
    value.add_argument("--segment-seconds", type=float, default=15)
    value.add_argument("--max-segments", type=int, help="Stop after N segments (useful for smoke tests)")
    value.add_argument("--api-url", default=os.getenv("FASTAPI_BASE_URL", "http://localhost:8000"))
    value.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "data/lab/live")
    value.add_argument("--metadata", type=Path, default=PROJECT_ROOT / "models/model_metadata.json")
    value.add_argument("--report", type=Path, default=PROJECT_ROOT / "reports/metrics/live_normal_validation.json")
    value.add_argument("--batch-size", type=int, default=int(os.getenv("INGESTION_BATCH_SIZE", "100")))
    return value


def main() -> int:
    configure_logging(os.getenv("LOG_LEVEL", "INFO"))
    args = parser().parse_args()
    if args.list_interfaces:
        print("\n".join(list_interfaces()))
        return 0
    if not args.interface:
        print("Specify --interface or RF_NIDS_CAPTURE_INTERFACE; use --list-interfaces to discover it")
        return 2
    report = run_live_capture(
        interface=args.interface, segment_seconds=args.segment_seconds,
        api_url=args.api_url, output_dir=args.output_dir, metadata_path=args.metadata,
        report_path=args.report, batch_size=args.batch_size, max_segments=args.max_segments,
    )
    gate = "PASS" if report["status"] == "completed" else "FAIL"
    print(f"LIVE NORMAL PIPELINE: {gate}")
    if gate == "FAIL":
        for failure in report["failures"]:
            print(f"- {failure.get('stage', 'flow')}: {failure['error']}")
    return 0 if gate == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
