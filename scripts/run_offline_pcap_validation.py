#!/usr/bin/env python3
"""Run and report the RF-NIDS offline PCAP end-to-end validation."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.common.logging import configure_logging
from src.ingestion.offline_validation import (
    PROJECT_ROOT,
    extract_with_docker,
    new_report,
    validate_flow_csv,
    write_report,
)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--pcap", type=Path, required=True)
    value.add_argument("--api-url", default="http://localhost:8000")
    value.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "reports/metrics/offline_pcap_validation.json",
    )
    value.add_argument("--flow-csv", type=Path, help="Use an already extracted CSV")
    value.add_argument("--batch-size", type=int, default=100)
    value.add_argument("--timeout", type=float, default=10)
    return value


def main() -> int:
    configure_logging(os.getenv("LOG_LEVEL", "INFO"))
    args = parser().parse_args()
    pcap = args.pcap.resolve()
    output = args.output.resolve()
    try:
        csv_path = args.flow_csv.resolve() if args.flow_csv else (
            PROJECT_ROOT / "data/lab/flows" / f"{pcap.stem}.csv"
        )
        if not args.flow_csv:
            extract_with_docker(pcap, csv_path)
        report = validate_flow_csv(
            pcap=pcap,
            csv_path=csv_path,
            api_url=args.api_url,
            metadata_path=PROJECT_ROOT / "models/model_metadata.json",
            output=output,
            batch_size=args.batch_size,
            timeout_seconds=args.timeout,
        )
    except Exception as exc:
        logging.getLogger(__name__).error("Extraction failed: %s", exc)
        report = new_report(pcap)
        report["failures"].append({"stage": "extraction", "error": str(exc)})
        write_report(report, output)
    print(f"Report: {output}")
    print(f"Status: {report['status']}")
    print(f"Flows: {report['flows']}")
    print(f"Predictions: {report['predictions']}")
    return 0 if report["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
