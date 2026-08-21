"""CLI orchestration for strict flow adaptation and API delivery."""

from __future__ import annotations

import argparse
import logging
import os
import time
from pathlib import Path

from src.common.logging import configure_logging

from .api_sender import ApiSendError, ApiSender
from .capture import CICFlowMeterCapture, CaptureError
from .cicflowmeter_mapping import (
    COMPATIBILITY_POLICIES,
    DEFAULT_COMPATIBILITY_POLICY,
)
from .feature_adapter import FeatureAdapter, FeatureCompatibilityError
from .flow_extractor import FlowCsvExtractor

logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Send compatible network flows to RF-NIDS API")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", type=Path)
    source.add_argument("--interface")
    source.add_argument("--flow-csv", type=Path, help="Existing CICFlowMeter-compatible CSV")
    parser.add_argument("--api-url", default=os.getenv("FASTAPI_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--metadata", type=Path, default=PROJECT_ROOT / "models/model_metadata.json")
    parser.add_argument("--extractor", default=os.getenv("CICFLOWMETER_EXECUTABLE", "cicflowmeter"))
    parser.add_argument("--batch-size", type=int, default=int(os.getenv("INGESTION_BATCH_SIZE", "100")))
    parser.add_argument("--flush-seconds", type=float, default=float(os.getenv("INGESTION_FLUSH_SECONDS", "2")))
    parser.add_argument(
        "--compatibility-policy",
        choices=COMPATIBILITY_POLICIES,
        default=os.getenv(
            "LIVE_FEATURE_COMPATIBILITY_POLICY",
            DEFAULT_COMPATIBILITY_POLICY,
        ),
    )
    return parser


def run(args: argparse.Namespace) -> dict[str, int]:
    if args.batch_size < 1 or args.flush_seconds <= 0:
        raise ValueError("batch-size and flush-seconds must be positive")
    capture = CICFlowMeterCapture(args.extractor)
    if args.pcap:
        csv_path = capture.from_pcap(args.pcap)
    elif args.interface:
        logger.info("Capturing interface=%s; press Ctrl+C for clean shutdown", args.interface)
        csv_path = capture.from_interface(args.interface)
    else:
        csv_path = args.flow_csv

    extractor = FlowCsvExtractor()
    adapter = FeatureAdapter.from_metadata(
        args.metadata,
        compatibility_policy=args.compatibility_policy,
    )
    logger.warning(
        "Live feature compatibility policy=%s; reproduced dataset artifacts are not "
        "independent network measurements",
        args.compatibility_policy,
    )
    report = adapter.compatibility(extractor.field_names(csv_path))
    if not report["compatible"]:
        raise FeatureCompatibilityError(
            f"Extractor schema incompatible; missing={report['missing_fields']} "
            f"duplicates={report['duplicate_fields']}"
        )
    sender = ApiSender(
        args.api_url,
        max_retries=int(os.getenv("INGESTION_MAX_RETRIES", "3")),
        retry_delay_seconds=float(os.getenv("INGESTION_RETRY_DELAY_SECONDS", "2")),
    )
    batch = []
    seen: set[str] = set()
    stats = {"captured": 0, "accepted": 0, "rejected": 0, "duplicates": 0, "sent": 0}
    last_flush = time.monotonic()
    for extracted in extractor.read(csv_path):
        stats["captured"] += 1
        try:
            adapted = adapter.adapt(extracted)
        except FeatureCompatibilityError as exc:
            stats["rejected"] += 1
            logger.warning("Flow rejected: %s", exc)
            continue
        if adapted.fingerprint in seen:
            stats["duplicates"] += 1
            continue
        seen.add(adapted.fingerprint or "")
        stats["accepted"] += 1
        batch.append(adapted)
        if len(batch) >= args.batch_size or time.monotonic() - last_flush >= args.flush_seconds:
            stats["sent"] += len(sender.send(batch))
            batch.clear()
            last_flush = time.monotonic()
    if batch:
        stats["sent"] += len(sender.send(batch))
    logger.info("Ingestion complete %s", stats)
    return stats


def main() -> int:
    configure_logging(os.getenv("LOG_LEVEL", "INFO"))
    try:
        run(build_parser().parse_args())
    except KeyboardInterrupt:
        logger.info("Capture stopped by user")
        return 130
    except (CaptureError, FeatureCompatibilityError, ApiSendError, OSError, ValueError) as exc:
        logger.error("Ingestion stopped: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
