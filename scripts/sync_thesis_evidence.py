#!/usr/bin/env python3
"""Synchronize allowlisted thesis evidence into the application database."""

from __future__ import annotations

import argparse
import json

from sqlalchemy.orm import Session

from src.api.database import build_engine
from src.application.evidence_sync import EvidenceSyncError, synchronize_evidence
from src.common.config import Settings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--experiment",
        choices=("A", "B", "C", "all"),
        default="all",
        help="Evidence group to synchronize (dataset/model evidence is always validated).",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    engine = build_engine(Settings.from_env().database_url)
    try:
        with Session(engine) as db:
            result = synchronize_evidence(
                db, experiments=args.experiment, dry_run=args.dry_run
            )
        print(json.dumps(result.as_dict(), indent=2 if args.verbose else None))
    except EvidenceSyncError as exc:
        parser.error(str(exc))
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
