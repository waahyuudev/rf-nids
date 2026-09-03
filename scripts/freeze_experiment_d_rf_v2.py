#!/usr/bin/env python3
"""Create the immutable Experiment D RF-v2 freeze manifest; performs no inference."""

from pathlib import Path

from src.common.config import PROJECT_ROOT
from src.experiment_d.d5 import freeze_rf_v2


if __name__ == "__main__":
    freeze_rf_v2(PROJECT_ROOT, PROJECT_ROOT / "reports/experiment_d/audit/rf_v2_frozen_manifest.json")
    print("RF_V2_FROZEN")
