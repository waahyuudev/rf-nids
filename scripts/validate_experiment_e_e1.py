#!/usr/bin/env python3
"""Read-only validation of the Experiment E E1 scaffold and preregistration."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.experiment_e.e1 import validate_e1


if __name__ == "__main__":
    print(json.dumps(validate_e1(), sort_keys=True))
