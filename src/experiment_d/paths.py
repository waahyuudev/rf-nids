"""Central Experiment D paths and containment checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.common.config import PROJECT_ROOT


ROLES = ("adaptation", "final_test")
CLASS_DIRS = ("normal", "ddos", "portscan")


def contained(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def require_under(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve(strict=False)
    if not contained(resolved, root):
        raise ValueError(f"{label} must be under {root}")
    return resolved


@dataclass(frozen=True)
class ExperimentDPaths:
    root: Path = PROJECT_ROOT

    @property
    def data_root(self) -> Path:
        return self.root / "data/lab/experiment_d"

    @property
    def model_root(self) -> Path:
        return self.root / "models/experiment_d"

    @property
    def report_root(self) -> Path:
        return self.root / "reports/experiment_d"

    def role_root(self, role: str) -> Path:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        return self.data_root / role

    def pcap_root(self, role: str, class_dir: str) -> Path:
        if class_dir not in CLASS_DIRS:
            raise ValueError(f"class must be one of {CLASS_DIRS}")
        return self.role_root(role) / "pcap" / class_dir

    def flow_root(self, role: str, class_dir: str) -> Path:
        if class_dir not in CLASS_DIRS:
            raise ValueError(f"class must be one of {CLASS_DIRS}")
        return self.role_root(role) / "flows/cicflowmeter-v3" / class_dir

    def manifest_root(self, role: str) -> Path:
        return self.role_root(role) / "manifests"

    def validate_input(self, path: Path, role: str, class_dir: str) -> Path:
        return require_under(path, self.pcap_root(role, class_dir), "input PCAP")

    def validate_output(self, path: Path, role: str, class_dir: str) -> Path:
        return require_under(path, self.flow_root(role, class_dir), "output CSV")
