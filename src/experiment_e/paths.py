"""Strict Experiment E path containment."""

from dataclasses import dataclass
from pathlib import Path

from src.common.config import PROJECT_ROOT
from src.experiment_d.paths import contained, require_under


ROLES = ("adaptation", "validation", "final_test")
CLASS_DIRS = ("normal", "portscan")


@dataclass(frozen=True)
class ExperimentEPaths:
    root: Path = PROJECT_ROOT

    @property
    def data_root(self) -> Path:
        return self.root / "data/lab/experiment_e"

    @property
    def model_root(self) -> Path:
        return self.root / "models/experiment_e"

    @property
    def report_root(self) -> Path:
        return self.root / "reports/experiment_e"

    @property
    def experiment_d_root(self) -> Path:
        return self.root / "data/lab/experiment_d"

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

    def validate_pcap(self, path: Path, role: str, class_dir: str) -> Path:
        return require_under(path, self.pcap_root(role, class_dir), "Experiment E PCAP")

    def validate_flow(self, path: Path, role: str, class_dir: str) -> Path:
        return require_under(path, self.flow_root(role, class_dir), "Experiment E flow")

    def assert_isolated_from_experiment_d(self) -> None:
        roots = (self.data_root, self.model_root, self.report_root)
        d_roots = (
            self.root / "data/lab/experiment_d",
            self.root / "models/experiment_d",
            self.root / "reports/experiment_d",
        )
        if any(contained(e, d) or contained(d, e) for e in roots for d in d_roots):
            raise ValueError("Experiment E roots must not alias Experiment D")
