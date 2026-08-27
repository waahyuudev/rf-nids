"""Ground-truth manifest schema for future Experiment C flow-level runs."""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, IPvAnyAddress, model_validator


EXPERIMENT_ID_PATTERN = re.compile(r"^expc-\d{8}T\d{6}Z-[0-9a-f]{8}$")


class Scenario(str, Enum):
    NORMAL = "normal"
    DDOS = "ddos"
    PORTSCAN = "portscan"


class ExpectedClass(str, Enum):
    NORMAL = "Normal"
    DDOS = "DDoS"
    PORTSCAN = "PortScan"


SCENARIO_CLASS = {
    Scenario.NORMAL: ExpectedClass.NORMAL,
    Scenario.DDOS: ExpectedClass.DDOS,
    Scenario.PORTSCAN: ExpectedClass.PORTSCAN,
}


def generate_experiment_id(now: datetime | None = None) -> str:
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return f"expc-{timestamp:%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"


class ExperimentManifest(BaseModel):
    """One controlled scenario window; predictions remain individual flows."""

    model_config = ConfigDict(extra="forbid")

    experiment_id: str
    scenario: Scenario
    expected_class: ExpectedClass
    start_time: datetime
    end_time: datetime
    source_ip: IPvAnyAddress
    target_ip: IPvAnyAddress
    capture_session_id: str
    status: str

    @model_validator(mode="after")
    def validate_ground_truth_window(self) -> "ExperimentManifest":
        if not EXPERIMENT_ID_PATTERN.fullmatch(self.experiment_id):
            raise ValueError("invalid Experiment C experiment_id")
        if self.end_time <= self.start_time:
            raise ValueError("end_time must be after start_time")
        if SCENARIO_CLASS[self.scenario] != self.expected_class:
            raise ValueError("expected_class must match scenario")
        return self
