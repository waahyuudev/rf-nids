from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.experiment_c.config import ExperimentCConfig, load_experiment_c_config
from src.experiment_c.manifest import (
    EXPERIMENT_ID_PATTERN,
    ExpectedClass,
    ExperimentManifest,
    Scenario,
    generate_experiment_id,
)


ROOT = Path(__file__).resolve().parents[2]


def test_configuration_loads_and_allows_only_configured_target() -> None:
    config = load_experiment_c_config(ROOT / "config/experiment_c.yaml")
    assert str(config.validate_target("192.168.56.10")) == "192.168.56.10"
    with pytest.raises(ValueError, match="allowlist"):
        config.validate_target("192.168.56.11")


@pytest.mark.parametrize("target", ["8.8.8.8", "2001:4860:4860::8888"])
def test_public_ipv4_and_ipv6_targets_are_rejected(target: str) -> None:
    config = load_experiment_c_config(ROOT / "config/experiment_c.yaml")
    with pytest.raises(ValueError):
        config.validate_target(target)


def test_loopback_and_address_outside_lab_are_rejected() -> None:
    config = load_experiment_c_config(ROOT / "config/experiment_c.yaml")
    with pytest.raises(ValueError, match="loopback"):
        config.validate_target("127.0.0.1")
    with pytest.raises(ValueError, match="outside"):
        config.validate_target("10.0.0.10")


def test_invalid_public_lab_subnet_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ExperimentCConfig.model_validate(
            {
                "lab": {
                    "subnet": "8.8.8.0/24",
                    "target_ip": "8.8.8.8",
                    "attacker_ip": "8.8.8.9",
                },
                "safety": {"allowed_targets": ["8.8.8.8"]},
            }
        )


def test_experiment_id_generation() -> None:
    identifier = generate_experiment_id(datetime(2026, 8, 21, tzinfo=timezone.utc))
    assert EXPERIMENT_ID_PATTERN.fullmatch(identifier)
    assert identifier.startswith("expc-20260821T000000Z-")


def test_scenario_and_expected_class_enums_are_exact() -> None:
    assert {item.value for item in Scenario} == {"normal", "ddos", "portscan"}
    assert {item.value for item in ExpectedClass} == {"Normal", "DDoS", "PortScan"}


def test_manifest_schema_accepts_consistent_flow_ground_truth() -> None:
    start = datetime(2026, 8, 21, tzinfo=timezone.utc)
    manifest = ExperimentManifest(
        experiment_id=generate_experiment_id(start),
        scenario="normal",
        expected_class="Normal",
        start_time=start,
        end_time=start + timedelta(seconds=30),
        source_ip="192.168.56.20",
        target_ip="192.168.56.10",
        capture_session_id="session-1",
        status="completed",
    )
    assert manifest.expected_class is ExpectedClass.NORMAL


def test_manifest_rejects_mismatched_class_and_invalid_window() -> None:
    start = datetime(2026, 8, 21, tzinfo=timezone.utc)
    with pytest.raises(ValidationError):
        ExperimentManifest(
            experiment_id=generate_experiment_id(start),
            scenario="normal",
            expected_class="DDoS",
            start_time=start,
            end_time=start,
            source_ip="192.168.56.20",
            target_ip="192.168.56.10",
            capture_session_id="session-1",
            status="failed",
        )
