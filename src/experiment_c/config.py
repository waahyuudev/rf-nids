"""Fail-closed configuration and target validation for Experiment C."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, model_validator


class LabConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subnet: str
    target_ip: IPvAnyAddress
    attacker_ip: IPvAnyAddress

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network(self.subnet, strict=True)

    @model_validator(mode="after")
    def addresses_belong_to_private_lab(self) -> "LabConfig":
        network = self.network
        if not network.is_private or network.is_loopback:
            raise ValueError("lab subnet must be private and non-loopback")
        for label, address in (("target_ip", self.target_ip), ("attacker_ip", self.attacker_ip)):
            if address not in network:
                raise ValueError(f"{label} must be inside lab subnet")
        if self.target_ip == self.attacker_ip:
            raise ValueError("target_ip and attacker_ip must differ")
        return self


class SafetyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    require_private_target: bool = True
    allow_loopback: bool = False
    allowed_targets: list[IPvAnyAddress] = Field(min_length=1)


class ExperimentCConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lab: LabConfig
    safety: SafetyConfig

    @model_validator(mode="after")
    def allowed_targets_are_scoped(self) -> "ExperimentCConfig":
        network = self.lab.network
        for target in self.safety.allowed_targets:
            if target not in network:
                raise ValueError("every allowed target must be inside lab subnet")
            if target.is_loopback and not self.safety.allow_loopback:
                raise ValueError("loopback target is not explicitly allowed")
            if self.safety.require_private_target and not target.is_private:
                raise ValueError("every allowed target must be private")
        if self.lab.target_ip not in self.safety.allowed_targets:
            raise ValueError("configured target_ip must be explicitly allowed")
        return self

    def validate_target(self, value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """Return a validated literal address or reject it without DNS resolution."""
        try:
            target = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("target must be a literal IP address") from exc
        if target.is_loopback and not self.safety.allow_loopback:
            raise ValueError("loopback target is not allowed")
        if self.safety.require_private_target and not target.is_private:
            raise ValueError("public target is not allowed")
        if target not in self.lab.network:
            raise ValueError("target is outside the configured lab subnet")
        if target not in self.safety.allowed_targets:
            raise ValueError("target is not in the explicit allowlist")
        return target


def load_experiment_c_config(path: str | Path) -> ExperimentCConfig:
    config_path = Path(path)
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"unable to load Experiment C configuration: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("Experiment C configuration must be a mapping")
    return ExperimentCConfig.model_validate(raw)
