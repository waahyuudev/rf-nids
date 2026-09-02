"""Fail-closed Experiment D configuration."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


EXPECTED_ROLES = ["adaptation", "final_test"]
EXPECTED_CLASSES = ["Normal", "DDoS", "PortScan"]
REQUIRED_FINAL_TEST_PROHIBITIONS = {
    "fitting", "tuning", "preprocessing_fit", "feature_selection",
    "threshold_selection", "model_selection",
}


class AdapterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identity: str
    version: str
    crosswalk_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ExtractorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository: str
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_archive_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    image_tag: str
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rf_v1_artifact: str
    rf_v1_metadata: str
    rf_v2_output: str
    rf_v2_metadata_output: str

    @model_validator(mode="after")
    def outputs_are_isolated(self) -> "ModelConfig":
        if self.rf_v2_output == self.rf_v1_artifact:
            raise ValueError("RF-v2 output must not overwrite RF-v1")
        if not self.rf_v2_output.startswith("models/experiment_d/"):
            raise ValueError("RF-v2 model must be under models/experiment_d")
        if not self.rf_v2_metadata_output.startswith("models/experiment_d/"):
            raise ValueError("RF-v2 metadata must be under models/experiment_d")
        return self


class SeedsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    split: int
    tuning: int
    sampling: int


class ExperimentDConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    experiment_code: str
    experiment_name: str
    roles: list[str]
    classes: list[str]
    feature_count: int
    adapter: AdapterConfig
    cicflowmeter_v3: ExtractorConfig
    model: ModelConfig
    seeds: SeedsConfig
    prohibited_sources: list[str] = Field(min_length=1)
    final_test_prohibited_operations: list[str]

    @model_validator(mode="after")
    def validate_protocol_constants(self) -> "ExperimentDConfig":
        if self.experiment_code != "EXPERIMENT_D":
            raise ValueError("experiment_code must be EXPERIMENT_D")
        if self.experiment_name != "External Adaptation and Revalidation":
            raise ValueError("unexpected Experiment D name")
        if self.roles != EXPECTED_ROLES or self.classes != EXPECTED_CLASSES:
            raise ValueError("roles/classes must use the declared stable order")
        if self.feature_count != 78:
            raise ValueError("Experiment D requires exactly 78 features")
        if set(self.final_test_prohibited_operations) != REQUIRED_FINAL_TEST_PROHIBITIONS:
            raise ValueError("final_test prohibition set is incomplete")
        return self


def load_experiment_d_config(path: str | Path) -> ExperimentDConfig:
    try:
        value = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"unable to load Experiment D configuration: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("Experiment D configuration must be a mapping")
    return ExperimentDConfig.model_validate(value)
