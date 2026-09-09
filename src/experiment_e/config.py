"""Fail-closed Experiment E E1 configuration."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.experiment_e.paths import ExperimentEPaths


SHA256 = r"^[0-9a-f]{64}$"


class BaselineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    artifact: str
    artifact_sha256: str = Field(pattern=SHA256)
    scientific_metadata: str
    scientific_metadata_sha256: str = Field(pattern=SHA256)
    runtime_metadata: str
    runtime_metadata_sha256: str = Field(pattern=SHA256)


class ExtractorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository: str
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_archive_sha256: str = Field(pattern=SHA256)
    image_tag: str
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class AdapterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identity: str
    version: str
    crosswalk: str
    crosswalk_sha256: str = Field(pattern=SHA256)


class FeatureContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    count: int
    ordered_names_sha256: str = Field(pattern=SHA256)


class OutputRoots(BaseModel):
    model_config = ConfigDict(extra="forbid")
    data: str
    models: str
    reports: str


class FinalTestPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sealed_from: list[str]


class ExperimentEConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    experiment_code: str
    experiment_name: str
    phase: str
    purpose: str
    baseline_rf_v2: BaselineConfig
    cicflowmeter_v3: ExtractorConfig
    adapter: AdapterConfig
    feature_contract: FeatureContract
    classes: list[str]
    new_lab_classes: list[str]
    random_state: int
    allowed_data_roles: list[str]
    forbidden_data_roles: list[str]
    forbidden_source_roots: list[str]
    output_roots: OutputRoots
    create_new_only: bool
    row_split_policy: str
    final_test_policy: FinalTestPolicy

    @model_validator(mode="after")
    def protocol_is_locked(self) -> "ExperimentEConfig":
        if (
            self.experiment_code != "EXPERIMENT_E"
            or self.phase != "E1_SCAFFOLD_AND_PREREGISTRATION"
        ):
            raise ValueError("unexpected Experiment E identity or phase")
        if self.classes != ["Normal", "DDoS", "PortScan"]:
            raise ValueError("three-class order is immutable")
        if self.new_lab_classes != ["Normal", "PortScan"]:
            raise ValueError("E lab collection is restricted to Normal and PortScan")
        if self.feature_contract.count != 78:
            raise ValueError("Experiment E requires exactly 78 ordered features")
        if self.allowed_data_roles != ["adaptation", "validation", "final_test"]:
            raise ValueError("session roles must use the preregistered order")
        if not self.create_new_only:
            raise ValueError("Experiment E outputs must be create-new-only")
        required = {
            "experiment_d_final_test_for_fitting", "experiment_d_final_test_for_adaptation",
            "experiment_d_final_test_for_hyperparameter_selection",
            "experiment_d_final_test_for_validation",
        }
        if not required.issubset(self.forbidden_data_roles):
            raise ValueError("Experiment D final-test prohibitions are incomplete")
        expected = OutputRoots(
            data="data/lab/experiment_e",
            models="models/experiment_e",
            reports="reports/experiment_e",
        )
        if self.output_roots != expected:
            raise ValueError("Experiment E output roots are not isolated")
        return self


def load_experiment_e_config(path: str | Path) -> ExperimentEConfig:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"unable to load Experiment E configuration: {exc}") from exc
    config = ExperimentEConfig.model_validate(raw)
    ExperimentEPaths(Path(path).resolve().parents[1]).assert_isolated_from_experiment_d()
    return config
