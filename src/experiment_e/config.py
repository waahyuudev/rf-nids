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


class TopologyAmendment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    amendment_id: str
    status: str
    approved_at: str
    traffic_captured_before_amendment: bool
    source_segment: str
    nids_role: str
    target_segment: str
    expected_generator_ip: str
    expected_generator_ip_status: str
    expected_nids_source_side_ip: str
    expected_nids_source_side_ip_status: str
    expected_nids_target_side_ip: str
    expected_nids_target_side_ip_status: str
    expected_target_ip: str
    expected_target_ip_status: str
    expected_capture_interface: str
    expected_capture_interface_status: str
    http_service_port_status: str
    final_test_collection_authorized: bool
    traffic_capture_authorized: bool


class LivePreflight(BaseModel):
    model_config = ConfigDict(extra="forbid")
    phase: str
    status: str
    evidence: str
    verified_at: str
    diagnostic_pcap_retained: bool
    scientific_pcap_created: bool
    recommended_capture_interface: str
    rejected_capture_interfaces: list[str]
    benign_target_service: str


class E3ProvenanceAmendment(BaseModel):
    """Experiment E-only authorization for a compatibility-qualified extractor."""

    model_config = ConfigDict(extra="forbid")
    amendment_id: str
    status: str
    historical_required_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    historical_artifact_available: bool
    approved_replacement_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    approved_replacement_image_tag: str
    recovery_gate_evidence: str
    compatibility_verdict: str
    equivalence_scope: str
    architecture_provenance_difference: str
    scope: str
    e3_extraction_authorized: bool


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
    topology_amendment: TopologyAmendment | None = None
    live_preflight: LivePreflight | None = None
    e3_provenance_amendment: E3ProvenanceAmendment | None = None

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
        if self.topology_amendment is not None:
            amendment = self.topology_amendment
            pending = (
                amendment.expected_generator_ip_status,
                amendment.expected_nids_target_side_ip_status,
                amendment.expected_capture_interface_status,
                amendment.http_service_port_status,
            )
            if amendment.amendment_id != "A1" or amendment.status != "APPROVED":
                raise ValueError("unexpected Experiment E topology amendment")
            if amendment.traffic_captured_before_amendment is not False:
                raise ValueError("Experiment E traffic must not predate amendment A1")
            if any(value != "pending_live_verification" for value in pending):
                raise ValueError("amended topology must preserve pending live verification")
            if amendment.traffic_capture_authorized or amendment.final_test_collection_authorized:
                raise ValueError("topology amendment must not authorize collection")
        if self.live_preflight is not None:
            preflight = self.live_preflight
            if preflight.phase != "E2_LIVE_3_VM_PREFLIGHT" or preflight.status != "PASS":
                raise ValueError("unexpected Experiment E live preflight")
            if preflight.diagnostic_pcap_retained or preflight.scientific_pcap_created:
                raise ValueError("E2 live preflight must not retain diagnostic or scientific PCAPs")
            if preflight.recommended_capture_interface != "enp0s3":
                raise ValueError("unexpected Experiment E capture interface")
            if "any" not in preflight.rejected_capture_interfaces:
                raise ValueError("E2 live preflight must reject tcpdump any interface")
            if preflight.benign_target_service != "http://10.10.20.2:8080/":
                raise ValueError("unexpected Experiment E benign target service")
        if self.e3_provenance_amendment is not None:
            amendment = self.e3_provenance_amendment
            if amendment.amendment_id != "E3-A1" or amendment.status != "APPROVED":
                raise ValueError("unexpected Experiment E E3 provenance amendment")
            if amendment.historical_required_image_digest != self.cicflowmeter_v3.image_digest:
                raise ValueError("E3 amendment must preserve the historical required image digest")
            if amendment.historical_artifact_available:
                raise ValueError("E3 amendment is only valid when historical image is unavailable")
            if amendment.approved_replacement_image_digest == amendment.historical_required_image_digest:
                raise ValueError("E3 replacement image must be distinct from historical image")
            if amendment.compatibility_verdict != (
                "BYTE_IDENTICAL_ON_NINE_NON_FINAL_EXPERIMENT_D_ADAPTATION_REFERENCE_PCAPS"
            ):
                raise ValueError("E3 replacement must have the approved byte-identical verdict")
            if amendment.scope != "Experiment E only" or not amendment.e3_extraction_authorized:
                raise ValueError("E3 provenance amendment must be limited to authorized Experiment E extraction")
        return self


def load_experiment_e_config(path: str | Path) -> ExperimentEConfig:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"unable to load Experiment E configuration: {exc}") from exc
    config = ExperimentEConfig.model_validate(raw)
    ExperimentEPaths(Path(path).resolve().parents[1]).assert_isolated_from_experiment_d()
    return config
