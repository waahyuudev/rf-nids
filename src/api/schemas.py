"""Validated API request and response contracts."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PredictionLabel(str, Enum):
    NORMAL = "Normal"
    DDOS = "DDoS"
    PORTSCAN = "PortScan"


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"


class AlertStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"


class FlowMetadata(BaseModel):
    capture_session_id: str | None = Field(default=None, max_length=80)
    capture_interface: str | None = Field(default=None, max_length=100)
    pcap_segment: str | None = Field(default=None, max_length=255)
    capture_time: datetime | None = None
    source_ip: str | None = Field(default=None, max_length=45)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_ip: str | None = Field(default=None, max_length=45)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=30)


class PredictionRequest(BaseModel):
    features: dict[str, Any]
    metadata: FlowMetadata | None = None


class BatchPredictionRequest(BaseModel):
    flows: list[PredictionRequest]


class PredictionResult(BaseModel):
    prediction_id: int
    prediction: PredictionLabel
    confidence: float
    probabilities: dict[str, float]
    model_version: str


class BatchPredictionResult(BaseModel):
    predictions: list[PredictionResult]


class ModelInfo(BaseModel):
    model_name: str
    model_version: str
    algorithm: str
    feature_count: int
    class_labels: list[str]
    accuracy: float | None
    macro_f1: float | None
    ddos_recall: float | None
    portscan_recall: float | None
    trained_at: datetime | None


class ModelPresentationInfo(ModelInfo):
    id: int
    is_active: bool
    artifact_path: str | None
    artifact_sha256: str | None
    parameters: dict[str, Any] | None
    experiment_id: int | None
    experiment_code: str | None
    experiment_name: str | None


class EvidenceSourceInfo(BaseModel):
    id: int
    owner_type: str
    owner_key: str
    evidence_role: str
    source_path: str
    source_sha256: str
    schema_version: str | None
    imported_at: datetime


class PredictionDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    traffic_flow_id: int
    predicted_label: PredictionLabel
    confidence_score: float | None
    class_probabilities: dict[str, float] | None
    prediction_time: datetime
    source_type: str | None = None
    external_key: str | None = None
    experiment_id: int | None = None
    experiment_code: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    capture_session_id: str | None = None
    capture_interface: str | None = None
    pcap_segment: str | None = None
    capture_time: datetime | None = None
    flow_created_at: datetime | None = None
    model_id: int
    model_name: str | None = None
    model_version: str
    flow_features: dict[str, Any] | None = None
    alert_id: int | None = None
    alert_severity: Severity | None = None
    alert_status: AlertStatus | None = None


class MonitoringRecord(BaseModel):
    flow_id: int
    flow_timestamp: datetime
    capture_time: datetime | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    prediction_id: int | None = None
    prediction_time: datetime | None = None
    predicted_label: PredictionLabel | None = None
    confidence_score: float | None = None
    alert_id: int | None = None
    alert_status: AlertStatus | None = None


class MonitoringSummary(BaseModel):
    total_flows: int
    total_normal: int
    total_ddos: int
    total_portscan: int
    total_alerts: int
    latest_detection_timestamp: datetime | None
    active_model: str | None


class AlertDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    prediction_id: int
    severity: Severity
    title: str
    description: str
    status: AlertStatus
    acknowledged_at: datetime | None
    created_at: datetime
    predicted_label: PredictionLabel
    confidence_score: float
    source_ip: str | None = None
    destination_ip: str | None = None


class DashboardSummary(BaseModel):
    total_flows: int
    total_normal: int
    total_ddos: int
    total_portscan: int
    active_alerts: int
    active_high_alerts: int
    active_medium_alerts: int
    acknowledged_alerts: int
    latest_prediction_timestamp: datetime | None


class TimelinePoint(BaseModel):
    bucket: datetime
    normal: int
    ddos: int
    portscan: int


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class UserInfo(BaseModel):
    id: int
    name: str
    email: str
    role: str
    is_active: bool


class LoginResult(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: UserInfo


class LogoutResult(BaseModel):
    status: str


class DatasetInfo(BaseModel):
    id: int
    name: str
    source_path: str | None
    source_sha256: str | None
    total_rows: int | None
    total_features: int | None
    label_column: str | None
    class_distribution: dict[str, int] | None
    created_by_user_id: int | None
    created_at: datetime
    updated_at: datetime


class ExperimentInfo(BaseModel):
    id: int
    experiment_code: str
    experiment_name: str
    experiment_type: str
    dataset_id: int | None
    description: str | None
    status: str
    source_path: str | None
    source_sha256: str | None
    schema_version: str | None
    imported_at: datetime | None
    created_at: datetime
    updated_at: datetime


class EvaluationInfo(BaseModel):
    id: int
    experiment_id: int
    metric_key: str | None
    class_name: str | None
    accuracy: float | None
    precision_score: float | None
    recall_score: float | None
    f1_score: float | None
    macro_precision: float | None
    macro_recall: float | None
    macro_f1: float | None
    false_positive_rate: float | None
    true_positive: int | None
    true_negative: int | None
    false_positive: int | None
    false_negative: int | None
    confusion_matrix: dict | list | None
    notes: str | None
    source_path: str | None
    source_sha256: str | None
    created_at: datetime
