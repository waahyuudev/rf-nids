"""Validated API request and response contracts."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FlowMetadata(BaseModel):
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
    prediction: str
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


class PredictionDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    traffic_flow_id: int
    predicted_label: str
    confidence_score: float
    class_probabilities: dict[str, float]
    prediction_time: datetime
    source_ip: str | None = None
    destination_ip: str | None = None


class AlertDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    prediction_id: int
    severity: str
    title: str
    description: str
    status: str
    acknowledged_at: datetime | None
    created_at: datetime


class DashboardSummary(BaseModel):
    total_flows: int
    total_normal: int
    total_ddos: int
    total_portscan: int
    active_alerts: int
    acknowledged_alerts: int
    latest_prediction_timestamp: datetime | None
