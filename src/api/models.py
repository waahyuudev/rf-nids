"""SQLAlchemy persistence entities."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.api.database import Base


PortableJSON = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('ADMIN')", name="ck_users_role"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(30), default="ADMIN")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    datasets: Mapped[list[Dataset]] = relationship(back_populates="created_by_user")
    acknowledged_alerts: Mapped[list[Alert]] = relationship(
        back_populates="acknowledged_by_user"
    )


class Dataset(Base):
    __tablename__ = "datasets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    source_path: Mapped[str | None] = mapped_column(String(1000))
    source_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    total_rows: Mapped[int | None] = mapped_column(Integer)
    total_features: Mapped[int | None] = mapped_column(Integer)
    label_column: Mapped[str | None] = mapped_column(String(255))
    class_distribution: Mapped[dict | None] = mapped_column(PortableJSON)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    created_by_user: Mapped[User | None] = relationship(back_populates="datasets")
    experiments: Mapped[list[Experiment]] = relationship(back_populates="dataset")


class Experiment(Base):
    __tablename__ = "experiments"
    id: Mapped[int] = mapped_column(primary_key=True)
    experiment_code: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    experiment_name: Mapped[str] = mapped_column(String(255))
    experiment_type: Mapped[str] = mapped_column(String(100))
    dataset_id: Mapped[int | None] = mapped_column(
        ForeignKey("datasets.id", ondelete="SET NULL"), index=True
    )
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(50))
    source_path: Mapped[str | None] = mapped_column(String(1000))
    source_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    schema_version: Mapped[str | None] = mapped_column(String(100))
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    dataset: Mapped[Dataset | None] = relationship(back_populates="experiments")
    evaluation_results: Mapped[list[EvaluationResult]] = relationship(
        back_populates="experiment", cascade="all, delete-orphan"
    )
    models: Mapped[list[ModelRecord]] = relationship(back_populates="experiment")
    predictions: Mapped[list[Prediction]] = relationship(back_populates="experiment")


class EvaluationResult(Base):
    __tablename__ = "evaluation_results"
    __table_args__ = (
        UniqueConstraint("experiment_id", "metric_key", name="uq_evaluation_metric_key"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    experiment_id: Mapped[int] = mapped_column(
        ForeignKey("experiments.id", ondelete="CASCADE"), index=True
    )
    class_name: Mapped[str | None] = mapped_column(String(100))
    metric_key: Mapped[str | None] = mapped_column(String(150))
    accuracy: Mapped[float | None] = mapped_column(Float)
    precision_score: Mapped[float | None] = mapped_column(Float)
    recall_score: Mapped[float | None] = mapped_column(Float)
    f1_score: Mapped[float | None] = mapped_column(Float)
    macro_precision: Mapped[float | None] = mapped_column(Float)
    macro_recall: Mapped[float | None] = mapped_column(Float)
    macro_f1: Mapped[float | None] = mapped_column(Float)
    false_positive_rate: Mapped[float | None] = mapped_column(Float)
    true_positive: Mapped[int | None] = mapped_column(Integer)
    true_negative: Mapped[int | None] = mapped_column(Integer)
    false_positive: Mapped[int | None] = mapped_column(Integer)
    false_negative: Mapped[int | None] = mapped_column(Integer)
    confusion_matrix: Mapped[dict | list | None] = mapped_column(PortableJSON)
    notes: Mapped[str | None] = mapped_column(Text)
    source_path: Mapped[str | None] = mapped_column(String(1000))
    source_sha256: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    experiment: Mapped[Experiment] = relationship(back_populates="evaluation_results")


class EvidenceSource(Base):
    __tablename__ = "evidence_sources"
    __table_args__ = (
        UniqueConstraint(
            "owner_type", "owner_key", "evidence_role", name="uq_evidence_owner_role"
        ),
        UniqueConstraint("source_path", name="uq_evidence_source_path"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_type: Mapped[str] = mapped_column(String(50), index=True)
    owner_key: Mapped[str] = mapped_column(String(150), index=True)
    evidence_role: Mapped[str] = mapped_column(String(100))
    source_path: Mapped[str] = mapped_column(String(1000))
    source_sha256: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[str | None] = mapped_column(String(100))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ModelRecord(Base):
    __tablename__ = "models"
    id: Mapped[int] = mapped_column(primary_key=True)
    model_name: Mapped[str] = mapped_column(String(200))
    model_version: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    algorithm: Mapped[str] = mapped_column(String(100))
    accuracy: Mapped[float | None] = mapped_column(Float)
    macro_f1: Mapped[float | None] = mapped_column(Float)
    ddos_recall: Mapped[float | None] = mapped_column(Float)
    portscan_recall: Mapped[float | None] = mapped_column(Float)
    feature_count: Mapped[int | None] = mapped_column(Integer)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    experiment_id: Mapped[int | None] = mapped_column(
        ForeignKey("experiments.id", ondelete="SET NULL"), index=True
    )
    artifact_path: Mapped[str | None] = mapped_column(String(1000))
    artifact_sha256: Mapped[str | None] = mapped_column(String(64))
    parameters: Mapped[dict | None] = mapped_column(PortableJSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Historical predictions prevent model deletion; model identity is audit data.
    predictions: Mapped[list[Prediction]] = relationship(
        back_populates="model", passive_deletes=True
    )
    experiment: Mapped[Experiment | None] = relationship(back_populates="models")


class TrafficFlow(Base):
    __tablename__ = "traffic_flows"
    id: Mapped[int] = mapped_column(primary_key=True)
    capture_session_id: Mapped[str | None] = mapped_column(String(80), index=True)
    capture_interface: Mapped[str | None] = mapped_column(String(100))
    pcap_segment: Mapped[str | None] = mapped_column(String(255))
    capture_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(30))
    raw_features: Mapped[dict] = mapped_column(PortableJSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # A flow owns its single prediction and any downstream alert.
    prediction: Mapped[Prediction | None] = relationship(
        back_populates="traffic_flow",
        cascade="all, delete-orphan",
        passive_deletes=True,
        single_parent=True,
    )


class Prediction(Base):
    __tablename__ = "predictions"
    __table_args__ = (
        CheckConstraint(
            "predicted_label IN ('Normal', 'DDoS', 'PortScan')",
            name="ck_predictions_predicted_label",
        ),
        Index("ix_predictions_label_time", "predicted_label", "prediction_time"),
        UniqueConstraint(
            "source_type", "external_key", name="uq_predictions_source_external_key"
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    traffic_flow_id: Mapped[int] = mapped_column(
        ForeignKey("traffic_flows.id", ondelete="CASCADE"), unique=True
    )
    model_id: Mapped[int] = mapped_column(
        ForeignKey("models.id", ondelete="RESTRICT"), index=True
    )
    experiment_id: Mapped[int | None] = mapped_column(
        ForeignKey("experiments.id", ondelete="SET NULL"), index=True
    )
    source_type: Mapped[str | None] = mapped_column(String(50), index=True)
    external_key: Mapped[str | None] = mapped_column(String(255))
    predicted_label: Mapped[str] = mapped_column(String(50), index=True)
    confidence_score: Mapped[float] = mapped_column(Float)
    class_probabilities: Mapped[dict] = mapped_column(PortableJSON)
    prediction_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    traffic_flow: Mapped[TrafficFlow] = relationship(back_populates="prediction")
    model: Mapped[ModelRecord] = relationship(back_populates="predictions")
    experiment: Mapped[Experiment | None] = relationship(back_populates="predictions")
    alert: Mapped[Alert | None] = relationship(
        back_populates="prediction",
        cascade="all, delete-orphan",
        passive_deletes=True,
        single_parent=True,
    )


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint("severity IN ('HIGH', 'MEDIUM')", name="ck_alerts_severity"),
        CheckConstraint(
            "status IN ('ACTIVE', 'ACKNOWLEDGED')", name="ck_alerts_status"
        ),
        Index("ix_alerts_status_severity", "status", "severity"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    prediction_id: Mapped[int] = mapped_column(
        ForeignKey("predictions.id", ondelete="CASCADE"), unique=True
    )
    severity: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE", index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    prediction: Mapped[Prediction] = relationship(back_populates="alert")
    acknowledged_by_user: Mapped[User | None] = relationship(
        back_populates="acknowledged_alerts"
    )
