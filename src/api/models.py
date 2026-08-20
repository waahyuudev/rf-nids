"""SQLAlchemy persistence entities."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.api.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


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
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    predictions: Mapped[list[Prediction]] = relationship(back_populates="model")


class TrafficFlow(Base):
    __tablename__ = "traffic_flows"
    id: Mapped[int] = mapped_column(primary_key=True)
    capture_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(30))
    raw_features: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    prediction: Mapped[Prediction] = relationship(back_populates="traffic_flow")


class Prediction(Base):
    __tablename__ = "predictions"
    __table_args__ = (Index("ix_predictions_label_time", "predicted_label", "prediction_time"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    traffic_flow_id: Mapped[int] = mapped_column(ForeignKey("traffic_flows.id"), unique=True)
    model_id: Mapped[int] = mapped_column(ForeignKey("models.id"), index=True)
    predicted_label: Mapped[str] = mapped_column(String(50), index=True)
    confidence_score: Mapped[float] = mapped_column(Float)
    class_probabilities: Mapped[dict] = mapped_column(JSON)
    prediction_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    traffic_flow: Mapped[TrafficFlow] = relationship(back_populates="prediction")
    model: Mapped[ModelRecord] = relationship(back_populates="predictions")
    alert: Mapped[Alert | None] = relationship(back_populates="prediction")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_status_severity", "status", "severity"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    prediction_id: Mapped[int] = mapped_column(ForeignKey("predictions.id"), unique=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE", index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    prediction: Mapped[Prediction] = relationship(back_populates="alert")
