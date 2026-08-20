"""RF-NIDS FastAPI application and HTTP endpoints."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import case, func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from src.api.database import Base, configure_database, get_db
from src.api.models import Alert, Prediction, TrafficFlow
from src.api.schemas import (
    AlertDetail,
    BatchPredictionRequest,
    BatchPredictionResult,
    DashboardSummary,
    ModelInfo,
    PredictionDetail,
    PredictionRequest,
    PredictionResult,
)
from src.api.service import metadata_metrics, persist_predictions, sync_active_model
from src.common.config import Settings
from src.common.logging import configure_logging
from src.inference import FeatureValidationError, InferenceEngine

Db = Annotated[Session, Depends(get_db)]


def _parse_datetime(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _prediction_detail(row: Prediction) -> PredictionDetail:
    return PredictionDetail(
        id=row.id,
        traffic_flow_id=row.traffic_flow_id,
        predicted_label=row.predicted_label,
        confidence_score=row.confidence_score,
        class_probabilities=row.class_probabilities,
        prediction_time=row.prediction_time,
        source_ip=row.traffic_flow.source_ip,
        destination_ip=row.traffic_flow.destination_ip,
    )


def create_app(
    settings: Settings | None = None,
    *,
    engine_factory=InferenceEngine,
    create_tables: bool = False,
) -> FastAPI:
    settings = settings or Settings.from_env()
    default_page_size = min(50, settings.max_page_size)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        configure_logging(settings.log_level)
        configure_database(application, settings)
        if create_tables:
            Base.metadata.create_all(application.state.engine)
        application.state.inference = engine_factory(
            settings.model_path, settings.model_metadata_path
        )
        with application.state.session_factory() as db:
            application.state.model_record = sync_active_model(
                db, application.state.inference.metadata
            )
        yield
        application.state.engine.dispose()

    application = FastAPI(
        title="RF-NIDS Detection API",
        version="1.0.0",
        description="Random Forest network-flow detection and alert persistence API.",
        lifespan=lifespan,
    )
    application.state.settings = settings

    @application.exception_handler(FeatureValidationError)
    async def feature_error_handler(_: Request, exc: FeatureValidationError):
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @application.exception_handler(SQLAlchemyError)
    async def database_error_handler(_: Request, __: SQLAlchemyError):
        return JSONResponse(status_code=503, content={"detail": "Database unavailable"})

    @application.get("/health", summary="Service health")
    def health(request: Request, db: Db):
        db.execute(text("SELECT 1"))
        return {
            "status": "healthy",
            "database": "connected",
            "model_loaded": hasattr(request.app.state, "inference"),
        }

    @application.get("/api/model", response_model=ModelInfo, summary="Active model metadata")
    def model_info(request: Request):
        metadata = request.app.state.inference.metadata
        metrics = metadata_metrics(metadata)
        return ModelInfo(
            model_name=metadata.get("model_name", "RF-NIDS Random Forest"),
            model_version=metadata["model_version"],
            algorithm="Random Forest",
            feature_count=len(metadata["feature_names"]),
            class_labels=metadata.get("class_names", list(metadata.get("label_mapping", {}))),
            trained_at=_parse_datetime(
                metadata.get("trained_at") or metadata.get("created_at_utc")
            ),
            **metrics,
        )

    @application.post(
        "/api/predict",
        response_model=PredictionResult,
        status_code=status.HTTP_201_CREATED,
        summary="Classify and persist one flow",
    )
    def predict(payload: PredictionRequest, request: Request, db: Db):
        output = request.app.state.inference.predict_one(payload.features)
        return persist_predictions(
            db,
            [payload],
            [output],
            request.app.state.model_record.id,
            settings.alert_confidence_threshold,
        )[0]

    @application.post(
        "/api/predict/batch",
        response_model=BatchPredictionResult,
        status_code=status.HTTP_201_CREATED,
        summary="Classify and persist a flow batch atomically",
    )
    def predict_batch(payload: BatchPredictionRequest, request: Request, db: Db):
        if not payload.flows:
            raise HTTPException(422, "Prediction batch must not be empty")
        if len(payload.flows) > settings.max_batch_size:
            raise HTTPException(
                413, f"Batch exceeds maximum size of {settings.max_batch_size}"
            )
        outputs = request.app.state.inference.predict_batch(
            [item.features for item in payload.flows]
        )
        results = persist_predictions(
            db,
            payload.flows,
            outputs,
            request.app.state.model_record.id,
            settings.alert_confidence_threshold,
        )
        return {"predictions": results}

    @application.get(
        "/api/predictions", response_model=list[PredictionDetail], summary="List predictions"
    )
    def list_predictions(
        db: Db,
        limit: int = Query(default_page_size, ge=1, le=settings.max_page_size),
        offset: int = Query(0, ge=0),
        predicted_label: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
    ):
        query = select(Prediction).join(Prediction.traffic_flow)
        if predicted_label:
            query = query.where(Prediction.predicted_label == predicted_label)
        if source_ip:
            query = query.where(TrafficFlow.source_ip == source_ip)
        if destination_ip:
            query = query.where(TrafficFlow.destination_ip == destination_ip)
        rows = db.scalars(
            query.order_by(Prediction.id.desc()).limit(limit).offset(offset)
        ).all()
        return [_prediction_detail(row) for row in rows]

    @application.get(
        "/api/predictions/{prediction_id}",
        response_model=PredictionDetail,
        summary="Get one prediction",
    )
    def get_prediction(prediction_id: int, db: Db):
        row = db.get(Prediction, prediction_id)
        if row is None:
            raise HTTPException(404, "Prediction not found")
        return _prediction_detail(row)

    @application.get("/api/alerts", response_model=list[AlertDetail], summary="List alerts")
    def list_alerts(
        db: Db,
        limit: int = Query(default_page_size, ge=1, le=settings.max_page_size),
        offset: int = Query(0, ge=0),
        severity: str | None = None,
        alert_status: str | None = Query(None, alias="status"),
    ):
        query = select(Alert)
        if severity:
            query = query.where(Alert.severity == severity)
        if alert_status:
            query = query.where(Alert.status == alert_status)
        return db.scalars(query.order_by(Alert.id.desc()).limit(limit).offset(offset)).all()

    @application.get(
        "/api/alerts/{alert_id}", response_model=AlertDetail, summary="Get one alert"
    )
    def get_alert(alert_id: int, db: Db):
        row = db.get(Alert, alert_id)
        if row is None:
            raise HTTPException(404, "Alert not found")
        return row

    @application.patch(
        "/api/alerts/{alert_id}/acknowledge",
        response_model=AlertDetail,
        summary="Acknowledge an active alert",
    )
    def acknowledge_alert(alert_id: int, db: Db):
        row = db.get(Alert, alert_id)
        if row is None:
            raise HTTPException(404, "Alert not found")
        if row.status != "ACKNOWLEDGED":
            row.status = "ACKNOWLEDGED"
            row.acknowledged_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(row)
        return row

    @application.get(
        "/api/dashboard/summary",
        response_model=DashboardSummary,
        summary="Aggregate dashboard counters",
    )
    def dashboard_summary(db: Db):
        prediction_counts = db.execute(
            select(
                func.count(Prediction.id),
                func.sum(case((Prediction.predicted_label == "Normal", 1), else_=0)),
                func.sum(case((Prediction.predicted_label == "DDoS", 1), else_=0)),
                func.sum(case((Prediction.predicted_label == "PortScan", 1), else_=0)),
                func.max(Prediction.prediction_time),
            )
        ).one()
        alert_counts = db.execute(
            select(
                func.sum(case((Alert.status == "ACTIVE", 1), else_=0)),
                func.sum(case((Alert.status == "ACKNOWLEDGED", 1), else_=0)),
            )
        ).one()
        return DashboardSummary(
            total_flows=prediction_counts[0] or 0,
            total_normal=prediction_counts[1] or 0,
            total_ddos=prediction_counts[2] or 0,
            total_portscan=prediction_counts[3] or 0,
            active_alerts=alert_counts[0] or 0,
            acknowledged_alerts=alert_counts[1] or 0,
            latest_prediction_timestamp=prediction_counts[4],
        )

    return application


app = create_app()
