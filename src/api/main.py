"""RF-NIDS FastAPI application and HTTP endpoints."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import logging
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import case, func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from src.api.database import Base, configure_database, get_db
from src.api.auth import (
    INVALID_PASSWORD_HASH,
    create_session,
    get_current_user,
    get_session_token,
    normalize_email,
    revoke_session,
    verify_password,
)
from src.api.models import (
    Alert,
    Dataset,
    EvaluationResult,
    Experiment,
    Prediction,
    TrafficFlow,
    User,
)
from src.api.schemas import (
    AlertStatus,
    AlertDetail,
    BatchPredictionRequest,
    BatchPredictionResult,
    DashboardSummary,
    DatasetInfo,
    EvaluationInfo,
    ExperimentInfo,
    ModelInfo,
    LoginRequest,
    LoginResult,
    LogoutResult,
    PredictionDetail,
    PredictionRequest,
    PredictionResult,
    PredictionLabel,
    Severity,
    TimelinePoint,
    UserInfo,
)
from src.api.service import metadata_metrics, persist_predictions, sync_active_model
from src.common.config import Settings
from src.common.logging import configure_logging
from src.inference import FeatureValidationError, InferenceEngine

Db = Annotated[Session, Depends(get_db)]
logger = logging.getLogger(__name__)
CurrentUser = Annotated[User, Depends(get_current_user)]
SessionToken = Annotated[str, Depends(get_session_token)]


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
        source_port=row.traffic_flow.source_port,
        destination_ip=row.traffic_flow.destination_ip,
        destination_port=row.traffic_flow.destination_port,
        protocol=row.traffic_flow.protocol,
        capture_session_id=row.traffic_flow.capture_session_id,
        capture_interface=row.traffic_flow.capture_interface,
        pcap_segment=row.traffic_flow.pcap_segment,
        model_version=row.model.model_version,
        flow_features=row.traffic_flow.raw_features,
    )


def _alert_detail(row: Alert) -> AlertDetail:
    prediction = row.prediction
    return AlertDetail(
        id=row.id,
        prediction_id=row.prediction_id,
        severity=row.severity,
        title=row.title,
        description=row.description,
        status=row.status,
        acknowledged_at=row.acknowledged_at,
        created_at=row.created_at,
        predicted_label=prediction.predicted_label,
        confidence_score=prediction.confidence_score,
        source_ip=prediction.traffic_flow.source_ip,
        destination_ip=prediction.traffic_flow.destination_ip,
    )


def _user_info(user: User) -> UserInfo:
    return UserInfo(
        id=user.id,
        name=user.name,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
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
        # Alembic's logging configuration can disable already-imported loggers in
        # processes that run migrations and API tests together.
        logger.disabled = False
        configure_database(application, settings)
        if create_tables:
            if application.state.engine.dialect.name != "sqlite":
                raise RuntimeError(
                    "create_tables is reserved for SQLite integration tests; "
                    "run 'alembic upgrade head' for development and production"
                )
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
    application.state.auth_sessions = {}

    @application.exception_handler(FeatureValidationError)
    async def feature_error_handler(_: Request, exc: FeatureValidationError):
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @application.exception_handler(SQLAlchemyError)
    async def database_error_handler(_: Request, exc: SQLAlchemyError):
        logger.exception("Database operation failed", exc_info=exc)
        return JSONResponse(status_code=503, content={"detail": "Database unavailable"})

    @application.get("/health", summary="Service health")
    def health(request: Request, db: Db):
        db.execute(text("SELECT 1"))
        return {
            "status": "healthy",
            "database": "connected",
            "model_loaded": hasattr(request.app.state, "inference"),
        }

    @application.post(
        "/api/auth/login", response_model=LoginResult, summary="Administrator login"
    )
    def login(payload: LoginRequest, request: Request, db: Db):
        user = db.scalar(select(User).where(User.email == normalize_email(payload.email)))
        encoded = user.password_hash if user is not None else INVALID_PASSWORD_HASH
        password_valid = verify_password(payload.password, encoded)
        if user is None or not password_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive",
            )
        token, expires_at = create_session(request, user.id)
        return LoginResult(
            access_token=token,
            expires_at=expires_at,
            user=_user_info(user),
        )

    @application.post(
        "/api/auth/logout", response_model=LogoutResult, summary="End current session"
    )
    def logout(request: Request, _: CurrentUser, token: SessionToken):
        revoke_session(request, token)
        return LogoutResult(status="logged_out")

    @application.get(
        "/api/auth/me", response_model=UserInfo, summary="Current authenticated user"
    )
    def current_user(user: CurrentUser):
        return _user_info(user)

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

    @application.get(
        "/api/datasets", response_model=list[DatasetInfo], summary="List imported datasets"
    )
    def list_datasets(db: Db):
        return db.scalars(select(Dataset).order_by(Dataset.id)).all()

    @application.get(
        "/api/datasets/{dataset_id}", response_model=DatasetInfo, summary="Get imported dataset"
    )
    def get_dataset(dataset_id: int, db: Db):
        row = db.get(Dataset, dataset_id)
        if row is None:
            raise HTTPException(404, "Dataset not found")
        return row

    @application.get(
        "/api/experiments",
        response_model=list[ExperimentInfo],
        summary="List imported experiments",
    )
    def list_experiments(db: Db):
        return db.scalars(select(Experiment).order_by(Experiment.id)).all()

    @application.get(
        "/api/experiments/{experiment_id}",
        response_model=ExperimentInfo,
        summary="Get imported experiment",
    )
    def get_experiment(experiment_id: int, db: Db):
        row = db.get(Experiment, experiment_id)
        if row is None:
            raise HTTPException(404, "Experiment not found")
        return row

    @application.get(
        "/api/experiments/{experiment_id}/evaluation",
        response_model=list[EvaluationInfo],
        summary="List evaluation results for an experiment",
    )
    def experiment_evaluation(experiment_id: int, db: Db):
        if db.get(Experiment, experiment_id) is None:
            raise HTTPException(404, "Experiment not found")
        return db.scalars(
            select(EvaluationResult)
            .where(EvaluationResult.experiment_id == experiment_id)
            .order_by(EvaluationResult.id)
        ).all()

    @application.get(
        "/api/evaluations",
        response_model=list[EvaluationInfo],
        summary="List imported evaluation results",
    )
    def list_evaluations(db: Db):
        return db.scalars(select(EvaluationResult).order_by(EvaluationResult.id)).all()

    @application.get(
        "/api/evaluations/{evaluation_id}",
        response_model=EvaluationInfo,
        summary="Get imported evaluation result",
    )
    def get_evaluation(evaluation_id: int, db: Db):
        row = db.get(EvaluationResult, evaluation_id)
        if row is None:
            raise HTTPException(404, "Evaluation result not found")
        return row

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
        predicted_label: PredictionLabel | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
    ):
        query = select(Prediction).join(Prediction.traffic_flow)
        if predicted_label:
            query = query.where(Prediction.predicted_label == predicted_label.value)
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
        severity: Severity | None = None,
        alert_status: AlertStatus | None = Query(None, alias="status"),
    ):
        query = select(Alert)
        if severity:
            query = query.where(Alert.severity == severity.value)
        if alert_status:
            query = query.where(Alert.status == alert_status.value)
        rows = db.scalars(query.order_by(Alert.id.desc()).limit(limit).offset(offset)).all()
        return [_alert_detail(row) for row in rows]

    @application.get(
        "/api/alerts/{alert_id}", response_model=AlertDetail, summary="Get one alert"
    )
    def get_alert(alert_id: int, db: Db):
        row = db.get(Alert, alert_id)
        if row is None:
            raise HTTPException(404, "Alert not found")
        return _alert_detail(row)

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
        return _alert_detail(row)

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
                func.sum(
                    case(
                        ((Alert.status == "ACTIVE") & (Alert.severity == "HIGH"), 1),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        ((Alert.status == "ACTIVE") & (Alert.severity == "MEDIUM"), 1),
                        else_=0,
                    )
                ),
                func.sum(case((Alert.status == "ACKNOWLEDGED", 1), else_=0)),
            )
        ).one()
        return DashboardSummary(
            total_flows=prediction_counts[0] or 0,
            total_normal=prediction_counts[1] or 0,
            total_ddos=prediction_counts[2] or 0,
            total_portscan=prediction_counts[3] or 0,
            active_alerts=alert_counts[0] or 0,
            active_high_alerts=alert_counts[1] or 0,
            active_medium_alerts=alert_counts[2] or 0,
            acknowledged_alerts=alert_counts[3] or 0,
            latest_prediction_timestamp=prediction_counts[4],
        )

    @application.get(
        "/api/dashboard/timeline",
        response_model=list[TimelinePoint],
        summary="Aggregate recent prediction activity by minute",
    )
    def dashboard_timeline(
        db: Db,
        minutes: int = Query(60, ge=1, le=1440),
    ):
        since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        dialect = db.bind.dialect.name if db.bind is not None else ""
        if dialect == "sqlite":
            bucket = func.strftime("%Y-%m-%dT%H:%M:00+00:00", Prediction.prediction_time)
        else:
            bucket = func.date_trunc("minute", Prediction.prediction_time)
        rows = db.execute(
            select(
                bucket.label("bucket"),
                func.sum(case((Prediction.predicted_label == "Normal", 1), else_=0)),
                func.sum(case((Prediction.predicted_label == "DDoS", 1), else_=0)),
                func.sum(case((Prediction.predicted_label == "PortScan", 1), else_=0)),
            )
            .where(Prediction.prediction_time >= since)
            .group_by(bucket)
            .order_by(bucket)
        ).all()
        return [
            TimelinePoint(
                bucket=_parse_datetime(row[0]),
                normal=row[1] or 0,
                ddos=row[2] or 0,
                portscan=row[3] or 0,
            )
            for row in rows
        ]

    return application


app = create_app()
