"""RF-NIDS FastAPI application and HTTP endpoints."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import logging
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy import case, func, or_, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from src.api.database import Base, configure_database, get_db
from src.api.auth import (
    INVALID_PASSWORD_HASH,
    create_session,
    get_session_token,
    normalize_email,
    require_admin,
    revoke_session,
    verify_password,
)
from src.api.models import (
    Alert,
    Dataset,
    EvidenceSource,
    EvaluationResult,
    Experiment,
    ModelRecord,
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
    EvidenceSourceInfo,
    EvaluationInfo,
    ExperimentInfo,
    ModelInfo,
    ModelPresentationInfo,
    MonitoringRecord,
    MonitoringSummary,
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
from src.api.exports import (
    EVALUATION_FIELDS,
    MAX_EXPORT_RECORDS,
    alert_record,
    confusion_matrix_rows,
    csv_bytes,
    dataset_record,
    evaluation_record,
    export_metadata,
    json_bytes,
    prediction_record,
)
from src.common.config import Settings
from src.common.logging import configure_logging
from src.inference import FeatureValidationError, InferenceEngine

Db = Annotated[Session, Depends(get_db)]
logger = logging.getLogger(__name__)
AdminUser = Annotated[User, Depends(require_admin)]
SessionToken = Annotated[str, Depends(get_session_token)]


def _parse_datetime(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _prediction_detail(row: Prediction) -> PredictionDetail:
    alert = row.alert
    experiment = row.experiment
    return PredictionDetail(
        id=row.id,
        traffic_flow_id=row.traffic_flow_id,
        predicted_label=row.predicted_label,
        confidence_score=row.confidence_score,
        class_probabilities=row.class_probabilities,
        prediction_time=row.prediction_time,
        source_type=row.source_type,
        external_key=row.external_key,
        experiment_id=row.experiment_id,
        experiment_code=experiment.experiment_code if experiment else None,
        source_ip=row.traffic_flow.source_ip,
        source_port=row.traffic_flow.source_port,
        destination_ip=row.traffic_flow.destination_ip,
        destination_port=row.traffic_flow.destination_port,
        protocol=row.traffic_flow.protocol,
        capture_session_id=row.traffic_flow.capture_session_id,
        capture_interface=row.traffic_flow.capture_interface,
        pcap_segment=row.traffic_flow.pcap_segment,
        capture_time=row.traffic_flow.capture_time,
        flow_created_at=row.traffic_flow.created_at,
        model_id=row.model_id,
        model_name=row.model.model_name,
        model_version=row.model.model_version,
        flow_features=row.traffic_flow.raw_features,
        alert_id=alert.id if alert else None,
        alert_severity=alert.severity if alert else None,
        alert_status=alert.status if alert else None,
    )


def _runtime_prediction_clause():
    """Include new runtime rows and legacy runtime rows created before provenance."""
    return or_(Prediction.source_type.is_(None), Prediction.source_type == "RUNTIME")


def _prediction_query(*, predicted_label=None, source_ip=None, destination_ip=None, protocol=None):
    query = select(Prediction).join(Prediction.traffic_flow).where(_runtime_prediction_clause())
    if predicted_label:
        query = query.where(Prediction.predicted_label == getattr(predicted_label, "value", predicted_label))
    if source_ip:
        query = query.where(TrafficFlow.source_ip == source_ip)
    if destination_ip:
        query = query.where(TrafficFlow.destination_ip == destination_ip)
    if protocol:
        query = query.where(TrafficFlow.protocol == protocol)
    return query


def _alert_query(*, severity=None, alert_status=None, predicted_label=None, source_ip=None, destination_ip=None):
    query = select(Alert).join(Alert.prediction).join(Prediction.traffic_flow).where(_runtime_prediction_clause())
    for column, value in ((Alert.severity, severity), (Alert.status, alert_status),
                          (Prediction.predicted_label, predicted_label)):
        if value:
            query = query.where(column == getattr(value, "value", value))
    if source_ip:
        query = query.where(TrafficFlow.source_ip == source_ip)
    if destination_ip:
        query = query.where(TrafficFlow.destination_ip == destination_ip)
    return query


def _download(content: bytes, filename: str, media_type: str, *, count: int) -> Response:
    return Response(content=content, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Export-Record-Count": str(count),
        "X-Export-Maximum-Records": str(MAX_EXPORT_RECORDS),
    })


def _alert_detail(row: Alert) -> AlertDetail:
    prediction = row.prediction
    flow = prediction.traffic_flow
    user = row.acknowledged_by_user
    return AlertDetail(
        id=row.id,
        prediction_id=row.prediction_id,
        severity=row.severity,
        title=row.title,
        description=row.description,
        status=row.status,
        acknowledged_at=row.acknowledged_at,
        acknowledged_by_user_id=row.acknowledged_by_user_id,
        acknowledged_by_name=user.name if user else None,
        acknowledged_by_email=user.email if user else None,
        created_at=row.created_at,
        predicted_label=prediction.predicted_label,
        confidence_score=prediction.confidence_score,
        class_probabilities=prediction.class_probabilities,
        source_ip=flow.source_ip,
        source_port=flow.source_port,
        destination_ip=flow.destination_ip,
        destination_port=flow.destination_port,
        protocol=flow.protocol,
        capture_time=flow.capture_time,
        model_name=prediction.model.model_name,
        model_version=prediction.model.model_version,
        source_type=prediction.source_type,
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
        if user.role != "ADMIN":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrator access required",
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
    def logout(request: Request, _: AdminUser, token: SessionToken):
        revoke_session(request, token)
        return LogoutResult(status="logged_out")

    @application.get(
        "/api/auth/me", response_model=UserInfo, summary="Current authenticated user"
    )
    def current_user(user: AdminUser):
        return _user_info(user)

    @application.get("/api/model", response_model=ModelInfo, summary="Active model metadata")
    def model_info(request: Request, _: AdminUser):
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
        "/api/models/active",
        response_model=ModelPresentationInfo,
        summary="Active model presentation metadata",
    )
    def active_model(request: Request, db: Db, _: AdminUser):
        row = db.scalar(
            select(ModelRecord)
            .where(ModelRecord.is_active.is_(True))
            .order_by(ModelRecord.id.desc())
        )
        if row is None:
            raise HTTPException(404, "No active model")
        metadata = request.app.state.inference.metadata
        experiment = row.experiment
        return ModelPresentationInfo(
            id=row.id,
            model_name=row.model_name,
            model_version=row.model_version,
            algorithm=row.algorithm,
            feature_count=row.feature_count or len(metadata.get("feature_names", [])),
            class_labels=metadata.get(
                "class_names", list(metadata.get("label_mapping", {}))
            ),
            accuracy=row.accuracy,
            macro_f1=row.macro_f1,
            ddos_recall=row.ddos_recall,
            portscan_recall=row.portscan_recall,
            trained_at=_parse_datetime(
                metadata.get("trained_at") or metadata.get("created_at_utc")
            ),
            is_active=row.is_active,
            artifact_path=row.artifact_path,
            artifact_sha256=row.artifact_sha256,
            parameters=row.parameters,
            experiment_id=row.experiment_id,
            experiment_code=experiment.experiment_code if experiment else None,
            experiment_name=experiment.experiment_name if experiment else None,
        )

    @application.get(
        "/api/evidence-sources",
        response_model=list[EvidenceSourceInfo],
        summary="List imported evidence provenance",
    )
    def list_evidence_sources(
        db: Db,
        _: AdminUser,
        owner_type: str | None = None,
        owner_key: str | None = None,
    ):
        query = select(EvidenceSource)
        if owner_type:
            query = query.where(EvidenceSource.owner_type == owner_type)
        if owner_key:
            query = query.where(EvidenceSource.owner_key == owner_key)
        return db.scalars(query.order_by(EvidenceSource.id)).all()

    @application.get(
        "/api/datasets", response_model=list[DatasetInfo], summary="List imported datasets"
    )
    def list_datasets(db: Db, _: AdminUser):
        return db.scalars(select(Dataset).order_by(Dataset.id)).all()

    @application.get(
        "/api/datasets/{dataset_id}", response_model=DatasetInfo, summary="Get imported dataset"
    )
    def get_dataset(dataset_id: int, db: Db, _: AdminUser):
        row = db.get(Dataset, dataset_id)
        if row is None:
            raise HTTPException(404, "Dataset not found")
        return row

    @application.get(
        "/api/experiments",
        response_model=list[ExperimentInfo],
        summary="List imported experiments",
    )
    def list_experiments(db: Db, _: AdminUser):
        return db.scalars(select(Experiment).order_by(Experiment.id)).all()

    @application.get(
        "/api/experiments/{experiment_id}",
        response_model=ExperimentInfo,
        summary="Get imported experiment",
    )
    def get_experiment(experiment_id: int, db: Db, _: AdminUser):
        row = db.get(Experiment, experiment_id)
        if row is None:
            raise HTTPException(404, "Experiment not found")
        return row

    @application.get(
        "/api/experiments/{experiment_id}/evaluation",
        response_model=list[EvaluationInfo],
        summary="List evaluation results for an experiment",
    )
    def experiment_evaluation(experiment_id: int, db: Db, _: AdminUser):
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
    def list_evaluations(db: Db, _: AdminUser):
        return db.scalars(select(EvaluationResult).order_by(EvaluationResult.id)).all()

    @application.get(
        "/api/evaluations/{evaluation_id}",
        response_model=EvaluationInfo,
        summary="Get imported evaluation result",
    )
    def get_evaluation(evaluation_id: int, db: Db, _: AdminUser):
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
        )
        return {"predictions": results}

    @application.get(
        "/api/predictions", response_model=list[PredictionDetail], summary="List predictions"
    )
    def list_predictions(
        db: Db,
        _: AdminUser,
        limit: int = Query(default_page_size, ge=1, le=settings.max_page_size),
        offset: int = Query(0, ge=0),
        predicted_label: PredictionLabel | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        protocol: str | None = None,
    ):
        query = _prediction_query(
            predicted_label=predicted_label, source_ip=source_ip,
            destination_ip=destination_ip, protocol=protocol,
        )
        rows = db.scalars(
            query.order_by(Prediction.id.desc()).limit(limit).offset(offset)
        ).all()
        return [_prediction_detail(row) for row in rows]

    @application.get(
        "/api/traffic-flows",
        response_model=list[MonitoringRecord],
        summary="List runtime traffic flows for monitoring",
    )
    def list_traffic_flows(
        db: Db,
        _: AdminUser,
        limit: int = Query(default_page_size, ge=1, le=settings.max_page_size),
        offset: int = Query(0, ge=0),
        predicted_label: PredictionLabel | None = None,
        protocol: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
    ):
        query = (
            select(TrafficFlow)
            .outerjoin(TrafficFlow.prediction)
            .where(or_(Prediction.id.is_(None), _runtime_prediction_clause()))
        )
        if predicted_label:
            query = query.where(Prediction.predicted_label == predicted_label.value)
        if protocol:
            query = query.where(TrafficFlow.protocol == protocol)
        if source_ip:
            query = query.where(TrafficFlow.source_ip == source_ip)
        if destination_ip:
            query = query.where(TrafficFlow.destination_ip == destination_ip)
        rows = db.scalars(
            query.order_by(TrafficFlow.id.desc()).limit(limit).offset(offset)
        ).all()
        return [
            MonitoringRecord(
                flow_id=row.id,
                flow_timestamp=row.capture_time or row.created_at,
                capture_time=row.capture_time,
                source_ip=row.source_ip,
                source_port=row.source_port,
                destination_ip=row.destination_ip,
                destination_port=row.destination_port,
                protocol=row.protocol,
                prediction_id=row.prediction.id if row.prediction else None,
                prediction_time=(row.prediction.prediction_time if row.prediction else None),
                predicted_label=(row.prediction.predicted_label if row.prediction else None),
                confidence_score=(row.prediction.confidence_score if row.prediction else None),
                alert_id=(row.prediction.alert.id if row.prediction and row.prediction.alert else None),
                alert_status=(row.prediction.alert.status if row.prediction and row.prediction.alert else None),
            )
            for row in rows
        ]

    @application.get(
        "/api/monitoring/summary",
        response_model=MonitoringSummary,
        summary="Aggregate runtime monitoring counters",
    )
    def monitoring_summary(db: Db, _: AdminUser):
        flow_counts = db.execute(
            select(
                func.count(TrafficFlow.id),
                func.sum(case((Prediction.predicted_label == "Normal", 1), else_=0)),
                func.sum(case((Prediction.predicted_label == "DDoS", 1), else_=0)),
                func.sum(case((Prediction.predicted_label == "PortScan", 1), else_=0)),
                func.max(Prediction.prediction_time),
            )
            .select_from(TrafficFlow)
            .outerjoin(TrafficFlow.prediction)
            .where(or_(Prediction.id.is_(None), _runtime_prediction_clause()))
        ).one()
        alert_counts = db.execute(
            select(
                func.count(Alert.id),
                func.sum(case((Alert.status == "ACTIVE", 1), else_=0)),
            )
            .join(Alert.prediction)
            .where(_runtime_prediction_clause())
        ).one()
        active_model = db.scalar(
            select(ModelRecord.model_version)
            .where(ModelRecord.is_active.is_(True))
            .order_by(ModelRecord.id.desc())
        )
        return MonitoringSummary(
            total_flows=flow_counts[0] or 0,
            total_normal=flow_counts[1] or 0,
            total_ddos=flow_counts[2] or 0,
            total_portscan=flow_counts[3] or 0,
            total_alerts=alert_counts[0] or 0,
            active_alerts=alert_counts[1] or 0,
            latest_detection_timestamp=flow_counts[4],
            active_model=active_model,
        )

    @application.get(
        "/api/predictions/{prediction_id}",
        response_model=PredictionDetail,
        summary="Get one prediction",
    )
    def get_prediction(prediction_id: int, db: Db, _: AdminUser):
        row = db.get(Prediction, prediction_id)
        if row is None:
            raise HTTPException(404, "Prediction not found")
        return _prediction_detail(row)

    @application.get("/api/alerts", response_model=list[AlertDetail], summary="List alerts")
    def list_alerts(
        db: Db,
        _: AdminUser,
        limit: int = Query(default_page_size, ge=1, le=settings.max_page_size),
        offset: int = Query(0, ge=0),
        severity: Severity | None = None,
        alert_status: AlertStatus | None = Query(None, alias="status"),
        predicted_label: PredictionLabel | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
    ):
        query = _alert_query(
            severity=severity, alert_status=alert_status, predicted_label=predicted_label,
            source_ip=source_ip, destination_ip=destination_ip,
        )
        rows = db.scalars(query.order_by(Alert.id.desc()).limit(limit).offset(offset)).all()
        return [_alert_detail(row) for row in rows]

    @application.get("/api/export/dataset", summary="Export verified dataset metadata")
    def export_dataset(db: Db, user: AdminUser):
        rows = db.scalars(select(Dataset).order_by(Dataset.id)).all()
        records = [dataset_record(row) for row in rows]
        payload = {
            "metadata": export_metadata(user=user, filters={}, count=len(records)),
            "datasets": records,
        }
        return _download(json_bytes(payload), "rf_nids_dataset.json", "application/json", count=len(records))

    @application.get("/api/export/experiments/{experiment_id}", summary="Export evaluation data")
    def export_experiment(
        experiment_id: int, db: Db, user: AdminUser,
        format: str = Query("json", pattern="^(json|csv)$"),
    ):
        experiment = db.get(Experiment, experiment_id)
        if experiment is None:
            raise HTTPException(404, "Experiment not found")
        evaluations = db.scalars(
            select(EvaluationResult).where(EvaluationResult.experiment_id == experiment_id)
            .order_by(EvaluationResult.metric_key, EvaluationResult.id)
        ).all()
        records = [evaluation_record(row) for row in evaluations]
        suffix = experiment.experiment_code.lower()
        if format == "csv":
            return _download(csv_bytes(EVALUATION_FIELDS, records), f"rf_nids_{suffix}_metrics.csv", "text/csv", count=len(records))
        sources = db.scalars(
            select(EvidenceSource).where(
                EvidenceSource.owner_type == "EXPERIMENT",
                EvidenceSource.owner_key == experiment.experiment_code,
            ).order_by(EvidenceSource.evidence_role, EvidenceSource.id)
        ).all()
        payload = {
            "metadata": export_metadata(user=user, filters={"experiment_id": experiment_id}, count=len(records)),
            "experiment": {
                "experiment_code": experiment.experiment_code,
                "name": experiment.experiment_name,
                "type": experiment.experiment_type,
                "description": experiment.description,
                "status": experiment.status,
                "source_path": experiment.source_path,
                "source_sha256": experiment.source_sha256,
                "schema_version": experiment.schema_version,
                "imported_at": experiment.imported_at,
            },
            "evaluations": records,
            "provenance": [{
                "role": source.evidence_role, "source_path": source.source_path,
                "source_sha256": source.source_sha256, "schema_version": source.schema_version,
                "imported_at": source.imported_at,
            } for source in sources],
        }
        return _download(json_bytes(payload), f"rf_nids_{suffix}_evaluation.json", "application/json", count=len(records))

    @application.get("/api/export/experiments/{experiment_id}/confusion-matrix", summary="Export confusion matrix")
    def export_confusion_matrix(experiment_id: int, db: Db, _: AdminUser):
        experiment = db.get(Experiment, experiment_id)
        if experiment is None:
            raise HTTPException(404, "Experiment not found")
        overall = db.scalar(select(EvaluationResult).where(
            EvaluationResult.experiment_id == experiment_id,
            EvaluationResult.metric_key == "OVERALL",
        ))
        fields, rows = confusion_matrix_rows(overall.confusion_matrix if overall else None)
        if not fields:
            raise HTTPException(404, "Confusion matrix not available")
        filename = f"rf_nids_{experiment.experiment_code.lower()}_confusion_matrix.csv"
        return _download(csv_bytes(fields, rows), filename, "text/csv", count=len(rows))

    @application.get("/api/export/predictions", summary="Export filtered runtime predictions")
    def export_predictions(
        db: Db, user: AdminUser,
        format: str = Query("csv", pattern="^(json|csv)$"),
        predicted_label: PredictionLabel | None = None, source_ip: str | None = None,
        destination_ip: str | None = None, protocol: str | None = None,
    ):
        filters = {"predicted_label": predicted_label.value if predicted_label else None,
                   "source_ip": source_ip, "destination_ip": destination_ip, "protocol": protocol}
        filters = {key: value for key, value in filters.items() if value is not None and value != ""}
        rows = db.scalars(_prediction_query(**filters).order_by(Prediction.id).limit(MAX_EXPORT_RECORDS)).all()
        records = [prediction_record(row) for row in rows]
        filename = f"rf_nids_predictions_{datetime.now(timezone.utc).date().isoformat()}.{format}"
        if format == "json":
            content = json_bytes({"metadata": export_metadata(user=user, filters=filters, count=len(records)), "predictions": records})
            return _download(content, filename, "application/json", count=len(records))
        fields = ["prediction_id", "prediction_time", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "predicted_label", "confidence", "class_probabilities", "model_name", "model_version", "source_type", "experiment_code", "alert_id", "alert_severity", "alert_status"]
        return _download(csv_bytes(fields, records), filename, "text/csv", count=len(records))

    @application.get("/api/export/alerts", summary="Export filtered runtime alerts")
    def export_alerts(
        db: Db, user: AdminUser,
        format: str = Query("csv", pattern="^(json|csv)$"), severity: Severity | None = None,
        alert_status: AlertStatus | None = Query(None, alias="status"),
        predicted_label: PredictionLabel | None = None, source_ip: str | None = None,
        destination_ip: str | None = None,
    ):
        filters = {"severity": severity.value if severity else None,
                   "alert_status": alert_status.value if alert_status else None,
                   "predicted_label": predicted_label.value if predicted_label else None,
                   "source_ip": source_ip, "destination_ip": destination_ip}
        query_filters = {key: value for key, value in filters.items() if value is not None and value != ""}
        rows = db.scalars(_alert_query(**query_filters).order_by(Alert.id).limit(MAX_EXPORT_RECORDS)).all()
        records = [alert_record(row) for row in rows]
        public_filters = {("status" if key == "alert_status" else key): value for key, value in query_filters.items()}
        filename = f"rf_nids_alerts_{datetime.now(timezone.utc).date().isoformat()}.{format}"
        if format == "json":
            content = json_bytes({"metadata": export_metadata(user=user, filters=public_filters, count=len(records)), "alerts": records})
            return _download(content, filename, "application/json", count=len(records))
        fields = ["alert_id", "created_at", "attack_type", "severity", "status", "confidence", "prediction_id", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "acknowledged_at", "acknowledged_by_name", "acknowledged_by_email"]
        return _download(csv_bytes(fields, records), filename, "text/csv", count=len(records))

    @application.get(
        "/api/alerts/{alert_id}", response_model=AlertDetail, summary="Get one alert"
    )
    def get_alert(alert_id: int, db: Db, _: AdminUser):
        row = db.get(Alert, alert_id)
        if row is None:
            raise HTTPException(404, "Alert not found")
        return _alert_detail(row)

    @application.patch(
        "/api/alerts/{alert_id}/acknowledge",
        response_model=AlertDetail,
        summary="Acknowledge an active alert",
    )
    def acknowledge_alert(alert_id: int, db: Db, user: AdminUser):
        row = db.get(Alert, alert_id)
        if row is None:
            raise HTTPException(404, "Alert not found")
        if row.status != "ACKNOWLEDGED":
            row.status = "ACKNOWLEDGED"
            row.acknowledged_at = datetime.now(timezone.utc)
            row.acknowledged_by_user_id = user.id
            db.commit()
            db.refresh(row)
        return _alert_detail(row)

    @application.get(
        "/api/dashboard/summary",
        response_model=DashboardSummary,
        summary="Aggregate dashboard counters",
    )
    def dashboard_summary(db: Db, _: AdminUser):
        prediction_counts = db.execute(
            select(
                func.count(Prediction.id),
                func.sum(case((Prediction.predicted_label == "Normal", 1), else_=0)),
                func.sum(case((Prediction.predicted_label == "DDoS", 1), else_=0)),
                func.sum(case((Prediction.predicted_label == "PortScan", 1), else_=0)),
                func.max(Prediction.prediction_time),
            ).where(_runtime_prediction_clause())
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
            ).where(
                Alert.prediction_id.in_(
                    select(Prediction.id).where(_runtime_prediction_clause())
                )
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
        _: AdminUser,
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
            .where(_runtime_prediction_clause())
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
