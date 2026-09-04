"""Phase 11 server-side runtime validation evidence aggregation."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.api.models import Alert, MonitoringSession, Prediction, RuntimeValidationRun, TrafficFlow
from src.ingestion.cicflowmeter_v3_adapter import (
    ADAPTER_IDENTITY, ADAPTER_VERSION, CICFLOWMETER_V3_IMAGE_DIGEST,
)

SCENARIOS = {"NORMAL_HTTP", "PORTSCAN", "STOP_RESTART"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class RuntimeValidationService:
    def __init__(self, artifact_root: Path, expected_feature_names: list[str]):
        self.artifact_root = artifact_root
        self.expected_feature_names = tuple(expected_feature_names)

    def create(self, db: Session, session_id: int, scenario: str) -> RuntimeValidationRun:
        session = db.get(MonitoringSession, session_id)
        if session is None:
            raise LookupError("Monitoring session not found")
        if scenario not in SCENARIOS:
            raise ValueError("scenario must be NORMAL_HTTP, PORTSCAN, or STOP_RESTART")
        row = RuntimeValidationRun(
            monitoring_session_id=session.id, scenario=scenario, status="RUNNING",
            target_ip=session.target_ip, interface_name=session.interface_name,
            model_id=session.model_id, model_version=session.model.model_version,
            extractor_identity=(
                f"{session.extractor_name or 'CICFlowMeter V3'}:"
                f"{session.extractor_version or CICFLOWMETER_V3_IMAGE_DIGEST}"
            ),
            adapter_identity=f"{ADAPTER_IDENTITY}:{ADAPTER_VERSION}",
            evidence_json={},
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    def complete(self, db: Session, session_id: int, validation_id: int) -> RuntimeValidationRun:
        row = db.get(RuntimeValidationRun, validation_id)
        if row is None or row.monitoring_session_id != session_id:
            raise LookupError("Validation run not found for monitoring session")
        if row.status in ("COMPLETED", "FAILED"):
            return row
        try:
            self._derive(db, row)
            row.status = "COMPLETED"
        except Exception as exc:
            row.status = "FAILED"
            row.pipeline_result = "FAIL"
            row.detection_result = "NOT_EVALUATED"
            row.notes = (str(exc) or exc.__class__.__name__)[:2000]
            row.evidence_json = {"error": row.notes}
        row.finished_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(row)
        return row

    def _derive(self, db: Session, row: RuntimeValidationRun) -> None:
        session = db.get(MonitoringSession, row.monitoring_session_id)
        predictions = db.scalars(
            select(Prediction).where(
                Prediction.monitoring_session_id == row.monitoring_session_id,
                Prediction.prediction_time >= row.started_at,
            ).order_by(Prediction.id)
        ).all()
        prediction_ids = [item.id for item in predictions]
        flows = [item.traffic_flow for item in predictions]
        segments = {flow.pcap_segment for flow in flows if flow.pcap_segment}
        artifacts = []
        session_root = (self.artifact_root / str(row.monitoring_session_id)).resolve()
        raw_rows = 0
        flow_root = session_root / "flows"
        if flow_root.is_dir():
            for csv_path in flow_root.glob("window-*/*.csv"):
                if csv_path.stat().st_mtime >= row.started_at.timestamp():
                    segments.add(f"{csv_path.parent.name}.pcap")
                    raw_rows += len(pd.read_csv(csv_path))
        segments = sorted(segments)
        for segment in segments:
            path = (session_root / "pcap" / Path(segment).name).resolve()
            if session_root not in path.parents or not path.is_file():
                continue
            artifacts.append({"filename": path.name, "sha256": _sha256(path), "bytes": path.stat().st_size})

        labels = {label: 0 for label in ("Normal", "PortScan", "DDoS")}
        for item in predictions:
            labels[item.predicted_label] = labels.get(item.predicted_label, 0) + 1
        alerts = 0
        if prediction_ids:
            alerts = db.scalar(select(func.count(Alert.id)).where(Alert.prediction_id.in_(prediction_ids))) or 0
        adapter_valid = sum(
            1 for flow in flows
            if isinstance(flow.raw_features, dict)
            and len(self.expected_feature_names) == 78
            and tuple(flow.raw_features) == self.expected_feature_names
        )
        target_matches = sum(
            1 for flow in flows
            if row.target_ip in (flow.source_ip, flow.destination_ip)
        )

        row.pcap_files_processed = len(artifacts)
        row.pcap_bytes_processed = sum(item["bytes"] for item in artifacts)
        row.flows_extracted = raw_rows
        row.flows_adapter_valid = adapter_valid
        row.predictions_committed = len(predictions)
        row.alerts_committed = alerts
        row.normal_predictions = labels["Normal"]
        row.portscan_predictions = labels["PortScan"]
        row.ddos_predictions = labels["DDoS"]

        probability_summary = {}
        for label in labels:
            values = [float(p.class_probabilities[label]) for p in predictions if label in (p.class_probabilities or {})]
            probability_summary[label] = ({"mean": sum(values) / len(values), "min": min(values), "max": max(values)} if values else None)

        core_pass = bool(
            artifacts and raw_rows > 0 and adapter_valid > 0
            and predictions and target_matches > 0
        )
        model_matches = all(p.model_id == session.model_id for p in predictions)
        if row.scenario == "STOP_RESTART":
            next_session = db.scalar(select(MonitoringSession).where(
                MonitoringSession.id != session.id,
                MonitoringSession.created_at > row.started_at,
            ).order_by(MonitoringSession.created_at, MonitoringSession.id))
            stale = db.scalar(select(func.count(Prediction.id)).where(
                Prediction.monitoring_session_id == session.id,
                Prediction.prediction_time > session.stopped_at,
            )) if session.stopped_at else None
            lifecycle_pass = bool(
                session.status == "STOPPED" and session.runtime_handle is None and
                session.latest_processing_at is not None and
                session.latest_processing_at >= row.started_at and
                next_session is not None and next_session.status in ("STARTING", "RUNNING", "STOPPING", "STOPPED") and
                stale == 0
            )
            row.pipeline_result = "PASS" if lifecycle_pass else "FAIL"
            row.detection_result = "NOT_APPLICABLE"
            lifecycle = {"first_session_status": session.status, "owned_runtime_handle_cleared": session.runtime_handle is None,
                         "second_session_id": next_session.id if next_session else None, "stale_predictions_after_stop": stale}
        else:
            row.pipeline_result = "PASS" if core_pass and model_matches else "FAIL"
            if not predictions:
                row.detection_result = "NOT_EVALUATED"
            elif row.scenario == "PORTSCAN":
                row.detection_result = "PASS" if labels["PortScan"] > 0 else "FAIL"
            else:
                row.detection_result = "PASS" if labels["Normal"] * 2 >= len(predictions) else "FAIL"
            lifecycle = None
        row.evidence_json = {
            "pcaps": artifacts, "pcap_segments": segments,
            "prediction_id_range": [prediction_ids[0], prediction_ids[-1]] if prediction_ids else None,
            "prediction_ids": prediction_ids, "alert_count": alerts,
            "label_distribution": labels, "class_probability_summary": probability_summary,
            "expected_feature_count": len(self.expected_feature_names),
            "expected_feature_order_sha256": hashlib.sha256(
                "\n".join(self.expected_feature_names).encode("utf-8")
            ).hexdigest(),
            "session_model_matches": model_matches,
            "flows_matching_configured_target": target_matches,
            "lifecycle": lifecycle,
        }
