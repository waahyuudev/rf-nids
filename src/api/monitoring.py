"""Persistent Phase 9 monitoring lifecycle and safe collector abstraction."""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address
import socket

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.api.models import ModelRecord, MonitoringSession, User

ACTIVE_STATUSES = ("STARTING", "RUNNING", "STOPPING")


class MonitoringConflict(RuntimeError):
    pass


class MonitoringValidation(ValueError):
    pass


class CollectorController:
    """Deterministic lifecycle test double; production uses RuntimeCollectorController."""

    mode = "LIFECYCLE_ONLY"

    def start(self, *, session_id: int, target_ip: str, interface_name: str) -> str:
        return f"lifecycle:{session_id}"

    def stop(self, runtime_handle: str | None) -> None:
        return None

    def status(self, runtime_handle: str | None) -> str:
        return "RUNNING" if runtime_handle else "STOPPED"


def list_capture_interfaces() -> tuple[list[dict], bool]:
    """Return names only; deliberately omit MACs and host configuration."""
    try:
        names = sorted({name for _, name in socket.if_nameindex()})
        return [{"name": name, "is_up": None} for name in names], True
    except (OSError, AttributeError):
        return [], False


class MonitoringService:
    def __init__(self, collector: CollectorController | None = None):
        self.collector = collector or CollectorController()

    @staticmethod
    def active(db: Session) -> MonitoringSession | None:
        return db.scalar(
            select(MonitoringSession)
            .where(MonitoringSession.status.in_(ACTIVE_STATUSES))
            .order_by(MonitoringSession.id.desc())
        )

    def reconcile_stale_sessions(self, db: Session) -> int:
        rows = db.scalars(
            select(MonitoringSession).where(MonitoringSession.status.in_(ACTIVE_STATUSES))
        ).all()
        now = datetime.now(timezone.utc)
        for row in rows:
            row.status = "FAILED"
            row.stopped_at = now
            row.last_error = "API restarted; the prior in-memory controller cannot be recovered."
            row.runtime_handle = None
        if rows:
            db.commit()
        return len(rows)

    def start(self, db: Session, *, target_ip: str, interface_name: str, user: User):
        try:
            address = ip_address(target_ip.strip())
            normalized_ip = str(address)
        except ValueError as exc:
            raise MonitoringValidation("target_ip must be a valid IP address") from exc
        if not address.is_private:
            raise MonitoringValidation("target_ip must be a private laboratory address")
        interface_name = interface_name.strip()
        if not interface_name:
            raise MonitoringValidation("interface_name cannot be empty")
        interfaces, available = list_capture_interfaces()
        if available and interface_name not in {item["name"] for item in interfaces}:
            raise MonitoringValidation("interface_name is not an available local interface")
        if self.active(db) is not None:
            raise MonitoringConflict("A monitoring session is already active")
        model = db.scalar(
            select(ModelRecord).where(ModelRecord.is_active.is_(True)).order_by(ModelRecord.id.desc())
        )
        if model is None:
            raise MonitoringValidation("No active model is available")
        row = MonitoringSession(
            target_ip=normalized_ip,
            interface_name=interface_name,
            model_id=model.id,
            created_by_user_id=user.id,
            status="STARTING",
            extractor_name="CICFlowMeter V3",
            extractor_version="a26aae27f21d165ff30b4b28e75124a5f9b4b2c4",
        )
        db.add(row)
        try:
            db.commit()
            db.refresh(row)
            handle = self.collector.start(
                session_id=row.id, target_ip=normalized_ip, interface_name=interface_name
            )
            db.refresh(row)
            if row.status != "FAILED":
                row.runtime_handle = handle
                row.started_at = datetime.now(timezone.utc)
                row.status = "RUNNING"
                db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise MonitoringConflict("A monitoring session is already active") from exc
        except Exception as exc:
            row.status = "FAILED"
            row.last_error = str(exc)[:2000] or exc.__class__.__name__
            row.stopped_at = datetime.now(timezone.utc)
            row.runtime_handle = None
            db.commit()
        db.refresh(row)
        return row

    def shutdown(self, db: Session) -> None:
        if self.active(db) is not None:
            self.stop(db)

    def stop(self, db: Session):
        row = self.active(db)
        if row is None:
            raise MonitoringConflict("No active monitoring session")
        row.status = "STOPPING"
        db.flush()
        try:
            self.collector.stop(row.runtime_handle)
            row.status = "STOPPED"
            row.last_error = None
        except Exception as exc:
            row.status = "FAILED"
            row.last_error = str(exc)[:2000] or exc.__class__.__name__
        row.runtime_handle = None
        row.stopped_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(row)
        return row
