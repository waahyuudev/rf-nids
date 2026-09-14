"""Persistent Phase 9 monitoring lifecycle and safe collector abstraction."""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
import socket
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.api.models import ModelRecord, MonitoringSession, User

ACTIVE_STATUSES = ("STARTING", "RUNNING", "STOPPING")
RFC1918_NETWORKS = tuple(
    ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


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
            # A STOPPING worker may have already completed its final flush before
            # the API restart.  We cannot prove failure from a lost in-memory
            # handle, so preserve its non-terminal lifecycle state.
            if row.status == "STOPPING":
                continue
            row.status = "FAILED"
            row.stopped_at = now
            row.last_error = "API restarted; the prior in-memory controller cannot be recovered."
            row.runtime_handle = None
        reconciled = sum(row.status != "STOPPING" for row in rows)
        if reconciled:
            db.commit()
        return reconciled

    def start(
        self, db: Session, *, target_ip: str, interface_name: str, user: User,
        model_id: int | None = None,
    ):
        try:
            address = ip_address(target_ip.strip())
            normalized_ip = str(address)
        except ValueError as exc:
            raise MonitoringValidation("target_ip must be a valid IP address") from exc
        if (
            address.version != 4
            or not any(address in network for network in RFC1918_NETWORKS)
            or address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or address.is_link_local
        ):
            raise MonitoringValidation("target_ip must be an RFC1918 private IPv4 laboratory address")
        interface_name = interface_name.strip()
        if not interface_name:
            raise MonitoringValidation("interface_name cannot be empty")
        interfaces, available = list_capture_interfaces()
        if not available:
            raise MonitoringValidation("capture interface discovery is unavailable")
        if interface_name not in {item["name"] for item in interfaces}:
            raise MonitoringValidation("interface_name is not an available local interface")
        if self.active(db) is not None:
            raise MonitoringConflict("A monitoring session is already active")
        model = (
            db.get(ModelRecord, model_id)
            if model_id is not None else
            db.scalar(select(ModelRecord).where(ModelRecord.is_active.is_(True)).order_by(ModelRecord.id.desc()))
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
            artifact_key=uuid4().hex,
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
            row.processing_state = None
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
        if row.status != "STOPPING":
            row.status = "STOPPING"
            # Make STOPPING visible to the worker before waiting.  Holding this
            # transaction during join previously prevented worker finalization.
            db.commit()
            db.refresh(row)
        try:
            stopped = self.collector.stop(row.runtime_handle)
        except Exception as exc:
            # A confirmed worker failure is terminal; an ordinary wait expiry is
            # represented by a false return below and remains STOPPING.
            row.status = "FAILED"
            row.last_error = str(exc)[:2000] or exc.__class__.__name__
            row.runtime_handle = None
            row.processing_state = None
            row.stopped_at = datetime.now(timezone.utc)
            db.commit()
        else:
            # Test/lifecycle collectors predate the boolean contract and return
            # None for an immediately completed stop.
            if stopped is not False:
                db.refresh(row)
                if row.status == "STOPPING":
                    row.status = "STOPPED"
                    row.last_error = None
                    row.runtime_handle = None
                    row.processing_state = None
                    row.stopped_at = datetime.now(timezone.utc)
                    db.commit()
        db.refresh(row)
        return row
