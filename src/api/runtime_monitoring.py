"""Managed tcpdump -> pinned CICFlowMeter V3 -> adapter -> inference worker."""

from __future__ import annotations

import hashlib
import logging
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import threading
import time
from types import SimpleNamespace
from uuid import uuid4
from datetime import datetime, timezone

import pandas as pd
from sqlalchemy import func, select

from src.api.models import Alert, MonitoringSession, Prediction, RuntimeCaptureArtifact
from src.api.monitoring import list_capture_interfaces
from src.api.service import persist_predictions
from src.common.config import PROJECT_ROOT
from src.ingestion.cicflowmeter_v3_adapter import (
    ADAPTER_IDENTITY,
    ADAPTER_VERSION,
    CICFLOWMETER_V3_IMAGE_DIGEST,
    CICFlowMeterV3ModelAdapter,
)
from src.ingestion.live_capture import validate_pcap

logger = logging.getLogger(__name__)


class RuntimePipelineError(RuntimeError):
    pass


class NoTrafficObserved(RuntimeError):
    """A valid capture window contained no packets/flows; this is not failure."""


def validate_runtime_root(path: Path, *, project_root: Path = PROJECT_ROOT) -> Path:
    """Allow runtime evidence only in the dedicated, resolved runtime tree."""
    project = project_root.resolve()
    allowed = (project / "data/runtime/monitoring").resolve()
    resolved = path.resolve()
    if resolved != allowed and allowed not in resolved.parents:
        raise RuntimePipelineError(
            f"Runtime monitoring root must remain under {allowed}"
        )
    if resolved == project:
        raise RuntimePipelineError("Repository root cannot be used for runtime evidence")
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_number(value):
    if pd.isna(value):
        return None
    if hasattr(value, "item"):
        value = value.item()
    return value if not isinstance(value, float) or math.isfinite(value) else None


def _first(row, *names):
    for name in names:
        if name in row and not pd.isna(row[name]):
            return row[name]
    return None


class RuntimePipeline:
    """One-window runtime processor with injectable subprocess primitives."""

    def __init__(
        self, *, root: Path, image: str, window_seconds: float,
        expected_image_digest: str = CICFLOWMETER_V3_IMAGE_DIGEST,
        extraction_timeout_seconds: float = 120.0,
        popen=subprocess.Popen, run=subprocess.run,
    ):
        self.root = root.resolve()
        self.image = image
        self.expected_image_digest = expected_image_digest
        self.window_seconds = window_seconds
        self.extraction_timeout_seconds = extraction_timeout_seconds
        self._popen = popen
        self._run = run
        self._process = None
        self._active_stage = None
        self._process_lock = threading.Lock()
        self.resolved_image_identity = None
        self.tcpdump_path = None

    def preflight(self, interface: str) -> None:
        if self.window_seconds <= 0:
            raise RuntimePipelineError("Capture window duration must be positive")
        tcpdump_path = shutil.which("tcpdump")
        if tcpdump_path is None:
            raise RuntimePipelineError("tcpdump capture executable is unavailable")
        interfaces, available = list_capture_interfaces()
        if not available or interface not in {item["name"] for item in interfaces}:
            raise RuntimePipelineError("Capture interface is no longer available")
        try:
            capture_access = self._run(
                [tcpdump_path, "-i", interface, "-c", "0", "-n"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                text=True, check=False, timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimePipelineError(
                f"Unable to verify packet-capture access on {interface}: {exc}"
            ) from exc
        if capture_access.returncode != 0:
            detail = capture_access.stderr.strip()
            raise RuntimePipelineError(
                f"macOS packet-capture permission is unavailable for interface {interface}. "
                "Grant this user BPF access with the Wireshark ChmodBPF launch daemon, "
                "then log out and back in; do not run FastAPI as root."
                + (f" tcpdump: {detail}" if detail else "")
            )
        self.tcpdump_path = tcpdump_path
        docker = self._run(
            ["docker", "image", "inspect", self.image, "--format", "{{.Id}}"], capture_output=True,
            text=True, check=False, timeout=20,
        )
        if docker.returncode != 0:
            raise RuntimePipelineError("Pinned CICFlowMeter V3 Docker image is unavailable")
        identity = docker.stdout.strip()
        if identity != self.expected_image_digest:
            raise RuntimePipelineError(
                "CICFlowMeter V3 image identity mismatch: "
                f"expected {self.expected_image_digest}, got {identity or '(empty)'}"
            )
        self.resolved_image_identity = identity

    def request_stop(self) -> None:
        with self._process_lock:
            process = self._process
            stage = self._active_stage
        if stage == "CAPTURING" and process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGINT)
            except ProcessLookupError:
                pass

    def _terminate_process(self, process, *, interrupt_first: bool = True) -> None:
        if process.poll() is not None:
            process.wait(timeout=0)
            return
        signals = [signal.SIGINT, signal.SIGTERM, signal.SIGKILL] if interrupt_first else [signal.SIGTERM, signal.SIGKILL]
        timeouts = [10, 5, 5] if interrupt_first else [5, 5]
        for sig, timeout in zip(signals, timeouts, strict=True):
            if process.poll() is not None:
                break
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                break
            try:
                process.wait(timeout=timeout)
                break
            except subprocess.TimeoutExpired:
                continue
        if process.poll() is None:
            raise RuntimePipelineError("Owned subprocess did not terminate cleanly")
        process.wait(timeout=0)

    def force_stop(self) -> None:
        with self._process_lock:
            process = self._process
        if process is not None:
            self._terminate_process(process, interrupt_first=False)

    def capture(self, interface: str, target_ip: str, output: Path, stop: threading.Event):
        names, available = list_capture_interfaces()
        if not available or interface not in {item["name"] for item in names}:
            raise RuntimePipelineError("Capture interface is no longer available")
        if output.exists():
            raise RuntimePipelineError(f"Refusing to overwrite runtime PCAP: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)
        command = [
            self.tcpdump_path or shutil.which("tcpdump") or "tcpdump",
            "-i", interface, "-U", "-n", "-w", str(output),
            "host", target_ip,
        ]
        try:
            process = self._popen(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                text=True, process_group=0,
            )
        except OSError as exc:
            raise RuntimePipelineError(f"Unable to start tcpdump: {exc}") from exc
        with self._process_lock:
            self._process = process
            self._active_stage = "CAPTURING"
        deadline = time.monotonic() + self.window_seconds
        try:
            while process.poll() is None and time.monotonic() < deadline and not stop.wait(0.1):
                pass
            self._terminate_process(process)
        finally:
            with self._process_lock:
                self._process = None
                self._active_stage = None
        if process.returncode not in (0, 130, -signal.SIGINT):
            detail = process.stderr.read().strip() if process.stderr else ""
            raise RuntimePipelineError(f"tcpdump failed ({process.returncode}): {detail}")
        validate_pcap(output)
        if output.stat().st_size <= 24:
            raise NoTrafficObserved("No traffic observed in capture window")

    def extract(self, pcap: Path, output_dir: Path) -> Path:
        if output_dir.exists():
            raise RuntimePipelineError(f"Refusing to overwrite runtime CSV directory: {output_dir}")
        output_dir.mkdir(parents=True, exist_ok=False)
        command = [
            "docker", "run", "--rm", "--platform", "linux/amd64",
            "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--read-only",
            "--tmpfs", "/work:rw,noexec,nosuid,size=64m,uid=10001,gid=10001",
            "--mount", f"type=bind,src={pcap},dst=/input/{pcap.name},readonly",
            "--mount", f"type=bind,src={output_dir.resolve()},dst=/output",
            self.image, f"/input/{pcap.name}", "/output",
        ]
        try:
            process = self._popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                process_group=0,
            )
            with self._process_lock:
                self._process = process
                self._active_stage = "EXTRACTING"
            try:
                stdout, stderr = process.communicate(timeout=self.extraction_timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                self._terminate_process(process)
                raise RuntimePipelineError("CICFlowMeter V3 execution timed out") from exc
            result = SimpleNamespace(returncode=process.returncode, stdout=stdout, stderr=stderr)
        except OSError as exc:
            raise RuntimePipelineError(f"CICFlowMeter V3 execution failed: {exc}") from exc
        finally:
            with self._process_lock:
                self._process = None
                self._active_stage = None
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimePipelineError(f"CICFlowMeter V3 failed: {detail}")
        candidates = sorted(output_dir.glob("*.csv"))
        if len(candidates) != 1 or candidates[0].stat().st_size == 0:
            raise RuntimePipelineError("CICFlowMeter V3 did not produce exactly one flow CSV")
        return candidates[0]


class RuntimeWorker:
    def __init__(self, *, session_id, session_factory, inference, settings, on_exit):
        self.session_id = session_id
        self.session_factory = session_factory
        self.inference = inference
        self.settings = settings
        self.on_exit = on_exit
        self.stop_event = threading.Event()
        self.failure = None
        self.pipeline = RuntimePipeline(
            root=settings.runtime_monitoring_root,
            image=settings.cicflowmeter_v3_image,
            expected_image_digest=getattr(
                settings, "cicflowmeter_v3_image_digest", CICFLOWMETER_V3_IMAGE_DIGEST
            ),
            window_seconds=settings.capture_window_seconds,
            extraction_timeout_seconds=getattr(settings, "extraction_timeout_seconds", 120.0),
        )
        self.thread = threading.Thread(
            target=self._run, name=f"monitoring-{session_id}", daemon=True
        )

    def start(self):
        with self.session_factory() as db:
            row = db.get(MonitoringSession, self.session_id)
            self.pipeline.preflight(row.interface_name)
            row.extractor_identity = self.pipeline.resolved_image_identity
            db.commit()
        self.thread.start()

    def stop(self, timeout: float):
        self.stop_event.set()
        self.pipeline.request_stop()
        self.thread.join(timeout)
        if self.thread.is_alive():
            self.pipeline.force_stop()
            self.thread.join(10)
        if self.thread.is_alive():
            raise RuntimePipelineError("Runtime worker did not stop before timeout")
        if self.failure:
            raise RuntimePipelineError(self.failure)

    def _set_processing_state(self, state: str | None) -> None:
        with self.session_factory() as db:
            row = db.get(MonitoringSession, self.session_id)
            if row is not None and row.status not in ("STOPPED", "FAILED"):
                row.processing_state = state
                db.commit()

    def _fail_artifact(self, artifact_id: int, stage: str, exc: Exception) -> None:
        with self.session_factory() as db:
            artifact = db.get(RuntimeCaptureArtifact, artifact_id)
            if artifact is not None:
                artifact.state = "FAILED"
                artifact.error_stage = stage
                artifact.error_message = (str(exc) or exc.__class__.__name__)[:2000]
                db.commit()

    def _run(self):
        failure = None
        artifact_id = None
        stage = "INITIALIZATION"
        try:
            adapter = CICFlowMeterV3ModelAdapter(self.inference.feature_names)
            with self.session_factory() as db:
                session = db.get(MonitoringSession, self.session_id)
                session_root = Path(session.artifact_root)
            pcap_root, flow_root = session_root / "pcap", session_root / "flows"
            segment = 0
            while not self.stop_event.is_set():
                segment += 1
                pcap = pcap_root / f"window-{segment:06d}.pcap"
                csv_dir = flow_root / f"window-{segment:06d}"
                with self.session_factory() as db:
                    row = db.get(MonitoringSession, self.session_id)
                    if row is None or row.status not in ("STARTING", "RUNNING"):
                        break
                    interface, target = row.interface_name, row.target_ip
                    artifact = RuntimeCaptureArtifact(
                        monitoring_session_id=self.session_id,
                        artifact_key=uuid4().hex,
                        window_number=segment,
                        state="CAPTURING",
                        pcap_relative_path=str(pcap.relative_to(session_root)),
                        extractor_identity=row.extractor_identity,
                        capture_started_at=datetime.now(timezone.utc),
                    )
                    row.processing_state = "CAPTURING"
                    db.add(artifact)
                    db.commit()
                    artifact_id = artifact.id
                logger.info("monitoring_capture_start session=%s window=%s", self.session_id, segment)
                stage = "CAPTURE"
                try:
                    self.pipeline.capture(interface, target, pcap, self.stop_event)
                    with self.session_factory() as db:
                        artifact = db.get(RuntimeCaptureArtifact, artifact_id)
                        artifact.state = "CAPTURED"
                        artifact.pcap_sha256 = _sha256(pcap)
                        artifact.pcap_size = pcap.stat().st_size
                        artifact.capture_finished_at = datetime.now(timezone.utc)
                        db.commit()
                except NoTrafficObserved as exc:
                    with self.session_factory() as db:
                        artifact = db.get(RuntimeCaptureArtifact, artifact_id)
                        artifact.state = "FAILED"
                        artifact.error_stage = "NO_TRAFFIC"
                        artifact.error_message = str(exc)
                        artifact.pcap_sha256 = _sha256(pcap)
                        artifact.pcap_size = pcap.stat().st_size
                        artifact.capture_finished_at = datetime.now(timezone.utc)
                        db.commit()
                    self._set_processing_state(None)
                    logger.info("monitoring_no_traffic session=%s window=%s", self.session_id, segment)
                    continue
                except Exception as exc:
                    self._fail_artifact(artifact_id, stage, exc)
                    raise
                self._set_processing_state("EXTRACTING")
                stage = "EXTRACTION"
                try:
                    csv_path = self.pipeline.extract(pcap, csv_dir)
                except Exception as exc:
                    self._fail_artifact(artifact_id, stage, exc)
                    raise
                logger.info("monitoring_extraction_complete session=%s window=%s", self.session_id, segment)
                raw = pd.read_csv(csv_path)
                stage = "ADAPTATION"
                if raw.empty:
                    logger.info("monitoring_no_flows session=%s window=%s", self.session_id, segment)
                    with self.session_factory() as db:
                        artifact = db.get(RuntimeCaptureArtifact, artifact_id)
                        artifact.state = "COMMITTED"
                        artifact.csv_relative_path = str(csv_path.relative_to(session_root))
                        artifact.csv_sha256 = _sha256(csv_path)
                        artifact.csv_size = csv_path.stat().st_size
                        artifact.extraction_finished_at = datetime.now(timezone.utc)
                        artifact.committed_at = datetime.now(timezone.utc)
                        db.commit()
                    self._set_processing_state(None)
                    continue
                adapted = adapter.adapt(raw, raw_input_path=csv_path, raw_input_sha256=_sha256(csv_path))
                with self.session_factory() as db:
                    artifact = db.get(RuntimeCaptureArtifact, artifact_id)
                    artifact.state = "EXTRACTED"
                    artifact.csv_relative_path = str(csv_path.relative_to(session_root))
                    artifact.csv_sha256 = _sha256(csv_path)
                    artifact.csv_size = csv_path.stat().st_size
                    artifact.extracted_row_count = len(raw)
                    artifact.adapted_row_count = len(adapted.features)
                    artifact.extraction_finished_at = datetime.now(timezone.utc)
                    db.commit()
                requests, keys = [], []
                artifact_hash = _sha256(pcap)
                for position, (_, features) in enumerate(adapted.features.iterrows(), 1):
                    raw_row = raw.iloc[position - 1]
                    metadata = {
                        "capture_session_id": str(self.session_id),
                        "capture_interface": interface,
                        "pcap_segment": pcap.name,
                        "source_ip": _first(raw_row, "Src IP", "Source IP"),
                        "source_port": _safe_number(_first(raw_row, "Src Port", "Source Port")),
                        "destination_ip": _first(raw_row, "Dst IP", "Destination IP"),
                        "destination_port": _safe_number(_first(raw_row, "Dst Port", "Destination Port")),
                        "protocol": str(_first(raw_row, "Protocol") or "") or None,
                    }
                    values = {name: _safe_number(value) for name, value in features.items()}
                    requests.append(
                        SimpleNamespace(
                            features=values,
                            metadata=SimpleNamespace(model_dump=lambda m=metadata: m),
                        )
                    )
                    keys.append(f"monitoring:{self.session_id}:{segment}:{artifact_hash}:{position}")
                self._set_processing_state("COMMITTING")
                stage = "INFERENCE_COMMIT"
                outputs = self.inference.predict_batch([item.features for item in requests])
                with self.session_factory() as db:
                    existing = set(
                        db.scalars(
                            select(Prediction.external_key).where(
                                Prediction.external_key.in_(keys)
                            )
                        ).all()
                    )
                    selected = [
                        (request, output, key)
                        for request, output, key in zip(
                            requests, outputs, keys, strict=True
                        )
                        if key not in existing
                    ]
                    if selected:
                        persist_predictions(
                            db, [item[0] for item in selected], [item[1] for item in selected],
                            db.get(MonitoringSession, self.session_id).model_id,
                            monitoring_session_id=self.session_id,
                            runtime_artifact_id=artifact_id,
                            external_keys=[item[2] for item in selected],
                            commit=False,
                        )
                    artifact = db.get(RuntimeCaptureArtifact, artifact_id)
                    artifact.state = "COMMITTED"
                    artifact.committed_at = datetime.now(timezone.utc)
                    db.commit()
                    self._refresh_counts(db)
                logger.info(
                    "monitoring_inference_complete session=%s flows=%s",
                    self.session_id,
                    len(selected),
                )
                self._set_processing_state(None)
        except Exception as exc:
            if artifact_id is not None:
                self._fail_artifact(artifact_id, stage, exc)
            failure = str(exc)[:2000] or exc.__class__.__name__
            self.failure = failure
            logger.exception("monitoring_worker_failed session=%s", self.session_id)
            with self.session_factory() as db:
                row = db.get(MonitoringSession, self.session_id)
                if row and row.status not in ("STOPPING", "STOPPED"):
                    row.status = "FAILED"
                    row.last_error = failure
                    row.stopped_at = datetime.now(timezone.utc)
                    row.runtime_handle = None
                    row.processing_state = None
                    db.commit()
        finally:
            self._set_processing_state(None)
            self.on_exit(self.session_id, failure)

    def _refresh_counts(self, db):
        row = db.get(MonitoringSession, self.session_id)
        prediction_count = db.scalar(
            select(func.count(Prediction.id)).where(
                Prediction.monitoring_session_id == self.session_id
            )
        ) or 0
        alert_count = db.scalar(
            select(func.count(Alert.id)).join(Prediction).where(
                Prediction.monitoring_session_id == self.session_id
            )
        ) or 0
        row.flow_count = prediction_count
        row.prediction_count = prediction_count
        row.alert_count = alert_count
        row.latest_processing_at = datetime.now(timezone.utc)
        db.commit()


class RuntimeCollectorController:
    mode = "RUNTIME_V3"

    def __init__(self, *, session_factory, inference, settings, worker_factory=RuntimeWorker):
        self.session_factory = session_factory
        self.inference = inference
        self.settings = settings
        self.worker_factory = worker_factory
        self._workers = {}
        self._lock = threading.Lock()
        self.runtime_root = validate_runtime_root(
            settings.runtime_monitoring_root,
            project_root=getattr(settings, "project_root", PROJECT_ROOT),
        )

    def start(self, *, session_id: int, target_ip: str, interface_name: str) -> str:
        handle = uuid4().hex
        with self.session_factory() as db:
            row = db.get(MonitoringSession, session_id)
            if row is None or not row.artifact_key:
                raise RuntimePipelineError("Monitoring session artifact identity is unavailable")
            session_root = self.runtime_root / f"{session_id}-{row.artifact_key}"
            try:
                session_root.mkdir(parents=True, exist_ok=False)
            except FileExistsError as exc:
                raise RuntimePipelineError(
                    f"Refusing to overwrite existing runtime session directory: {session_root}"
                ) from exc
            row.artifact_root = str(session_root)
            db.commit()
        worker = self.worker_factory(
            session_id=session_id, session_factory=self.session_factory,
            inference=self.inference, settings=self.settings, on_exit=self._on_exit,
        )
        try:
            worker.start()
        except Exception:
            raise
        with self._lock:
            self._workers[handle] = worker
        return handle

    def stop(self, runtime_handle: str | None) -> None:
        with self._lock:
            worker = self._workers.get(runtime_handle)
        if worker is None:
            raise RuntimePipelineError("Runtime worker handle is unavailable")
        timeout = max(
            self.settings.capture_stop_timeout_seconds,
            getattr(self.settings, "extraction_timeout_seconds", 120.0) + 20.0,
        )
        worker.stop(timeout)
        with self._lock:
            self._workers.pop(runtime_handle, None)

    def status(self, runtime_handle: str | None) -> str:
        with self._lock:
            worker = self._workers.get(runtime_handle)
        return "RUNNING" if worker and worker.thread.is_alive() else "STOPPED"

    def shutdown(self):
        with self._lock:
            workers = list(self._workers.values())
        for worker in workers:
            try:
                worker.stop(self.settings.capture_stop_timeout_seconds)
            except Exception:
                logger.exception("monitoring_worker_shutdown_failed")

    def _on_exit(self, session_id, failure):
        logger.info("monitoring_worker_exit session=%s failed=%s", session_id, bool(failure))
