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

from src.api.models import Alert, MonitoringSession, Prediction
from src.api.service import persist_predictions
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
        popen=subprocess.Popen, run=subprocess.run,
    ):
        self.root = root.resolve()
        self.image = image
        self.window_seconds = window_seconds
        self._popen = popen
        self._run = run
        self._process = None
        self._process_lock = threading.Lock()

    def preflight(self) -> None:
        if self.window_seconds <= 0:
            raise RuntimePipelineError("Capture window duration must be positive")
        if shutil.which("tcpdump") is None:
            raise RuntimePipelineError("tcpdump capture executable is unavailable")
        docker = self._run(
            ["docker", "image", "inspect", self.image], capture_output=True,
            text=True, check=False, timeout=20,
        )
        if docker.returncode != 0:
            raise RuntimePipelineError("Pinned CICFlowMeter V3 Docker image is unavailable")

    def request_stop(self) -> None:
        with self._process_lock:
            process = self._process
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGINT)
            except ProcessLookupError:
                pass

    def capture(self, interface: str, target_ip: str, output: Path, stop: threading.Event):
        output.parent.mkdir(parents=True, exist_ok=True)
        command = [
            "tcpdump", "-i", interface, "-U", "-n", "-w", str(output),
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
        deadline = time.monotonic() + self.window_seconds
        try:
            while process.poll() is None and time.monotonic() < deadline and not stop.wait(0.1):
                pass
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired as exc:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                    raise RuntimePipelineError("tcpdump did not terminate cleanly") from exc
        finally:
            with self._process_lock:
                self._process = None
        if process.returncode not in (0, 130, -signal.SIGINT):
            detail = process.stderr.read().strip() if process.stderr else ""
            raise RuntimePipelineError(f"tcpdump failed ({process.returncode}): {detail}")
        validate_pcap(output)
        if output.stat().st_size <= 24:
            raise NoTrafficObserved("No traffic observed in capture window")

    def extract(self, pcap: Path, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
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
            result = self._run(
                command, capture_output=True, text=True, check=False, timeout=120
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimePipelineError(f"CICFlowMeter V3 execution failed: {exc}") from exc
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
        self.pipeline = RuntimePipeline(
            root=settings.runtime_monitoring_root,
            image=settings.cicflowmeter_v3_image,
            window_seconds=settings.capture_window_seconds,
        )
        self.thread = threading.Thread(
            target=self._run, name=f"monitoring-{session_id}", daemon=True
        )

    def start(self):
        self.pipeline.preflight()
        self.thread.start()

    def stop(self, timeout: float):
        self.stop_event.set()
        self.pipeline.request_stop()
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise RuntimePipelineError("Runtime worker did not stop before timeout")

    def _run(self):
        failure = None
        try:
            adapter = CICFlowMeterV3ModelAdapter(self.inference.feature_names)
            session_root = self.settings.runtime_monitoring_root / str(self.session_id)
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
                logger.info("monitoring_capture_start session=%s window=%s", self.session_id, segment)
                try:
                    self.pipeline.capture(interface, target, pcap, self.stop_event)
                except NoTrafficObserved:
                    logger.info("monitoring_no_traffic session=%s window=%s", self.session_id, segment)
                    continue
                if self.stop_event.is_set():
                    break
                csv_path = self.pipeline.extract(pcap, csv_dir)
                logger.info("monitoring_extraction_complete session=%s window=%s", self.session_id, segment)
                raw = pd.read_csv(csv_path)
                if raw.empty:
                    logger.info("monitoring_no_flows session=%s window=%s", self.session_id, segment)
                    continue
                adapted = adapter.adapt(raw, raw_input_path=csv_path, raw_input_sha256=_sha256(csv_path))
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
                if self.stop_event.is_set():
                    break
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
                            external_keys=[item[2] for item in selected],
                        )
                    self._refresh_counts(db)
                logger.info(
                    "monitoring_inference_complete session=%s flows=%s",
                    self.session_id,
                    len(selected),
                )
        except Exception as exc:
            failure = str(exc)[:2000] or exc.__class__.__name__
            logger.exception("monitoring_worker_failed session=%s", self.session_id)
            with self.session_factory() as db:
                row = db.get(MonitoringSession, self.session_id)
                if row and row.status not in ("STOPPING", "STOPPED"):
                    row.status = "FAILED"
                    row.last_error = failure
                    row.stopped_at = datetime.now(timezone.utc)
                    row.runtime_handle = None
                    db.commit()
        finally:
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

    def start(self, *, session_id: int, target_ip: str, interface_name: str) -> str:
        handle = uuid4().hex
        worker = self.worker_factory(
            session_id=session_id, session_factory=self.session_factory,
            inference=self.inference, settings=self.settings, on_exit=self._on_exit,
        )
        worker.start()
        with self._lock:
            self._workers[handle] = worker
        return handle

    def stop(self, runtime_handle: str | None) -> None:
        with self._lock:
            worker = self._workers.get(runtime_handle)
        if worker is None:
            raise RuntimePipelineError("Runtime worker handle is unavailable")
        worker.stop(self.settings.capture_stop_timeout_seconds)
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
