"""macOS near-real-time capture using short tcpdump PCAP segments."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .api_sender import ApiSender
from .cicflowmeter_mapping import CICIDS2017_DATASET_ARTIFACT_REPRODUCTION
from .feature_adapter import FeatureAdapter, FeatureCompatibilityError
from .flow_extractor import FlowCsvExtractor
from .models import AdaptedFlow
from .offline_validation import DashboardApiVerifier, EXTRACTOR_NAME, EXTRACTOR_VERSION

logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SESSION_ID_RE = re.compile(r"^\d{8}T\d{6}Z_[0-9a-f]{6}$")


class LiveCaptureError(RuntimeError):
    """A live capture prerequisite or pipeline stage failed."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_session_id(now: datetime | None = None) -> str:
    current = (now or utc_now()).astimezone(timezone.utc)
    return f"{current:%Y%m%dT%H%M%SZ}_{uuid.uuid4().hex[:6]}"


def list_interfaces(*, run: Callable[..., Any] = subprocess.run) -> list[str]:
    """Return interface names reported by macOS/BSD ifconfig."""
    try:
        result = run(["ifconfig", "-l"], capture_output=True, text=True, check=False)
    except OSError as exc:
        raise LiveCaptureError(f"Unable to run ifconfig: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise LiveCaptureError(f"Interface discovery failed: {detail}")
    return [name for name in result.stdout.split() if name]


def validate_interface(interface: str, interfaces: Iterable[str]) -> str:
    available = list(interfaces)
    if not interface or interface not in available:
        raise LiveCaptureError(
            f"Capture interface '{interface}' does not exist; available: "
            f"{', '.join(available) or '(none)'}"
        )
    return interface


def discover_pcap_segments(directory: Path) -> list[Path]:
    return sorted(
        (path for path in directory.glob("segment-*.pcap") if path.is_file()),
        key=lambda path: path.name,
    )


def flow_fingerprint(flow: AdaptedFlow) -> str:
    """Identify a flow from provenance/5-tuple/time, never from RF values alone."""
    metadata = flow.metadata
    identity = {
        "capture_session_id": metadata.get("capture_session_id"),
        "source_ip": metadata.get("source_ip"),
        "destination_ip": metadata.get("destination_ip"),
        "source_port": metadata.get("source_port"),
        "destination_port": metadata.get("destination_port"),
        "protocol": metadata.get("protocol"),
        "timestamp": metadata.get("capture_time"),
        "duration": flow.features.get("flow_duration"),
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


class BoundedDeduplicator:
    def __init__(self, capacity: int = 50_000) -> None:
        if capacity < 1:
            raise ValueError("dedup capacity must be positive")
        self.capacity = capacity
        self._order: deque[str] = deque()
        self._seen: set[str] = set()

    def add(self, fingerprint: str) -> bool:
        """Return True for a new fingerprint and False for a duplicate."""
        if fingerprint in self._seen:
            return False
        if len(self._order) >= self.capacity:
            self._seen.remove(self._order.popleft())
        self._order.append(fingerprint)
        self._seen.add(fingerprint)
        return True


def new_live_report(session_id: str, interface: str, started_at: datetime) -> dict[str, Any]:
    return {
        "status": "failed",
        "validation_type": "live_normal_traffic",
        "session_id": session_id,
        "capture": {
            "interface": interface,
            "started_at": started_at.isoformat(),
            "ended_at": None,
            "duration_seconds": 0,
            "segments": 0,
        },
        "extractor": {"name": EXTRACTOR_NAME, "version": EXTRACTOR_VERSION},
        "compatibility_policy": CICIDS2017_DATASET_ARTIFACT_REPRODUCTION,
        "feature_schema": {"required": 78, "produced": 0, "missing": 78},
        "flows": {
            "extracted": 0, "unique": 0, "duplicates_skipped": 0,
            "submitted": 0, "successful": 0, "failed": 0,
        },
        "predictions": {"Normal": 0, "DDoS": 0, "PortScan": 0},
        "observed_normal_prediction_rate": 0.0,
        "observed_attack_prediction_count": 0,
        "candidate_false_positive_rate": 0.0,
        "normal_traffic_false_positive_candidates": 0,
        "alerts_created": 0,
        "api": {"reachable": False},
        "database_persistence_verified": False,
        "dashboard_api_data_available": False,
        "failures": [],
        "limitations": [
            "near-real-time flow processing using short PCAP segments; not inline inspection or prevention",
            "hieulw/cicflowmeter differs from historical Java CICFlowMeter",
            "schema compatibility does not prove perfect numerical parity",
            "CICIDS2017 dataset-artifact reproduction policy remains active",
            "this controlled normal-session result is not final model accuracy or false-positive rate",
        ],
    }


def write_live_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


class DockerSegmentExtractor:
    def __init__(self, root: Path = PROJECT_ROOT, run: Callable[..., Any] = subprocess.run):
        self.root = root.resolve()
        self._run = run

    def extract(self, pcap: Path, csv_path: Path) -> Path:
        live_root = (self.root / "data/lab/live").resolve()
        try:
            pcap.resolve().relative_to(live_root)
            csv_path.resolve().relative_to(live_root)
        except ValueError as exc:
            raise LiveCaptureError("Live PCAP and CSV must remain under data/lab/live") from exc
        if not pcap.is_file() or pcap.stat().st_size == 0:
            raise LiveCaptureError(f"Captured PCAP is empty or missing: {pcap}")
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        result = self._run(
            [
                "docker", "compose", "--profile", "tools", "run", "--rm",
                "--volume", f"{pcap.parent.resolve()}:/input:ro",
                "--volume", f"{csv_path.parent.resolve()}:/output",
                "cicflowmeter", f"/input/{pcap.name}", f"/output/{csv_path.name}",
            ],
            cwd=self.root, capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise LiveCaptureError(f"CICFlowMeter extraction failed: {detail}")
        if not csv_path.is_file() or csv_path.stat().st_size == 0:
            raise LiveCaptureError("Extractor did not create a non-empty flow CSV")
        return csv_path


def capture_segment(
    interface: str,
    output: Path,
    seconds: float,
    *,
    popen: Callable[..., Any] = subprocess.Popen,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    kill_process_group: Callable[[int, int], None] = os.killpg,
) -> bool:
    """Capture one segment. Return False when Ctrl+C requested a graceful stop."""
    output.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Starting tcpdump on %s", interface)
    process = popen(
        ["sudo", "-n", "tcpdump", "-i", interface, "-U", "-w", str(output)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        # A separate process group lets us signal sudo + tcpdump together, while
        # retaining the caller's controlling TTY for macOS sudo timestamp lookup.
        process_group=0,
    )
    interrupted = False

    def stop_process_group() -> None:
        if process.poll() is not None:
            return
        logger.info("Stopping tcpdump with SIGINT")
        kill_process_group(process.pid, signal.SIGINT)
        try:
            process.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            logger.warning("tcpdump did not exit after SIGINT; sending SIGTERM")
        kill_process_group(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            logger.warning("tcpdump did not exit after SIGTERM; sending SIGKILL")
        kill_process_group(process.pid, signal.SIGKILL)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise LiveCaptureError("tcpdump process group remained alive after SIGKILL") from exc

    try:
        logger.info("Capturing for %.1f seconds", seconds)
        deadline = monotonic() + seconds
        while process.poll() is None and monotonic() < deadline:
            sleep(min(0.25, max(0.0, deadline - monotonic())))
    except KeyboardInterrupt:
        interrupted = True
        logger.info("Ctrl+C received during capture; finalizing current PCAP")
    finally:
        stop_process_group()

    if process.poll() is None:
        raise LiveCaptureError("tcpdump process is still running after segment shutdown")
    if process.returncode not in (0, 130, -signal.SIGINT):
        detail = process.stderr.read().strip() if process.stderr else ""
        raise LiveCaptureError(f"tcpdump failed ({process.returncode}): {detail}")
    validate_pcap(output)
    logger.info("PCAP finalized: %s", output.name)
    return not interrupted


def validate_pcap(path: Path) -> Path:
    """Validate a finalized classic PCAP/PCAPNG header before extraction."""
    if not path.is_file():
        raise LiveCaptureError(f"Captured PCAP does not exist: {path}")
    if path.stat().st_size < 24:
        raise LiveCaptureError(
            f"Captured PCAP is too small to contain a valid header: {path}"
        )
    with path.open("rb") as handle:
        magic = handle.read(4)
    valid_magic = {
        b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
        b"\x0a\x0d\x0d\x0a",
    }
    if magic not in valid_magic:
        raise LiveCaptureError(f"Captured file is not a readable PCAP/PCAPNG: {path}")
    return path


def preflight(
    interface: str,
    api_url: str,
    metadata_path: Path,
    *,
    verifier: DashboardApiVerifier,
    run: Callable[..., Any] = subprocess.run,
) -> tuple[FeatureAdapter, dict[str, Any]]:
    if platform.system() != "Darwin":
        logger.warning("This runner is designed for macOS; detected %s", platform.system())
    validate_interface(interface, list_interfaces(run=run))
    if shutil.which("tcpdump") is None:
        raise LiveCaptureError("tcpdump is not installed or not on PATH")
    sudo = run(
        ["sudo", "-n", "tcpdump", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if sudo.returncode != 0:
        raise LiveCaptureError(
            "sudo authorization for tcpdump is unavailable; run 'sudo -v' in this "
            "terminal immediately before starting the live capture"
        )
    health = verifier.health()
    if health.get("model_loaded") is not True:
        raise LiveCaptureError("API health reports that the active model is not loaded")
    model_response = verifier._json("/api/model")
    if int(model_response.get("feature_count", 0)) != 78:
        raise LiveCaptureError("Active API model does not expose the required 78 features")
    docker = run(
        ["docker", "compose", "--profile", "tools", "config", "--services"],
        cwd=PROJECT_ROOT, capture_output=True, text=True, check=False,
    )
    if docker.returncode != 0 or "cicflowmeter" not in docker.stdout.split():
        raise LiveCaptureError("Docker CICFlowMeter extractor service is unavailable")
    adapter = FeatureAdapter.from_metadata(
        metadata_path,
        compatibility_policy=CICIDS2017_DATASET_ARTIFACT_REPRODUCTION,
    )
    if len(adapter.feature_names) != 78:
        raise LiveCaptureError("Local active-model metadata does not contain 78 features")
    return adapter, health


def finalize_report(
    report: dict[str, Any], started_at: datetime, before: dict[str, Any] | None,
    verifier: DashboardApiVerifier | None, prediction_ids: set[int], output: Path,
) -> dict[str, Any]:
    ended = utc_now()
    report["capture"]["ended_at"] = ended.isoformat()
    report["capture"]["duration_seconds"] = round((ended - started_at).total_seconds(), 3)
    successful = report["flows"]["successful"]
    attacks = report["predictions"]["DDoS"] + report["predictions"]["PortScan"]
    report["observed_attack_prediction_count"] = attacks
    report["normal_traffic_false_positive_candidates"] = attacks
    if successful:
        report["observed_normal_prediction_rate"] = report["predictions"]["Normal"] / successful
        report["candidate_false_positive_rate"] = attacks / successful
    try:
        if verifier is not None and before is not None and prediction_ids:
            after = verifier.summary()
            persisted = verifier.prediction_ids(prediction_ids)
            delta = int(after["total_flows"]) - int(before["total_flows"])
            report["database_persistence_verified"] = delta == successful and prediction_ids <= persisted
            report["dashboard_api_data_available"] = report["database_persistence_verified"]
            before_alerts = int(before["active_alerts"]) + int(before["acknowledged_alerts"])
            after_alerts = int(after["active_alerts"]) + int(after["acknowledged_alerts"])
            report["alerts_created"] = max(0, after_alerts - before_alerts)
    except Exception as exc:
        report["failures"].append({"stage": "final_verification", "error": str(exc)})
    passed = (
        report["capture"]["segments"] > 0
        and report["flows"]["extracted"] > 0
        and report["feature_schema"] == {"required": 78, "produced": 78, "missing": 0}
        and successful > 0
        and report["flows"]["failed"] == 0
        and report["database_persistence_verified"]
        and report["dashboard_api_data_available"]
    )
    report["status"] = "completed" if passed else "failed"
    if not passed and not report["failures"]:
        report["failures"].append({"stage": "gate", "error": "One or more validation gates were not satisfied"})
    write_live_report(report, output)
    return report


def run_live_capture(
    *, interface: str, segment_seconds: float, api_url: str, output_dir: Path,
    metadata_path: Path, report_path: Path, batch_size: int = 100,
    max_segments: int | None = None, dedup_capacity: int = 50_000,
    sender: ApiSender | None = None, verifier: DashboardApiVerifier | None = None,
    extractor: DockerSegmentExtractor | None = None,
    capture: Callable[[str, Path, float], bool] = capture_segment,
    skip_preflight: bool = False,
) -> dict[str, Any]:
    if segment_seconds <= 0 or batch_size < 1 or (max_segments is not None and max_segments < 1):
        raise ValueError("segment-seconds, batch-size, and max-segments must be positive")
    started = utc_now()
    session_id = generate_session_id(started)
    session_dir = output_dir / session_id
    pcap_dir, flows_dir, logs_dir = (session_dir / name for name in ("pcap", "flows", "logs"))
    for directory in (pcap_dir, flows_dir, logs_dir):
        directory.mkdir(parents=True, exist_ok=True)
    report = new_live_report(session_id, interface, started)
    session_report_path = logs_dir / "session-report.json"
    verifier = verifier or DashboardApiVerifier(api_url)
    sender = sender or ApiSender(api_url)
    extractor = extractor or DockerSegmentExtractor()
    before = None
    prediction_ids: set[int] = set()
    deduplicator = BoundedDeduplicator(dedup_capacity)
    stop_requested = False
    try:
        verifier.health()
        report["api"]["reachable"] = True
        before = verifier.summary()
        if skip_preflight:
            adapter = FeatureAdapter.from_metadata(
                metadata_path,
                compatibility_policy=CICIDS2017_DATASET_ARTIFACT_REPRODUCTION,
            )
        else:
            adapter, _ = preflight(interface, api_url, metadata_path, verifier=verifier)
        segment_number = 0
        while not stop_requested and (max_segments is None or segment_number < max_segments):
            segment_number += 1
            pcap = pcap_dir / f"segment-{segment_number:06d}.pcap"
            csv_path = flows_dir / f"segment-{segment_number:06d}.csv"
            logger.info("Starting capture segment %d on %s", segment_number, interface)
            stop_requested = not capture(interface, pcap, segment_seconds)
            validate_pcap(pcap)
            logger.info("Extracting flows from %s", pcap.name)
            extractor.extract(pcap, csv_path)
            report["capture"]["segments"] += 1
            flow_reader = FlowCsvExtractor()
            compatibility = adapter.compatibility(flow_reader.field_names(csv_path))
            report["feature_schema"] = {
                "required": len(adapter.feature_names),
                "produced": len(adapter.feature_names) if compatibility["compatible"] else 0,
                "missing": len(compatibility["missing_features"]),
            }
            if not compatibility["compatible"]:
                raise FeatureCompatibilityError(
                    f"Extractor schema incompatible: missing={compatibility['missing_features']} "
                    f"duplicates={compatibility['duplicate_features']}"
                )
            batch: list[AdaptedFlow] = []

            def submit_batch() -> None:
                if not batch:
                    return
                report["flows"]["submitted"] += len(batch)
                results = sender.send(batch)
                report["flows"]["successful"] += len(results)
                for result in results:
                    report["predictions"][result["prediction"]] += 1
                    if "prediction_id" in result:
                        prediction_ids.add(int(result["prediction_id"]))
                batch.clear()

            for row_number, extracted in enumerate(flow_reader.read(csv_path), 1):
                report["flows"]["extracted"] += 1
                extracted.metadata.update({
                    "capture_session_id": session_id,
                    "capture_interface": interface,
                    "pcap_segment": pcap.name,
                })
                try:
                    adapted = adapter.adapt(extracted)
                    fingerprint = flow_fingerprint(adapted)
                    if not deduplicator.add(fingerprint):
                        report["flows"]["duplicates_skipped"] += 1
                        continue
                    report["flows"]["unique"] += 1
                    batch.append(adapted)
                    if len(batch) >= batch_size:
                        submit_batch()
                except FeatureCompatibilityError as exc:
                    report["flows"]["failed"] += 1
                    report["failures"].append({"segment": pcap.name, "flow": row_number, "error": str(exc)})
            submit_batch()
            logger.info("Extracted %d cumulative flows", report["flows"]["extracted"])
            logger.info("Submitted %d cumulative flows", report["flows"]["submitted"])
            logger.info("Segment %d complete", segment_number)
            logger.info(
                "Session=%s segment=%d extracted=%d unique=%d duplicates=%d submitted=%d failed=%d predictions=%s",
                session_id, segment_number, report["flows"]["extracted"], report["flows"]["unique"],
                report["flows"]["duplicates_skipped"], report["flows"]["submitted"],
                report["flows"]["failed"], report["predictions"],
            )
    except KeyboardInterrupt:
        logger.info("Ctrl+C received; finalizing captured evidence")
    except Exception as exc:
        report["failures"].append({"stage": "pipeline", "error": str(exc)})
        logger.error("Live capture failed: %s", exc)
    finally:
        finalize_report(report, started, before, verifier, prediction_ids, report_path)
        write_live_report(report, session_report_path)
    return report
