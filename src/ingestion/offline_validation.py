"""End-to-end offline PCAP validation through the public RF-NIDS API."""

from __future__ import annotations

import json
import logging
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, Callable

import requests

from .api_sender import ApiSendError, ApiSender
from .cicflowmeter_mapping import CICIDS2017_DATASET_ARTIFACT_REPRODUCTION
from .feature_adapter import FeatureAdapter, FeatureCompatibilityError
from .flow_extractor import FlowCsvExtractor

logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXTRACTOR_NAME = "hieulw/cicflowmeter"
EXTRACTOR_VERSION = "0.4.2"


class OfflineValidationError(RuntimeError):
    """Raised when an end-to-end validation stage cannot be completed."""


class DashboardApiVerifier:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 10,
        get: Callable[..., Any] = requests.get,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._get = get

    def _json(self, path: str) -> Any:
        response = self._get(
            f"{self.base_url}{path}", timeout=self.timeout_seconds
        )
        response.raise_for_status()
        return response.json()

    def health(self) -> dict[str, Any]:
        value = self._json("/health")
        if value.get("status") != "healthy" or value.get("database") != "connected":
            raise OfflineValidationError(f"API health check failed: {value}")
        return value

    def summary(self) -> dict[str, Any]:
        value = self._json("/api/dashboard/summary")
        required = {"total_flows", "active_alerts", "acknowledged_alerts"}
        if not isinstance(value, dict) or not required <= value.keys():
            raise OfflineValidationError("Dashboard summary response is incomplete")
        return value

    def prediction_ids(self, prediction_ids: set[int]) -> set[int]:
        persisted = set()
        for prediction_id in prediction_ids:
            row = self._json(f"/api/predictions/{prediction_id}")
            if int(row.get("id", -1)) == prediction_id:
                persisted.add(prediction_id)
        return persisted


def extract_with_docker(pcap: Path, output_csv: Path, *, root: Path = PROJECT_ROOT) -> Path:
    pcap = pcap.resolve()
    input_root = (root / "data/lab/pcap").resolve()
    output_root = (root / "data/lab/flows").resolve()
    try:
        input_name = pcap.relative_to(input_root)
        output_name = output_csv.resolve().relative_to(output_root)
    except ValueError as exc:
        raise OfflineValidationError(
            "Docker extraction requires PCAP under data/lab/pcap and CSV under data/lab/flows"
        ) from exc
    if not pcap.is_file():
        raise OfflineValidationError(f"PCAP file does not exist: {pcap}")
    if pcap.stat().st_size == 0:
        raise OfflineValidationError(f"PCAP file is empty: {pcap}")
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "docker", "compose", "--profile", "tools", "run", "--rm", "cicflowmeter",
        f"/input/{input_name.as_posix()}", f"/output/{output_name.as_posix()}",
    ]
    try:
        completed = subprocess.run(
            command, cwd=root, capture_output=True, text=True, check=False
        )
    except OSError as exc:
        raise OfflineValidationError(f"Unable to start Docker extractor: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise OfflineValidationError(
            f"CICFlowMeter Docker extraction failed ({completed.returncode}): {detail}"
        )
    if not output_csv.is_file() or output_csv.stat().st_size == 0:
        raise OfflineValidationError("Extractor did not produce a non-empty flow CSV")
    return output_csv


def new_report(pcap: Path) -> dict[str, Any]:
    return {
        "status": "failed",
        "input_pcap": str(pcap),
        "extractor": {"name": EXTRACTOR_NAME, "version": EXTRACTOR_VERSION},
        "compatibility_policy": CICIDS2017_DATASET_ARTIFACT_REPRODUCTION,
        "feature_schema": {"required": 78, "produced": 0, "missing": 78},
        "flows": {"extracted": 0, "submitted": 0, "successful": 0, "failed": 0},
        "predictions": {"Normal": 0, "DDoS": 0, "PortScan": 0},
        "alerts_created": 0,
        "api": {"reachable": False},
        "database_persistence_verified": False,
        "dashboard_api_data_available": False,
        "failures": [],
        "limitations": [
            "hieulw/cicflowmeter is not identical to historical Java CICFlowMeter",
            "schema compatibility does not prove numerical feature equivalence",
            "dataset artifact reproduction policy is active",
            "this test validates pipeline functionality and does not measure detection accuracy",
        ],
    }


def write_report(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def validate_flow_csv(
    *,
    pcap: Path,
    csv_path: Path,
    api_url: str,
    metadata_path: Path,
    output: Path,
    batch_size: int = 100,
    timeout_seconds: float = 10,
    sender: ApiSender | None = None,
    verifier: DashboardApiVerifier | None = None,
) -> dict[str, Any]:
    report = new_report(pcap)
    extractor = FlowCsvExtractor()
    try:
        if batch_size < 1:
            raise OfflineValidationError("batch-size must be positive")
        adapter = FeatureAdapter.from_metadata(
            metadata_path,
            compatibility_policy=CICIDS2017_DATASET_ARTIFACT_REPRODUCTION,
        )
        compatibility = adapter.compatibility(extractor.field_names(csv_path))
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

        verifier = verifier or DashboardApiVerifier(
            api_url, timeout_seconds=timeout_seconds
        )
        verifier.health()
        report["api"]["reachable"] = True
        before = verifier.summary()
        sender = sender or ApiSender(api_url, timeout_seconds=timeout_seconds)
        batch = []
        all_results: list[dict[str, Any]] = []

        def submit() -> None:
            if not batch:
                return
            report["flows"]["submitted"] += len(batch)
            try:
                results = sender.send(batch)
            except ApiSendError:
                report["flows"]["failed"] += len(batch)
                raise
            required = {"prediction", "confidence", "model_version", "prediction_id"}
            invalid = [item for item in results if not required <= item.keys()]
            if invalid:
                report["flows"]["failed"] += len(batch)
                raise OfflineValidationError(
                    "API response is missing prediction label, confidence, model version, "
                    "or persisted prediction ID"
                )
            report["flows"]["successful"] += len(results)
            all_results.extend(results)
            batch.clear()

        for index, extracted in enumerate(extractor.read(csv_path), start=1):
            report["flows"]["extracted"] += 1
            try:
                batch.append(adapter.adapt(extracted))
            except FeatureCompatibilityError as exc:
                report["flows"]["failed"] += 1
                report["failures"].append({"flow": index, "error": str(exc)})
                continue
            if len(batch) >= batch_size:
                submit()
        submit()
        if report["flows"]["extracted"] == 0:
            raise OfflineValidationError("Flow CSV contains no flow rows")
        if report["flows"]["failed"]:
            raise OfflineValidationError(
                f"{report['flows']['failed']} flow(s) failed; failures were not skipped"
            )

        counts = Counter(item["prediction"] for item in all_results)
        report["predictions"] = {
            label: counts[label] for label in ("Normal", "DDoS", "PortScan")
        }
        after = verifier.summary()
        prediction_ids = {int(item["prediction_id"]) for item in all_results}
        persisted_ids = verifier.prediction_ids(prediction_ids)
        delta = int(after["total_flows"]) - int(before["total_flows"])
        report["database_persistence_verified"] = (
            delta == len(all_results) and prediction_ids <= persisted_ids
        )
        before_alerts = int(before["active_alerts"]) + int(before["acknowledged_alerts"])
        after_alerts = int(after["active_alerts"]) + int(after["acknowledged_alerts"])
        report["alerts_created"] = max(0, after_alerts - before_alerts)
        report["dashboard_api_data_available"] = report["database_persistence_verified"]
        if not report["database_persistence_verified"]:
            raise OfflineValidationError(
                f"Persistence verification failed: expected delta={len(all_results)}, actual={delta}"
            )
        report["status"] = "completed"
    except Exception as exc:
        report["failures"].append({"stage": "pipeline", "error": str(exc)})
        logger.error("Offline PCAP validation failed: %s", exc)
    finally:
        write_report(report, output)
    return report
