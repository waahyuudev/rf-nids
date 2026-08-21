from __future__ import annotations

import csv
import json
from pathlib import Path

from src.ingestion.feature_adapter import load_feature_names
from src.ingestion.offline_validation import validate_flow_csv


class FakeSender:
    def __init__(self):
        self.batches = []

    def send(self, flows):
        self.batches.append(list(flows))
        start = sum(len(batch) for batch in self.batches[:-1])
        return [
            {
                "prediction_id": start + index + 1,
                "prediction": "Normal",
                "confidence": 0.9,
                "model_version": "test",
            }
            for index in range(len(flows))
        ]


class FakeVerifier:
    def __init__(self, total):
        self.summaries = iter(
            [
                {"total_flows": 5, "active_alerts": 1, "acknowledged_alerts": 0},
                {"total_flows": 5 + total, "active_alerts": 1, "acknowledged_alerts": 0},
            ]
        )

    def health(self):
        return {"status": "healthy", "database": "connected"}

    def summary(self):
        return next(self.summaries)

    def prediction_ids(self, prediction_ids):
        return set(prediction_ids)


def write_flow_csv(path: Path, metadata_path: Path, rows: int = 2) -> None:
    features = load_feature_names(metadata_path)
    artifact_sources = {"fwd_header_length.1", "cwe_flag_count"}
    headers = [name for name in features if name not in artifact_sources]
    headers += ["Source IP", "Source Port", "Destination IP", "Protocol", "Timestamp"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for index in range(rows):
            values = {name: index + 1 for name in headers}
            values.update(
                {
                    "Source IP": "10.0.0.1",
                    "Source Port": 1234,
                    "Destination IP": "10.0.0.2",
                    "Protocol": "TCP",
                    "Timestamp": "2026-08-20T00:00:00Z",
                }
            )
            writer.writerow(values)


def test_validation_batches_payload_separates_metadata_and_writes_report(tmp_path) -> None:
    metadata = Path("models/model_metadata.json")
    csv_path = tmp_path / "flows.csv"
    output = tmp_path / "report.json"
    write_flow_csv(csv_path, metadata, rows=3)
    sender = FakeSender()

    report = validate_flow_csv(
        pcap=tmp_path / "sample.pcap",
        csv_path=csv_path,
        api_url="http://unused",
        metadata_path=metadata,
        output=output,
        batch_size=2,
        sender=sender,
        verifier=FakeVerifier(3),
    )

    assert report["status"] == "completed"
    assert report["feature_schema"] == {"required": 78, "produced": 78, "missing": 0}
    assert [len(batch) for batch in sender.batches] == [2, 1]
    adapted = sender.batches[0][0]
    assert len(adapted.features) == 78
    assert "source_ip" not in adapted.features
    assert adapted.metadata["source_ip"] == "10.0.0.1"
    assert json.loads(output.read_text())["database_persistence_verified"] is True


def test_empty_csv_generates_failed_report(tmp_path) -> None:
    metadata = Path("models/model_metadata.json")
    csv_path = tmp_path / "empty.csv"
    write_flow_csv(csv_path, metadata, rows=0)
    output = tmp_path / "report.json"

    report = validate_flow_csv(
        pcap=tmp_path / "sample.pcap",
        csv_path=csv_path,
        api_url="http://unused",
        metadata_path=metadata,
        output=output,
        sender=FakeSender(),
        verifier=FakeVerifier(0),
    )

    assert report["status"] == "failed"
    assert report["flows"]["extracted"] == 0
    assert "no flow rows" in report["failures"][-1]["error"]
