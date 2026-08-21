from __future__ import annotations

import csv
import json
import signal
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.ingestion.feature_adapter import load_feature_names
from src.ingestion.live_capture import (
    BoundedDeduplicator,
    DockerSegmentExtractor,
    LiveCaptureError,
    capture_segment,
    discover_pcap_segments,
    flow_fingerprint,
    generate_session_id,
    run_live_capture,
    preflight,
    validate_pcap,
    validate_interface,
)
from src.ingestion.models import AdaptedFlow


def test_session_id_is_utc_and_unique_format() -> None:
    value = generate_session_id(datetime(2026, 8, 20, 8, 30, tzinfo=timezone.utc))
    assert value.startswith("20260820T083000Z_")
    assert len(value) == 23


def test_live_capture_script_runs_directly_from_repository_root() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/run_live_capture.py", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "--segment-seconds" in result.stdout


def test_interface_validation() -> None:
    assert validate_interface("en7", ["lo0", "en7"]) == "en7"
    with pytest.raises(LiveCaptureError, match="available: lo0, en7"):
        validate_interface("en0", ["lo0", "en7"])


def test_preflight_fails_early_when_sudo_credentials_are_not_cached(monkeypatch) -> None:
    class Result:
        def __init__(self, returncode, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def run(command, **kwargs):
        if command == ["ifconfig", "-l"]:
            return Result(0, "lo0 en7")
        return Result(1, stderr="password required")

    class Verifier:
        pass

    monkeypatch.setattr("src.ingestion.live_capture.platform.system", lambda: "Darwin")
    monkeypatch.setattr("src.ingestion.live_capture.shutil.which", lambda _: "/usr/sbin/tcpdump")
    with pytest.raises(LiveCaptureError, match="sudo -v"):
        preflight(
            "en7", "http://unused", Path("models/model_metadata.json"),
            verifier=Verifier(), run=run,
        )


def test_segment_discovery_is_sorted_and_ignores_other_files(tmp_path: Path) -> None:
    (tmp_path / "segment-000002.pcap").touch()
    (tmp_path / "segment-000001.pcap").touch()
    (tmp_path / "notes.txt").touch()
    assert [path.name for path in discover_pcap_segments(tmp_path)] == [
        "segment-000001.pcap", "segment-000002.pcap"
    ]


def test_fingerprint_uses_flow_identity_and_bounded_dedup() -> None:
    first = AdaptedFlow(
        features={"flow_duration": 10.0},
        metadata={"capture_session_id": "s", "source_ip": "10.0.0.1", "source_port": 5},
    )
    second = AdaptedFlow(
        features={"flow_duration": 10.0},
        metadata={"capture_session_id": "s", "source_ip": "10.0.0.2", "source_port": 5},
    )
    assert flow_fingerprint(first) != flow_fingerprint(second)
    dedup = BoundedDeduplicator(capacity=1)
    assert dedup.add("a") is True
    assert dedup.add("a") is False
    assert dedup.add("b") is True
    assert dedup.add("a") is True


def write_csv(path: Path) -> None:
    feature_names = load_feature_names(Path("models/model_metadata.json"))
    headers = [name for name in feature_names if name not in {"fwd_header_length.1", "cwe_flag_count"}]
    headers += ["Source IP", "Source Port", "Destination IP", "Protocol", "Timestamp"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        values = {name: 1 for name in headers}
        values.update({
            "Source IP": "10.0.0.1", "Source Port": 1234,
            "Destination IP": "10.0.0.2",
            "Protocol": "TCP", "Timestamp": "2026-08-20T08:00:00Z",
        })
        writer.writerow(values)


PCAP_HEADER = b"\xd4\xc3\xb2\xa1" + (b"\x00" * 20)


class FakeCaptureProcess:
    def __init__(self, wait_timeouts: int = 0):
        self.pid = 4321
        self.returncode = None
        self.wait_timeouts = wait_timeouts
        self.wait_calls = []

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        self.wait_calls.append(timeout)
        if self.wait_timeouts:
            self.wait_timeouts -= 1
            raise subprocess.TimeoutExpired(["sudo", "tcpdump"], timeout)
        self.returncode = -signal.SIGINT
        return self.returncode


class FakeClock:
    def __init__(self, interrupt: bool = False):
        self.now = 0.0
        self.sleeps = []
        self.interrupt = interrupt

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        if self.interrupt:
            raise KeyboardInterrupt
        self.sleeps.append(seconds)
        self.now += seconds


def test_capture_uses_popen_configured_duration_and_process_group_sigint(tmp_path: Path) -> None:
    process = FakeCaptureProcess()
    clock = FakeClock()
    popen_calls = []
    signals = []
    output = tmp_path / "segment.pcap"
    output.write_bytes(PCAP_HEADER)

    def popen(command, **kwargs):
        popen_calls.append((command, kwargs))
        return process

    assert capture_segment(
        "en7", output, 15, popen=popen, sleep=clock.sleep,
        monotonic=clock.monotonic, kill_process_group=lambda pid, sig: signals.append((pid, sig)),
    ) is True
    assert popen_calls[0][0][:5] == ["sudo", "-n", "tcpdump", "-i", "en7"]
    assert popen_calls[0][1]["process_group"] == 0
    assert "start_new_session" not in popen_calls[0][1]
    assert sum(clock.sleeps) == pytest.approx(15)
    assert signals == [(4321, signal.SIGINT)]
    assert process.wait_calls == [10]
    assert process.poll() is not None


def test_capture_escalates_from_sigint_to_terminate_then_kill(tmp_path: Path) -> None:
    process = FakeCaptureProcess(wait_timeouts=2)
    clock = FakeClock()
    signals = []
    output = tmp_path / "segment.pcap"
    output.write_bytes(PCAP_HEADER)
    capture_segment(
        "en7", output, 1, popen=lambda *args, **kwargs: process,
        sleep=clock.sleep, monotonic=clock.monotonic,
        kill_process_group=lambda pid, sig: signals.append(sig),
    )
    assert signals == [signal.SIGINT, signal.SIGTERM, signal.SIGKILL]
    assert process.wait_calls == [10, 5, 5]
    assert process.poll() is not None


def test_ctrl_c_stops_group_and_returns_final_segment(tmp_path: Path) -> None:
    process = FakeCaptureProcess()
    clock = FakeClock(interrupt=True)
    signals = []
    output = tmp_path / "segment.pcap"
    output.write_bytes(PCAP_HEADER)
    assert capture_segment(
        "en7", output, 15, popen=lambda *args, **kwargs: process,
        sleep=clock.sleep, monotonic=clock.monotonic,
        kill_process_group=lambda pid, sig: signals.append(sig),
    ) is False
    assert signals == [signal.SIGINT]
    assert process.poll() is not None


@pytest.mark.parametrize("content", [b"", b"not-a-valid-pcap-header-at-all"])
def test_invalid_or_empty_pcap_is_rejected(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "invalid.pcap"
    path.write_bytes(content)
    with pytest.raises(LiveCaptureError, match="PCAP"):
        validate_pcap(path)


def test_docker_extractor_uses_entrypoint_input_output_contract(tmp_path: Path) -> None:
    pcap = tmp_path / "data/lab/live/session/pcap/segment-000001.pcap"
    csv_path = tmp_path / "data/lab/live/session/flows/segment-000001.csv"
    pcap.parent.mkdir(parents=True)
    pcap.write_bytes(PCAP_HEADER)
    calls = []

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def run(command, **kwargs):
        calls.append((command, kwargs))
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        csv_path.write_text("header\n", encoding="utf-8")
        return Result()

    assert DockerSegmentExtractor(root=tmp_path, run=run).extract(pcap, csv_path) == csv_path
    command = calls[0][0]
    assert f"{pcap.parent.resolve()}:/input:ro" in command
    assert f"{csv_path.parent.resolve()}:/output" in command
    assert command[-2:] == [
        "/input/segment-000001.pcap", "/output/segment-000001.csv"
    ]


class FakeExtractor:
    def extract(self, pcap: Path, csv_path: Path) -> Path:
        write_csv(csv_path)
        return csv_path


class FakeSender:
    def send(self, flows):
        assert len(flows[0].features) == 78
        assert flows[0].metadata["capture_interface"] == "en7"
        assert "capture_session_id" not in flows[0].features
        return [{"prediction_id": 11, "prediction": "Normal"} for _ in flows]


class FakeVerifier:
    def __init__(self):
        self.values = iter([
            {"total_flows": 4, "active_alerts": 0, "acknowledged_alerts": 0},
            {"total_flows": 5, "active_alerts": 0, "acknowledged_alerts": 0},
        ])

    def summary(self):
        return next(self.values)

    def health(self):
        return {"status": "healthy", "database": "connected", "model_loaded": True}

    def prediction_ids(self, values):
        return values


def test_session_summary_report_and_finalization_without_privileged_capture(tmp_path: Path) -> None:
    def capture(interface, pcap, seconds):
        pcap.write_bytes(PCAP_HEADER)
        return True

    report_path = tmp_path / "live-report.json"
    report = run_live_capture(
        interface="en7", segment_seconds=1, api_url="http://unused",
        output_dir=tmp_path / "live", metadata_path=Path("models/model_metadata.json"),
        report_path=report_path, max_segments=1, sender=FakeSender(),
        verifier=FakeVerifier(), extractor=FakeExtractor(), capture=capture,
        skip_preflight=True,
    )
    assert report["status"] == "completed"
    assert report["flows"] == {
        "extracted": 1, "unique": 1, "duplicates_skipped": 0,
        "submitted": 1, "successful": 1, "failed": 0,
    }
    assert report["feature_schema"] == {"required": 78, "produced": 78, "missing": 0}
    assert json.loads(report_path.read_text())["predictions"]["Normal"] == 1
    assert (next((tmp_path / "live").iterdir()) / "logs/session-report.json").is_file()


def test_report_is_written_when_capture_raises_keyboard_interrupt(tmp_path: Path) -> None:
    def interrupted(*args):
        raise KeyboardInterrupt

    report_path = tmp_path / "interrupted.json"
    report = run_live_capture(
        interface="en7", segment_seconds=1, api_url="http://unused",
        output_dir=tmp_path / "live", metadata_path=Path("models/model_metadata.json"),
        report_path=report_path, max_segments=1, sender=FakeSender(),
        verifier=FakeVerifier(), extractor=FakeExtractor(), capture=interrupted,
        skip_preflight=True,
    )
    assert report["status"] == "failed"
    assert report_path.is_file()


def test_invalid_pcap_is_not_counted_or_sent_to_extractor(tmp_path: Path) -> None:
    class TrackingExtractor:
        calls = 0

        def extract(self, pcap, csv_path):
            self.calls += 1

    tracking = TrackingExtractor()

    def invalid_capture(interface, pcap, seconds):
        pcap.write_bytes(b"invalid")
        return True

    report = run_live_capture(
        interface="en7", segment_seconds=1, api_url="http://unused",
        output_dir=tmp_path / "live", metadata_path=Path("models/model_metadata.json"),
        report_path=tmp_path / "invalid-report.json", max_segments=1,
        sender=FakeSender(), verifier=FakeVerifier(), extractor=tracking,
        capture=invalid_capture, skip_preflight=True,
    )
    assert report["status"] == "failed"
    assert report["capture"]["segments"] == 0
    assert tracking.calls == 0
