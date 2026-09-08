import subprocess
import threading
import io
import signal
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.api.runtime_monitoring import (
    RuntimeCollectorController, RuntimePipeline, RuntimePipelineError, validate_runtime_root,
)
from src.api.runtime_monitoring import RuntimeWorker
from src.api.database import Base, build_engine
from src.api.models import Alert, ModelRecord, MonitoringSession, Prediction
from src.ingestion.cicflowmeter_v3_adapter import MODEL_FEATURES, REQUIRED_V3_HEADERS
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker


class Result:
    returncode = 0
    stdout = ""
    stderr = ""


class FakeProcess:
    def __init__(self, command):
        self.command = command
        self.pid = 4242
        self.returncode = None
        self.stderr = SimpleNamespace(read=lambda: "")
        output = command[command.index("-w") + 1]
        with open(output, "wb") as stream:
            stream.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 21)

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("tcpdump", timeout)
        return self.returncode


class FakeExtractorProcess:
    def __init__(self, command, output, *, returncode=0, stderr=""):
        self.command = command
        self.pid = 4343
        self.returncode = returncode
        self.output = output
        self.stderr_text = stderr

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def communicate(self, timeout=None):
        if self.returncode == 0:
            (self.output / "window.pcap_ISCX.csv").write_text("A\n1\n", encoding="utf-8")
        return "", self.stderr_text

def test_capture_uses_argument_array_target_filter_and_clean_process_group(tmp_path, monkeypatch):
    calls = []
    process = None

    def popen(command, **kwargs):
        nonlocal process
        calls.append((command, kwargs))
        process = FakeProcess(command)
        return process

    def killpg(pid, sig):
        assert pid == 4242
        process.returncode = -sig

    monkeypatch.setattr("src.api.runtime_monitoring.os.killpg", killpg)
    monkeypatch.setattr(
        "src.api.runtime_monitoring.list_capture_interfaces",
        lambda: ([{"name": "bridge100", "is_up": True}], True),
    )
    pipeline = RuntimePipeline(
        root=tmp_path, image="pinned-v3", window_seconds=0.001, popen=popen
    )
    pipeline.tcpdump_path = "/usr/sbin/tcpdump"
    output = tmp_path / "runtime" / "window.pcap"
    pipeline.capture("bridge100", "192.168.128.2", output, threading.Event())
    command, kwargs = calls[0]
    assert command == [
        "/usr/sbin/tcpdump", "-i", "bridge100", "-p", "-U", "-n", "-w", str(output),
        "host", "192.168.128.2",
    ]
    assert "shell" not in kwargs
    assert process.poll() is not None


def test_capture_fails_if_interface_disappears_before_start(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "src.api.runtime_monitoring.list_capture_interfaces", lambda: ([], False)
    )
    pipeline = RuntimePipeline(root=tmp_path, image="v3", window_seconds=1)
    with pytest.raises(RuntimePipelineError, match="no longer available"):
        pipeline.capture("enp0s2", "192.168.128.4", tmp_path / "capture.pcap", threading.Event())


def test_preflight_reports_missing_capture_executable(tmp_path, monkeypatch):
    monkeypatch.setattr("src.api.runtime_monitoring.shutil.which", lambda _: None)
    pipeline = RuntimePipeline(root=tmp_path, image="pinned-v3", window_seconds=1)
    with pytest.raises(RuntimePipelineError, match="tcpdump"):
        pipeline.preflight("vmenet3")


class ProbeProcess:
    pid = 4242

    def __init__(self, returncode=None, detail="", ignore_signals=False):
        self.returncode = returncode
        self.detail = detail
        self.stderr = io.StringIO(detail)
        self.ignore_signals = ignore_signals
        self.signals = []
        self.waited = False

    def communicate(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("tcpdump", timeout)
        return None, self.detail

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("tcpdump", timeout)
        self.waited = True
        return self.returncode


@pytest.fixture
def probe(monkeypatch):
    process = ProbeProcess()
    monkeypatch.setattr(
        "src.api.runtime_monitoring.list_capture_interfaces",
        lambda: ([{"name": "enp0s3", "is_up": None}], True),
    )
    monkeypatch.setattr("src.api.runtime_monitoring.shutil.which", lambda _: "/usr/bin/tcpdump")

    def killpg(pid, sig):
        assert pid == process.pid
        process.signals.append(sig)
        if not process.ignore_signals or sig == signal.SIGKILL:
            process.returncode = -sig

    monkeypatch.setattr("src.api.runtime_monitoring.os.killpg", killpg)
    return process


@pytest.mark.parametrize("detail", [
    "Permission denied", "No such device", "cannot open BPF device /dev/bpf0",
])
def test_preflight_reports_immediate_capture_failure(tmp_path, probe, detail):
    probe.returncode, probe.detail = 1, detail
    pipeline = RuntimePipeline(
        root=tmp_path, image="v3", window_seconds=1,
        popen=lambda *a, **kw: probe,
        run=lambda *a, **kw: pytest.fail("must not inspect Docker after capture failure"),
    )
    with pytest.raises(RuntimePipelineError, match=detail):
        pipeline.preflight("enp0s3")
    assert probe.waited and probe.stderr.closed
    assert probe.signals == []


def test_preflight_accepts_idle_interface_without_packets_and_reaps(tmp_path, probe):
    calls = []

    def popen(command, **kwargs):
        calls.append((command, kwargs))
        return probe

    pipeline = RuntimePipeline(
        root=tmp_path, image="v3", expected_image_digest="sha256:expected",
        window_seconds=1, popen=popen,
        run=lambda *a, **kw: SimpleNamespace(returncode=0, stdout="sha256:expected", stderr=""),
    )
    pipeline.preflight("enp0s3")
    assert calls[0][0] == [
        "/usr/bin/tcpdump", "-i", "enp0s3", "-p", "-n", "-U", "-w", "/dev/null",
    ]
    assert calls[0][1]["process_group"] == 0
    assert probe.signals == [signal.SIGINT]
    assert probe.waited and probe.stderr.closed and probe.poll() is not None
    assert pipeline.tcpdump_path == "/usr/bin/tcpdump"
    assert pipeline.resolved_image_identity == "sha256:expected"


def test_preflight_escalates_and_reaps_stubborn_capture(tmp_path, probe):
    probe.ignore_signals = True
    pipeline = RuntimePipeline(
        root=tmp_path, image="v3", window_seconds=1, popen=lambda *a, **kw: probe,
    )
    with pytest.raises(RuntimePipelineError, match="Unable to open"):
        pipeline.preflight("enp0s3")
    assert probe.signals == [signal.SIGINT, signal.SIGTERM, signal.SIGKILL]
    assert probe.waited and probe.stderr.closed


def test_preflight_reports_spawn_error(tmp_path, probe):
    def popen(*a, **kw):
        raise PermissionError("executable denied")
    pipeline = RuntimePipeline(root=tmp_path, image="v3", window_seconds=1, popen=popen)
    with pytest.raises(RuntimePipelineError, match="executable denied"):
        pipeline.preflight("enp0s3")


def test_preflight_rejects_ubuntu_interface_not_discovered_on_macos(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "src.api.runtime_monitoring.list_capture_interfaces",
        lambda: ([{"name": "vmenet3", "is_up": True}], True),
    )
    monkeypatch.setattr(
        "src.api.runtime_monitoring.shutil.which", lambda _: "/usr/sbin/tcpdump"
    )
    pipeline = RuntimePipeline(root=tmp_path, image="v3", window_seconds=1)
    with pytest.raises(RuntimePipelineError, match="no longer available"):
        pipeline.preflight("enp0s2")


@pytest.mark.parametrize("returncode, identity, error", [
    (0, "sha256:wrong", "identity mismatch"),
    (1, "", "image is unavailable"),
])
def test_preflight_validates_extractor_identity(tmp_path, probe, returncode, identity, error):
    pipeline = RuntimePipeline(
        root=tmp_path, image="v3", expected_image_digest="sha256:expected",
        window_seconds=1, popen=lambda *a, **kw: probe,
        run=lambda *a, **kw: SimpleNamespace(returncode=returncode, stdout=identity, stderr=""),
    )
    with pytest.raises(RuntimePipelineError, match=error):
        pipeline.preflight("enp0s3")
    assert probe.waited and probe.stderr.closed


@pytest.mark.parametrize("relative", [".", "data/lab", "reports", "models", "migrations"])
def test_runtime_root_rejects_frozen_or_repository_paths(tmp_path, relative):
    project = tmp_path / "project"
    project.mkdir()
    candidate = project if relative == "." else project / relative
    candidate.mkdir(parents=True, exist_ok=True)
    with pytest.raises(RuntimePipelineError, match="must remain under|Repository root"):
        validate_runtime_root(candidate, project_root=project)


def test_runtime_root_accepts_dedicated_tree_and_rejects_symlink_escape(tmp_path):
    project = tmp_path / "project"
    allowed = project / "data/runtime/monitoring"
    allowed.mkdir(parents=True)
    assert validate_runtime_root(allowed, project_root=project) == allowed.resolve()
    outside = tmp_path / "outside"
    outside.mkdir()
    escaped = allowed / "escaped"
    escaped.symlink_to(outside, target_is_directory=True)
    with pytest.raises(RuntimePipelineError, match="must remain under"):
        validate_runtime_root(escaped, project_root=project)


def test_existing_session_directory_is_never_overwritten(tmp_path):
    project = tmp_path / "project"
    runtime_root = project / "data/runtime/monitoring"
    runtime_root.mkdir(parents=True)
    engine = build_engine(f"sqlite:///{tmp_path / 'collision.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    with sessions() as db:
        model = ModelRecord(model_name="RF", model_version="v1", algorithm="RF", is_active=True)
        db.add(model)
        db.flush()
        row = MonitoringSession(
            target_ip="192.168.128.4", interface_name="enp0s2", model_id=model.id,
            status="STARTING", artifact_key="unique-key",
        )
        db.add(row)
        db.commit()
        session_id = row.id
    (runtime_root / f"{session_id}-unique-key").mkdir()
    settings = SimpleNamespace(
        project_root=project, runtime_monitoring_root=runtime_root,
        capture_stop_timeout_seconds=1, extraction_timeout_seconds=1,
    )
    controller = RuntimeCollectorController(
        session_factory=sessions, inference=object(), settings=settings,
        worker_factory=lambda **kwargs: None,
    )
    with pytest.raises(RuntimePipelineError, match="Refusing to overwrite"):
        controller.start(
            session_id=session_id, target_ip="192.168.128.4", interface_name="enp0s2"
        )
    engine.dispose()


def test_integer_session_id_cannot_collide_when_artifact_key_changes(tmp_path):
    project = tmp_path / "project"
    runtime_root = project / "data/runtime/monitoring"
    runtime_root.mkdir(parents=True)
    first = runtime_root / "1-first-uuid"
    second = runtime_root / "1-second-uuid"
    first.mkdir()
    second.mkdir()
    assert first != second and first.is_dir() and second.is_dir()


def test_extractor_uses_pinned_hardened_container_and_requires_output(tmp_path):
    pcap = tmp_path / "window.pcap"
    pcap.write_bytes(b"pcap")
    output = tmp_path / "flows"
    calls = []

    def popen(command, **kwargs):
        calls.append((command, kwargs))
        return FakeExtractorProcess(command, output)

    pipeline = RuntimePipeline(
        root=tmp_path, image="rf-nids-cicflowmeter-v3:a26aae27",
        window_seconds=1, popen=popen,
    )
    assert pipeline.extract(pcap, output).name == "window.pcap_ISCX.csv"
    command, kwargs = calls[0]
    assert command[:3] == ["docker", "run", "--rm"]
    assert "--network" in command and "none" in command
    assert "--cap-drop" in command and "ALL" in command
    assert command[-3:] == ["rf-nids-cicflowmeter-v3:a26aae27", "/input/window.pcap", "/output"]
    assert "shell" not in kwargs


def test_extractor_failure_is_not_treated_as_empty_traffic(tmp_path):
    pcap = tmp_path / "window.pcap"
    pcap.write_bytes(b"pcap")

    class Failed(Result):
        returncode = 2
        stderr = "extractor error"

    pipeline = RuntimePipeline(
        root=tmp_path, image="pinned-v3", window_seconds=1,
        popen=lambda command, **kwargs: FakeExtractorProcess(
            command, tmp_path / "flows", returncode=2, stderr="extractor error"
        ),
    )
    with pytest.raises(RuntimePipelineError, match="extractor error"):
        pipeline.extract(pcap, tmp_path / "flows")


def test_extractor_timeout_escalates_and_reaps_process(tmp_path, monkeypatch):
    pcap = tmp_path / "window.pcap"
    pcap.write_bytes(b"pcap")
    signals = []

    class HangingProcess:
        pid = 5151
        returncode = None

        def poll(self):
            return self.returncode

        def communicate(self, timeout=None):
            raise subprocess.TimeoutExpired("docker", timeout)

        def wait(self, timeout=None):
            if self.returncode is None:
                raise subprocess.TimeoutExpired("docker", timeout)
            return self.returncode

    process = HangingProcess()

    def killpg(pid, sig):
        assert pid == 5151
        signals.append(sig)
        if sig == __import__("signal").SIGKILL:
            process.returncode = -sig

    monkeypatch.setattr("src.api.runtime_monitoring.os.killpg", killpg)
    pipeline = RuntimePipeline(
        root=tmp_path, image="v3", window_seconds=1, extraction_timeout_seconds=.001,
        popen=lambda *args, **kwargs: process,
    )
    with pytest.raises(RuntimePipelineError, match="timed out"):
        pipeline.extract(pcap, tmp_path / "flows")
    assert signals == [
        __import__("signal").SIGINT,
        __import__("signal").SIGTERM,
        __import__("signal").SIGKILL,
    ]
    assert process.poll() is not None


def test_stop_during_extraction_allows_flush_until_forced_timeout(tmp_path, monkeypatch):
    signals = []

    class ExtractorProcess:
        pid = 6161
        returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            if self.returncode is None:
                raise subprocess.TimeoutExpired("docker", timeout)
            return self.returncode

    process = ExtractorProcess()

    def killpg(pid, sig):
        signals.append(sig)
        process.returncode = -sig

    monkeypatch.setattr("src.api.runtime_monitoring.os.killpg", killpg)
    pipeline = RuntimePipeline(root=tmp_path, image="v3", window_seconds=1)
    pipeline._process = process
    pipeline._active_stage = "EXTRACTING"
    pipeline.request_stop()
    assert signals == []  # graceful Stop lets the finalized window finish
    pipeline.force_stop()
    assert signals == [__import__("signal").SIGTERM]
    assert process.poll() is not None


def test_worker_reuses_v3_adapter_persists_prediction_and_real_counters(tmp_path):
    engine = build_engine(f"sqlite:///{tmp_path / 'runtime.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    with sessions() as db:
        model = ModelRecord(model_name="RF", model_version="v1", algorithm="RF", is_active=True)
        db.add(model)
        db.flush()
        monitoring = MonitoringSession(
            target_ip="192.168.128.2", interface_name="test0", model_id=model.id,
            status="RUNNING", flow_count=0, prediction_count=0, alert_count=0,
            artifact_key="a" * 32, artifact_root=str(tmp_path / "artifacts" / "1-a"),
            extractor_identity="test-v3",
        )
        db.add(monitoring)
        db.commit()
        session_id = monitoring.id

    settings = SimpleNamespace(
        runtime_monitoring_root=tmp_path / "artifacts", cicflowmeter_v3_image="v3",
        capture_window_seconds=1, capture_stop_timeout_seconds=1,
    )

    class Inference:
        feature_names = list(MODEL_FEATURES)

        def predict_batch(self, rows):
            assert list(rows[0]) == list(MODEL_FEATURES)
            return [{
                "prediction": "Normal", "confidence": 0.8,
                "probabilities": {"Normal": 0.8, "DDoS": 0.1, "PortScan": 0.1},
                "model_version": "v1",
            }]

    class Pipeline:
        capture_calls = 0

        def capture(self, interface, target, pcap, stop):
            self.capture_calls += 1
            assert (interface, target) == ("test0", "192.168.128.2")
            pcap.parent.mkdir(parents=True, exist_ok=True)
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 21)
            stop.set()

        def extract(self, pcap, output):
            output.mkdir(parents=True, exist_ok=True)
            values = {name: [1] for name in REQUIRED_V3_HEADERS}
            values.update({"Src IP": ["192.168.128.3"], "Dst IP": ["192.168.128.2"]})
            path = output / "window.pcap_ISCX.csv"
            __import__("pandas").DataFrame(values).to_csv(path, index=False)
            return path

    worker = RuntimeWorker(
        session_id=session_id, session_factory=sessions, inference=Inference(),
        settings=settings, on_exit=lambda *_: None,
    )
    worker.pipeline = Pipeline()
    worker._run()

    with sessions() as db:
        row = db.get(MonitoringSession, session_id)
        prediction = db.scalar(select(Prediction))
        assert prediction.monitoring_session_id == session_id
        assert prediction.runtime_artifact_id is not None
        assert prediction.model_id == row.model_id
        assert prediction.confidence_score == 0.8
        assert (row.flow_count, row.prediction_count, row.alert_count) == (1, 1, 0)
        assert db.scalar(select(func.count(Alert.id))) == 0
        assert row.latest_processing_at is not None
        assert worker.pipeline.capture_calls == 1
    engine.dispose()


def test_host_path_mapping_is_used_for_both_extractor_mounts(tmp_path):
    session = tmp_path / "session-x"
    session.mkdir()
    pcap = session / "capture.pcap"
    pcap.write_bytes(b"pcap")
    output = session / "flows"
    calls = []
    def popen(command, **kwargs):
        calls.append(command)
        return FakeExtractorProcess(command, output)
    pipeline = RuntimePipeline(
        root=tmp_path, host_root=Path("/srv/rf-nids/data/runtime/monitoring"),
        image="v3", window_seconds=1, popen=popen,
    )
    pipeline.extract(pcap, output)
    assert "type=bind,src=/srv/rf-nids/data/runtime/monitoring/session-x/capture.pcap,dst=/input/capture.pcap,readonly" in calls[0]
    assert "type=bind,src=/srv/rf-nids/data/runtime/monitoring/session-x/flows,dst=/output" in calls[0]


def test_container_path_maps_without_resolving_host_filesystem():
    pipeline = RuntimePipeline(
        root=Path("/app/data/runtime/monitoring"), host_root=Path("/srv/runtime"),
        image="v3", window_seconds=1,
    )
    assert pipeline.host_artifact_path(Path("/app/data/runtime/monitoring/session-x/capture.pcap")) == Path("/srv/runtime/session-x/capture.pcap")


def test_host_mapping_rejects_escape_and_symlinks(tmp_path):
    root = tmp_path / "runtime"
    root.mkdir()
    (root / "escape").symlink_to(tmp_path, target_is_directory=True)
    pipeline = RuntimePipeline(root=root, image="v3", window_seconds=1)
    for path in (root / "../capture.pcap", root / "escape/capture.pcap"):
        with pytest.raises(RuntimePipelineError, match="escapes runtime root"):
            pipeline.host_artifact_path(path)


@pytest.mark.parametrize("host", ["relative/path", "/srv/../runtime"])
def test_host_mapping_requires_absolute_unambiguous_root(tmp_path, host):
    with pytest.raises(RuntimePipelineError, match="absolute path"):
        RuntimePipeline(root=tmp_path, host_root=Path(host), image="v3", window_seconds=1)
