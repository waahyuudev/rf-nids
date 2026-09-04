import subprocess
import threading
from types import SimpleNamespace

import pytest

from src.api.runtime_monitoring import RuntimePipeline, RuntimePipelineError
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
    pipeline = RuntimePipeline(
        root=tmp_path, image="pinned-v3", window_seconds=0.001, popen=popen
    )
    output = tmp_path / "runtime" / "window.pcap"
    pipeline.capture("bridge100", "192.168.128.2", output, threading.Event())
    command, kwargs = calls[0]
    assert command == [
        "tcpdump", "-i", "bridge100", "-U", "-n", "-w", str(output),
        "host", "192.168.128.2",
    ]
    assert "shell" not in kwargs
    assert process.poll() is not None


def test_preflight_reports_missing_capture_executable(tmp_path, monkeypatch):
    monkeypatch.setattr("src.api.runtime_monitoring.shutil.which", lambda _: None)
    pipeline = RuntimePipeline(root=tmp_path, image="pinned-v3", window_seconds=1)
    with pytest.raises(RuntimePipelineError, match="tcpdump"):
        pipeline.preflight()


def test_extractor_uses_pinned_hardened_container_and_requires_output(tmp_path):
    pcap = tmp_path / "window.pcap"
    pcap.write_bytes(b"pcap")
    output = tmp_path / "flows"
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        output.mkdir(parents=True, exist_ok=True)
        (output / "window.pcap_ISCX.csv").write_text("A\n1\n", encoding="utf-8")
        return Result()

    pipeline = RuntimePipeline(
        root=tmp_path, image="rf-nids-cicflowmeter-v3:a26aae27",
        window_seconds=1, run=run,
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
        run=lambda *args, **kwargs: Failed(),
    )
    with pytest.raises(RuntimePipelineError, match="extractor error"):
        pipeline.extract(pcap, tmp_path / "flows")


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
            worker.stop_event.set()
            return [{
                "prediction": "Normal", "confidence": 0.8,
                "probabilities": {"Normal": 0.8, "DDoS": 0.1, "PortScan": 0.1},
                "model_version": "v1",
            }]

    class Pipeline:
        def capture(self, interface, target, pcap, stop):
            assert (interface, target) == ("test0", "192.168.128.2")
            pcap.parent.mkdir(parents=True, exist_ok=True)
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 21)

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
        assert prediction.model_id == row.model_id
        assert prediction.confidence_score == 0.8
        assert (row.flow_count, row.prediction_count, row.alert_count) == (1, 1, 0)
        assert db.scalar(select(func.count(Alert.id))) == 0
        assert row.latest_processing_at is not None
    engine.dispose()
