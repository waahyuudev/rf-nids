from pathlib import Path

import pytest

from scripts.run_experiment_d_cicflowmeter_v3 import validate_request


ROOT = Path(__file__).resolve().parents[2]


def test_extractor_wrapper_accepts_only_matching_experiment_d_role_class_paths() -> None:
    source = ROOT / "data/lab/experiment_d/adaptation/pcap/normal/future.pcap"
    output = ROOT / "data/lab/experiment_d/adaptation/flows/cicflowmeter-v3/normal/future.pcap_ISCX.csv"
    report = ROOT / "data/lab/experiment_d/adaptation/manifests/future-extraction.json"
    assert validate_request("adaptation", "normal", source, output, report)[0] == source.resolve()
    with pytest.raises(ValueError):
        validate_request("adaptation", "normal", ROOT / "data/lab/pcap/normal-http-test.pcap", output, report)
    with pytest.raises(ValueError):
        validate_request("adaptation", "normal", source, ROOT / "data/lab/flows/cicflowmeter-v3/new.csv", report)


def test_extractor_wrapper_refuses_existing_outputs(tmp_path: Path) -> None:
    # Containment is tested above; create-new behavior is independently fail-closed.
    from src.experiment_d.integrity import require_create_new
    output = tmp_path / "existing.csv"
    output.write_text("existing")
    with pytest.raises(FileExistsError):
        require_create_new(output)
