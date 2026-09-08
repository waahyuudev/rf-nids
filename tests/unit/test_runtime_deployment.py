"""Deployment contract checks; no Docker daemon or real capture required."""
from pathlib import Path

import yaml

from src.api.monitoring import list_capture_interfaces
from src.common.config import PROJECT_ROOT, Settings


def test_interface_discovery_returns_actual_namespace_names(monkeypatch):
    monkeypatch.setattr("src.api.monitoring.socket.if_nameindex", lambda: [
        (3, "enp0s3"), (1, "lo"), (2, "enp0s2"), (4, "enp0s1"),
    ])
    interfaces, available = list_capture_interfaces()
    assert available
    assert [item["name"] for item in interfaces] == ["enp0s1", "enp0s2", "enp0s3", "lo"]


def test_runtime_path_configuration(monkeypatch):
    monkeypatch.setenv("RUNTIME_MONITORING_ROOT", "/app/data/runtime/monitoring")
    monkeypatch.setenv("RUNTIME_MONITORING_HOST_ROOT", "/srv/rf-nids/data/runtime/monitoring")
    settings = Settings.from_env()
    assert settings.runtime_monitoring_root == Path("/app/data/runtime/monitoring")
    assert settings.runtime_monitoring_host_root == Path("/srv/rf-nids/data/runtime/monitoring")
    monkeypatch.delenv("RUNTIME_MONITORING_HOST_ROOT")
    assert Settings.from_env().runtime_monitoring_host_root is None


def test_linux_compose_network_storage_and_privilege_contract():
    compose = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text())
    services = compose["services"]
    api = services["api"]
    assert api["network_mode"] == "host" and "ports" not in api
    assert "@127.0.0.1:5432/" in api["environment"]["DATABASE_URL"]
    assert "@postgres:5432/" in services["migration"]["environment"]["DATABASE_URL"]
    assert services["postgres"]["volumes"] == ["rf_nids_postgres:/var/lib/postgresql/data"]
    assert api["cap_drop"] == ["ALL"] and api["cap_add"] == ["NET_RAW"]
    assert not api.get("privileged", False)
    assert "--reload" not in api["command"]
    binds = [item for item in api["volumes"] if isinstance(item, dict)]
    runtime = next(item for item in binds if item["target"] == "/app/data/runtime/monitoring")
    assert runtime["source"] == api["environment"]["RUNTIME_MONITORING_HOST_ROOT"]
    assert runtime["bind"]["create_host_path"] is False
    assert any(item["source"] == "/var/run/docker.sock" for item in binds)
    for name, service in services.items():
        if name != "api":
            assert "docker.sock" not in str(service)
