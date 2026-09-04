# Phase 9 Runtime Monitoring Controller

> Historical phase document. Phase 10 replaces the lifecycle-only production
> collector with the runtime V3 pipeline documented in
> `docs/phase_10_runtime_capture_pipeline.md`.

Phase 9 adds a persistent defensive control plane without implementing packet capture,
flow extraction, or inference. A monitoring session therefore reports controller
lifecycle state truthfully; its flow, prediction, and alert counters remain zero until
Phase 10 connects the collector pipeline.

## Architecture and lifecycle

Authenticated ADMIN requests pass through FastAPI to `MonitoringService`, which owns
validation, active-model lookup, persistence, and transitions. `CollectorController`
is the explicit Phase 10 integration seam. Its Phase 9 implementation creates only an
opaque in-memory lifecycle handle and never starts an operating-system process.

The lifecycle is `STARTING → RUNNING → STOPPING → STOPPED`, with startup/stop errors
ending in `FAILED`. A partial unique database index permits only one
`STARTING`/`RUNNING`/`STOPPING` row. On API startup, stale active rows become `FAILED`
with a restart explanation because Phase 9 handles cannot be recovered across a
process restart.

## API

- `GET /api/monitoring/status`
- `GET /api/monitoring/interfaces`
- `GET /api/monitoring/sessions`
- `GET /api/monitoring/sessions/{id}`
- `POST /api/monitoring/start`
- `POST /api/monitoring/stop`

Start accepts a validated IP address and a discovered local interface name. The API
resolves the active model from the existing model registry. It never accepts a model
path or command. Interface discovery exposes names and availability only, not MAC
addresses or host configuration. Discovery failure is returned safely and disables
start in the dashboard.

The nullable `predictions.monitoring_session_id` preserves all legacy rows and gives
Phase 10 a provenance link without schema redesign. Experiment A/B/C evidence and
existing runtime prediction/alert semantics are untouched.

## Security boundary

No subprocess, shell, Nmap, traffic generation, SSH, or arbitrary command interface
is present. The application controls only the RF-NIDS defensive session lifecycle.

The attacker is external to RF-NIDS and is operated manually from the isolated Kali Linux virtual machine.
