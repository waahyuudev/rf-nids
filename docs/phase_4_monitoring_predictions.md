# Phase 4 — Monitoring and Predictions

Completed: 2026-09-02  
Scope: runtime Monitoring, Predictions, and Prediction Detail only. Alert-rule changes, full Login UX, and export remain outside Phase 4.

## Runtime Boundary

Phase 4 keeps application inference records separate from Experiment A/B/C scientific evidence. New API inference rows are marked `source_type=RUNTIME`; legacy rows with null `source_type` remain visible as pre-provenance runtime records. Dashboard, Monitoring, Predictions, and runtime alert counters exclude non-runtime prediction sources. Experiment C per-flow tables were not imported or used for runtime counts.

## Navigation and Pages

The navigation is now Dashboard, Dataset, Models, Evaluation, Monitoring, Predictions, and Alerts.

Monitoring is an operational flow view. It shows runtime Total Flows, Normal, DDoS, PortScan, Alerts, the most recent detection timestamp, and active model when available. Its table uses actual stored timestamp/network/protocol/prediction/confidence fields. Flows without predictions remain visible with nullable prediction fields, while a truly empty database shows an explicit empty state.

Predictions is a classifier-result view. Its table includes prediction ID/time, available endpoints, class, confidence, model version, and alert state. Selecting an ID opens a full detail presentation with prediction and model information, actual stored class probabilities, flow metadata, raw stored features, provenance/context, and alert metadata.

The existing schema already stores the genuine probability vector returned by inference in `class_probabilities`; Phase 4 therefore required no probability migration. The UI displays only keys actually persisted. If a legacy response lacks the vector, it shows confidence and documents that full probabilities are unavailable; it never reconstructs them.

## Read APIs

- `GET /api/traffic-flows` — runtime monitoring list with `limit`, `offset`, predicted-class, protocol, source-IP, and destination-IP filters.
- `GET /api/monitoring/summary` — runtime flow/class/alert counters plus latest detection and active model.
- `GET /api/predictions` — bounded runtime classifier list with class, protocol, source-IP, and destination-IP filters.
- `GET /api/predictions/{id}` — joined flow, model, experiment/provenance, raw-feature, probability, and alert detail.

All list endpoints enforce the configured maximum page size. Existing prediction list semantics remain a JSON list for backward compatibility.

## Producing Legitimate Runtime Records

An empty runtime database is valid and is not seeded. With FastAPI running, legitimate live records can be produced through the existing capture pipeline:

```bash
PYTHONPATH=. .venv/bin/python scripts/run_live_capture.py \
  --interface <capture-interface> \
  --api-url http://127.0.0.1:8000 \
  --max-segments 1
```

Use `--list-interfaces` first when needed. This follows the existing capture → extraction → feature adaptation → runtime inference/persistence path and does not import Experiment C evaluation predictions.

## Verification

Automated verification:

```bash
PYTHONPATH=. .venv/bin/python -m pytest -q
```

The suite passes 138 tests. Phase 4 coverage includes empty and populated monitoring, unpredicted legacy flows, runtime/scientific separation, monitoring filters/pagination, prediction pagination/class and protocol filtering, joined flow/model/alert details, actual probability handling, missing nullable context, not-found behavior, API-client mapping, and friendly backend errors.

Manual verification used a temporary SQLite application database and one existing recorded live-capture row from `data/lab/live`. FastAPI and Streamlit were started locally. The browser confirmed the final navigation order, empty and populated Monitoring states, five runtime summary cards, active model/latest detection context, bounded tables and filters, Dashboard automatic visibility, the classifier-focused Predictions table, and all Prediction Detail sections with a stored 78-field feature representation. No scientific artifacts or evidence files were written.

## Phase Boundary

The existing confidence-threshold alert rule is unchanged. Phase 5 alert behavior, Phase 6 Login UX, and Phase 7 Export were not implemented.
