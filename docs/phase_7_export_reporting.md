# Phase 7 — Administrator Export / Reporting

Completed: 2026-09-02  
Scope: deterministic, administrator-only exports of application presentation data. No Phase 8 work is included.

## Architecture and Security Boundary

Exports follow the existing thesis architecture:

```text
immutable scientific evidence
  → allowlisted evidence synchronization
  → application database
  → authenticated FastAPI export response
  → Streamlit download button
```

Streamlit never reads `models/`, `reports/`, or scientific source files. Every export endpoint depends on the existing `require_admin` authentication dependency. Missing/invalid sessions receive HTTP 401 and non-administrator users receive HTTP 403. Exported administrator identity is limited to ID, name, and email; password hashes, bearer tokens, and session internals are never serialized. Runtime `/api/predict` and `/api/predict/batch` behavior is unchanged.

## Supported Exports

| Data | Endpoint | Format | Filename |
|---|---|---|---|
| Dataset metadata | `GET /api/export/dataset` | JSON | `rf_nids_dataset.json` |
| Evaluation | `GET /api/export/experiments/{id}?format=json` | JSON | `rf_nids_experiment_a_evaluation.json` (and B/C) |
| Evaluation metrics | same endpoint with `format=csv` | CSV | `rf_nids_experiment_a_metrics.csv` (and B/C) |
| Confusion matrix | `GET /api/export/experiments/{id}/confusion-matrix` | CSV | `rf_nids_experiment_a_confusion_matrix.csv` (and B/C) |
| Predictions | `GET /api/export/predictions` | CSV (default) or JSON | `rf_nids_predictions_YYYY-MM-DD.*` |
| Alerts | `GET /api/export/alerts` | CSV (default) or JSON | `rf_nids_alerts_YYYY-MM-DD.*` |

Responses use `Content-Disposition: attachment`, the appropriate JSON/CSV content type, and record-count/maximum-record headers. JSON includes UTC export time, public administrator identity, export schema version `1.0`, active filters, record count, and the maximum size.

Dataset JSON contains only stored identity, row/feature counts, label column, class distribution, source path/hash, and database import timestamp. Missing values remain JSON `null`.

Evaluation JSON contains experiment metadata, stored overall/per-class results, confusion matrix, notes, and all database provenance rows ordered by evidence role. CSV emits the stored metrics only; NULL remains an empty CSV field. Confusion-matrix CSV explicitly labels rows as actual classes and columns as predicted classes. Experiment C is exported under its unchanged `EXPERIMENT_C` identity and retains its external-validation/no-refit description, exact zero DDoS and PortScan recall, NULL macro values, and imported matrix.

Prediction exports contain runtime rows and legacy runtime-compatible rows only. Fields cover prediction/time, endpoints, protocol, label, confidence, stored class probabilities, model/version, source type, optional experiment context, and alert state. Raw features are deliberately excluded from bulk export.

Alert exports contain alert/time/type/severity/status/confidence, related prediction, endpoint/protocol metadata, acknowledgment time, and acknowledging administrator name/email when available.

## Filter Consistency and Ordering

The list and export endpoints share the same SQL query builders. Prediction exports support class, protocol, source IP, and destination IP. Alert exports support attack type (`predicted_label`), severity, status, source IP, and destination IP. Empty strings are omitted by the dashboard client exactly as for list requests.

List pages remain newest-first for operator use. Exports are deterministically sorted by ascending database ID. Identical database state and filters therefore produce identical scientific/data rows; only explicit export metadata and the date-based runtime filename can change.

## Size Behavior

Prediction and alert exports are bounded to 10,000 matching rows per request. The database applies the limit before records are materialized. `X-Export-Maximum-Records` documents the bound, and JSON metadata repeats it. This simple bounded strategy is appropriate for the local thesis prototype; streaming/paginated archive jobs are intentionally outside Phase 7.

## Streamlit UX

- Dataset: **Download metadata (JSON)**.
- Evaluation: **Download evaluation JSON**, **Download metrics CSV**, and **Download confusion matrix CSV** when a matrix exists.
- Predictions: **Export current filtered predictions**.
- Alerts: **Export current filtered alerts**.

All bytes come from FastAPI using the current bearer session. Logging out removes access to both pages and endpoints through the Phase 6 guard.

## Tests and Verification

The Phase 7 integration coverage verifies dataset authorization/content; A/B/C availability; exact Experiment C negative metrics; NULL preservation; confusion-matrix orientation/content; prediction/alert authorization and filter parity; acknowledging administrator identity; absence of password/token fields; deterministic ordering; invalid experiment handling; empty CSV headers; and response download headers/content types. Dashboard client coverage verifies authenticated binary download handling and filter forwarding.

Verified command:

```bash
PYTHONPATH=. .venv/bin/python -m pytest -q
```

Result: **156 passed**, 329 existing dependency/deprecation warnings, in 11.77 seconds.

API startup and Streamlit import/startup were smoke-checked locally. Download content and logged-out authorization are covered through the same FastAPI application using integration tests; no scientific source is read by Streamlit.

## Scientific Integrity Verification

| Frozen artifact | SHA-256 before | SHA-256 after | Result |
|---|---|---|---|
| `models/random_forest_active.joblib` | `73d86cb98f35c228d6e619e0f746a2b659d94deabe86d57e801c58bcf935f647` | same | Unchanged |
| `models/model_metadata.json` | `c632b16d30efb8f5a642070520c43cc1caaf36cbead33bddf9b5359b0fb531f2` | same | Unchanged |
| `reports/metrics/experiment_c_v3_final.json` | `6e091fdc1f0113fd34403d60dafdea83e6aa6ee957bf4a77632da31c6478f02b` | same | Unchanged |

Phase 7 created no output under `models/`, `reports/`, or `data/lab/pcap/`. Export responses are generated in memory.

## Known Limitations

- The 10,000-row bound does not provide continuation tokens or a multi-file archive.
- Export time is intentionally variable metadata; runtime filenames use the current UTC date.
- Time/date filtering was not added because the current Predictions/Alerts UI has no such filter; Phase 7 avoids a second filtering system.
- PDF and a report-builder page are not implemented.
- Sessions remain process-local as documented in Phase 6.

Phase 7 stops here.
