# Phase 3 — Thesis Presentation Layer

Completed: 2026-09-02  
Scope: Dashboard, Dataset, Models, and Evaluation presentation pages only. Monitoring refinements, alert-rule changes, full Login UX, and export remain outside Phase 3.

## Navigation

The Streamlit sidebar now uses one consistent primary navigation set: Dashboard, Dataset, Models, Evaluation, Predictions, and Alerts. The former Overview and singular Model labels were removed. Existing Predictions and Alerts pages remain available and functional.

## Pages

### Dashboard

Dashboard presents application/runtime data only: total processed flows, Normal/DDoS/PortScan prediction counts, total and active alert counts, active model identity, prediction distribution, recent activity, and recent predictions. Empty runtime storage renders zeros and explicit empty states. It never substitutes Experiment A/B/C evaluation counts.

### Dataset

Dataset is a read-only evidence presentation. It shows the canonical dataset identity, total rows, 78-feature count, label column, mapped class distribution, and expandable provenance. Missing database fields render as `Not available`; the page does not infer values or provide a synthetic upload flow.

### Models

Models displays the active Random Forest record, version/status, 78 ordered CICIDS2017-compatible inputs, Normal/DDoS/PortScan classes, artifact path/hash, real imported parameters, linked Experiment A, and available performance summary. Training Information is descriptive only and cannot trigger training.

### Evaluation

Evaluation provides a selector for:

- Experiment A — internal model evaluation using the selected tuned snapshot. Baseline/model-comparison context remains separate provenance and is not merged into the tuned metrics.
- Experiment B — scenario / ordered-contiguous holdout validation. The page explicitly states that this is not external production validation.
- Experiment C — External Virtual Laboratory Validation. The page explicitly states that the fitted pipeline was reused without retraining or preprocessing refit and presents the imported generalization failure and distribution/environment-shift limitation.

Each experiment shows available overall and per-class metrics, a confusion matrix with actual classes on rows and predicted classes on columns, notes/limitations, and expandable evidence provenance. NULL macro metrics remain `Not available`; the UI does not calculate replacements.

Experiment C is rendered from the database snapshot with accuracy `0.005404447594577833`, Normal recall `1.0`, DDoS recall `0.0`, PortScan recall `0.0`, and matrix `[[61,0,0],[10226,0,0],[1000,0,0]]`. The page formats accuracy as `0.5404%` but retains the exact numeric API/database value.

## Data Flow and API Endpoints

The presentation preserves the architecture:

```text
canonical scientific evidence → synchronizer → application database → FastAPI → Streamlit
```

Streamlit does not open files under `reports/` or `models/`. It consumes:

- `GET /api/dashboard/summary`
- `GET /api/dashboard/timeline`
- `GET /api/predictions`
- `GET /api/model` for sidebar identity
- `GET /api/models/active` for imported model presentation metadata
- `GET /api/datasets`
- `GET /api/experiments`
- `GET /api/experiments/{id}/evaluation`
- `GET /api/evidence-sources` for filtered read-only provenance

The two new Phase 3 endpoints are read-only and introduce no scientific mutation behavior.

## Reusable Presentation Mapping

`dashboard/presentation.py` centralizes null formatting, dataset/model field mapping, overall/per-class evaluation selection, confusion-matrix validation, notes parsing, and experiment-comparison rows. `dashboard/components/evidence.py` renders provenance consistently across Dataset, Models, and Evaluation.

## Tests

Phase 3 adds focused coverage for API client paths and filters, dataset/model mapping, Experiment A/B/C comparison selection, NULL metric preservation, Experiment C confusion-matrix ordering/values, provenance filtering, and the active-model presentation endpoint. Existing integration tests continue to cover empty and populated runtime dashboard summaries, predictions/alerts, and friendly API error mapping.

Verified command:

```bash
PYTHONPATH=. .venv/bin/python -m pytest -q
```

## Manual Verification

A temporary SQLite application database was populated through the Phase 2 evidence synchronizer, then FastAPI and Streamlit were started locally. Browser verification confirmed:

- Dashboard: API online, active `rf-v1.0`, all six runtime cards at zero, empty activity/recent-prediction states.
- Dataset: `cicids2017`, `2,830,743` rows, `78` features, label `label`, chart/table, provenance expander.
- Models: Random Forest, active status, 78 inputs, three classes, Experiment A linkage, performance summary, parameter table, provenance expander.
- Evaluation A: imported overall metrics and matrix loaded.
- Evaluation B: ordered-contiguous holdout wording and metrics loaded.
- Evaluation C: external-lab/no-refit warning, exact imported accuracy, unavailable macro metrics, per-class rows, matrix, limitations, and provenance loaded.
- Predictions and Alerts: navigation and empty states remained functional.

## Scientific Integrity

Phase 3 does not write under `models/`, `reports/`, or `data/lab/pcap/`. The active model artifact, model metadata, and final Experiment C evidence hashes were recorded before editing and verified after implementation.

## Known Remaining Gaps

- Monitoring and prediction-detail refinements are Phase 4.
- Alert-rule changes and acknowledgment refinements are Phase 5.
- Full administrator Login UX is Phase 6.
- Export/report functionality is Phase 7.
- Streamlit automatic refresh applies globally in the current shell; evidence pages remain read-only but may make repeated GET requests.
- Plain `pytest` import-path packaging remains unchanged; the documented `PYTHONPATH=.` invocation is authoritative.

Phase 3 stops here.
