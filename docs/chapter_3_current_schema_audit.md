# RF-NIDS Chapter III Current Implementation Audit

## 1. Audit Scope

This is a read-only audit of the repository state on 2026-09-27. No migration, inference, training, experiment, application-data, evidence, artifact, or source-code operation was run. The only created file is this report.

Authority was applied in the requested order: live PostgreSQL, Alembic, ORM, application/service code, then UI code. PostgreSQL live verification was attempted against the configured endpoint but was unavailable: `psql` is not installed, Docker inspection was unavailable because the local Docker socket was inaccessible, and a read-only Psycopg connection to `127.0.0.1:5432/rf_nids` was refused. Consequently, the final physical design below is authoritative for **Alembic head `20260917_10`**, but the live database column `Present in Live DB` is `NOT VERIFIED`, not an assertion of absence.

Primary evidence:

- ORM/base/config: `src/api/models.py:34-443`, `src/api/database.py:12-27`, `src/common/config.py:29-110`.
- Migration chain: `20260820_01` -> `20260820_02` -> `20260902_03` -> `20260902_04` -> `20260904_05` -> `20260904_06` -> `20260904_07` -> `20260905_08` -> `20260917_09` -> head `20260917_10`; see each migration's `revision` and `down_revision` declarations.
- Persistence behavior: `src/api/service.py:25-130`, `src/api/monitoring.py:54-213`, `src/api/runtime_validation.py:30-200`, `src/application/evidence_sync.py:640-676`.
- API/UI: `src/api/main.py:328-1165`, `dashboard/app.py:41-121`, `dashboard/components/sidebar.py:4-32`, and `dashboard/pages/*.py`.

## 2. Authoritative Current Table Inventory

The exact Alembic-head inventory is **12 application tables** (plus Alembic's own infrastructure table `alembic_version`, which is not an application entity). The expected name `flows` is not defined; the implemented name is `traffic_flows` (`src/api/models.py:346-359`; `migrations/versions/20260820_01_detection_backend.py:19-22`).

| No | Table | ORM Class | Present in Migration | Present in Live DB | Purpose |
|---:|---|---|---|---|---|
| 1 | `users` | `User` | Yes — `20260902_03:21-34` | NOT VERIFIED | Administrator identity and audit actor |
| 2 | `datasets` | `Dataset` | Yes — `20260902_03:36-55` | NOT VERIFIED | Imported canonical dataset metadata |
| 3 | `experiments` | `Experiment` | Yes — `20260902_03:57-81` | NOT VERIFIED | Imported scientific experiment metadata |
| 4 | `evaluation_results` | `EvaluationResult` | Yes — `20260902_03:83-113`; altered by `20260902_04:35-39` | NOT VERIFIED | Overall/per-class evaluation metrics |
| 5 | `evidence_sources` | `EvidenceSource` | Yes — `20260902_04:18-34` | NOT VERIFIED | File-level scientific evidence provenance |
| 6 | `models` | `ModelRecord` | Yes — `20260820_01:16-18`; altered by `20260902_03:115-127`, `20260902_04:40-42` | NOT VERIFIED | Registered model metadata and artifacts |
| 7 | `monitoring_sessions` | `MonitoringSession` | Yes — `20260904_05:17-50`; altered by `06:17-20`, `08:16-21`, `09:17-33`, `10:17-24` | NOT VERIFIED | Persistent runtime monitoring lifecycle |
| 8 | `traffic_flows` | `TrafficFlow` | Yes — `20260820_01:19-22`; altered by `20260820_02:13-21` | NOT VERIFIED | Captured flow metadata and 78-feature payload |
| 9 | `predictions` | `Prediction` | Yes — `20260820_01:23-26`; altered by `03:129-144`, `05:51-57`, `08:51-54` | NOT VERIFIED | Persisted classifications and provenance links |
| 10 | `alerts` | `Alert` | Yes — `20260820_01:27-30`; altered by `20260902_03:146-155` | NOT VERIFIED | Attack alerts and acknowledgement audit |
| 11 | `runtime_capture_artifacts` | `RuntimeCaptureArtifact` | Yes — `20260905_08:22-50` | NOT VERIFIED | Per-window PCAP/CSV provenance and processing state |
| 12 | `runtime_validation_runs` | `RuntimeValidationRun` | Yes — `20260904_07:16-50` | NOT VERIFIED | Server-derived runtime validation evidence |

All 12 names in the requested candidate list are present. No additional SQLAlchemy application table or Alembic-created application table was found.

## 3. ORM vs Migration vs Live DB Comparison

### Table-level comparison

- ORM tables missing from Alembic head: **none**.
- Alembic application tables missing from ORM: **none**.
- Live-only or ORM-only tables: **cannot be determined without a reachable live database**.
- `alembic_version` is expected migration infrastructure, not an ORM/domain table.

### Verified narrower mismatches

1. `runtime_validation_runs.evidence_json` is declared with portable PostgreSQL `JSONB` in the ORM (`src/api/models.py:27,340`), while migration `20260904_07` creates plain `sa.JSON()` (`migrations/versions/20260904_07_runtime_validation.py:41`). On PostgreSQL, Alembic head therefore specifies `JSON`, not `JSONB`.
2. `monitoring_sessions.selection_mode` retains migration-level server default `DEFAULT` after creation/alteration (`20260917_09_runtime_model_selection.py:18-23`; `20260917_10_expand_monitoring_selection_mode.py:18-24`), while the ORM defines only a Python-side default (`src/api/models.py:211`).
3. Counter/status defaults are frequently server-side in migrations but client-side in ORM: monitoring counters (`20260904_05:31-33` vs `models.py:233-235`), capture counters (`20260905_08:36-37` vs `models.py:277-278`), and runtime-validation fields (`20260904_07:26-36` vs `models.py:320-340`). This does not change columns or cardinalities, but inserts bypassing SQLAlchemy may behave differently.
4. Two valid database FKs lack matching ORM `relationship()` navigation: `runtime_validation_runs.model_id -> models.id` (`models.py:338`) has no `ModelRecord.validation_runs`/`RuntimeValidationRun.model`; and `predictions.monitoring_session_id -> monitoring_sessions.id` (`models.py:391-393`) has no corresponding ORM relationship on either class. The FKs and cardinalities remain physically valid.
5. `RuntimeValidationRun.model_id` has no dedicated relationship index in either the ORM or migration (`models.py:338`; `20260904_07:39,49-50`). All other FK columns have a dedicated or leading-column relationship index. This is a performance observation, not a missing FK.
6. The migration names the nullable `monitoring_sessions.artifact_key` unique constraint `uq_monitoring_sessions_artifact_key` (`20260905_08:21`); the ORM expresses the same uniqueness through `unique=True` without preserving that explicit name (`models.py:229`). Semantics match.

## 4. Detailed Table Structures

Unless marked nullable, mapped columns are non-nullable. All primary keys are integer `id` columns.

### `users` — `User`

- PK: `id`.
- FK: none.
- Important attributes: `name`, unique `email`, `password_hash`, `role`, `is_active`, `created_at`, `updated_at`.
- Constraints: `ck_users_role` permits only `ADMIN`; unique index `ix_users_email`; indexes `ix_users_email`, `ix_users_is_active`.
- ORM relationships: `datasets`, `acknowledged_alerts`, `monitoring_sessions`; no explicit cascade.
- Evidence: `src/api/models.py:34-55`; migration `20260902_03:21-34`.

### `datasets` — `Dataset`

- PK: `id`.
- FK: nullable `created_by_user_id -> users.id`, `ON DELETE SET NULL`.
- Important attributes: `name`; nullable `source_path`, `source_sha256`, `total_rows`, `total_features`, `label_column`, `class_distribution` (JSONB on PostgreSQL through ORM/migration portable type); timestamps.
- Constraints/indexes: indexes on `created_by_user_id` and `source_sha256`; no table-level unique/check constraint.
- ORM relationships: optional `created_by_user`; collection `experiments`; no explicit cascade.
- Evidence: `models.py:58-76`; migration `20260902_03:36-55`.

### `experiments` — `Experiment`

- PK: `id`.
- FK: nullable `dataset_id -> datasets.id`, `ON DELETE SET NULL`.
- Important attributes: unique `experiment_code`, `experiment_name`, `experiment_type`, `status`; nullable description/source hash/schema/import time; timestamps.
- Constraints/indexes: unique index `ix_experiments_experiment_code`; indexes on `dataset_id`, `source_sha256`.
- ORM relationships: optional `dataset`; collections `evaluation_results` (ORM `all, delete-orphan`), `models`, `predictions`.
- Evidence: `models.py:79-103`; migration `20260902_03:57-81`.

### `evaluation_results` — `EvaluationResult`

- PK: `id`.
- FK: non-null `experiment_id -> experiments.id`, `ON DELETE CASCADE`.
- Important attributes: nullable `class_name`, `metric_key`, accuracy/precision/recall/F1/macro/FPR/confusion counts, `confusion_matrix` JSONB, notes and evidence path/hash; `created_at`.
- Constraints/indexes: unique `(experiment_id, metric_key)` named `uq_evaluation_metric_key`; index on `experiment_id`. Because PostgreSQL permits multiple `NULL`s, the unique constraint does not prevent multiple rows with null `metric_key`.
- ORM relationship: required `experiment`; parent collection has `all, delete-orphan`.
- Evidence: `models.py:106-134`; migrations `20260902_03:83-113`, `20260902_04:35-39`.

### `evidence_sources` — `EvidenceSource`

- PK: `id`.
- FK/ORM relationship: none. `owner_type` + `owner_key` is an application-level polymorphic reference, not a database FK.
- Important attributes: `owner_type`, `owner_key`, `evidence_role`, `source_path`, `source_sha256`, nullable `schema_version`, `imported_at`.
- Constraints/indexes: unique `(owner_type, owner_key, evidence_role)`; unique `source_path`; indexes on `owner_type`, `owner_key`.
- Evidence: `models.py:137-152`; migration `20260902_04:18-34`; synchronization assigns owners at `evidence_sync.py:290-299`.

### `models` — `ModelRecord`

- PK: `id`.
- FK: nullable `experiment_id -> experiments.id`, `ON DELETE SET NULL`.
- Important attributes: `model_name`, unique `model_version`, `algorithm`, nullable metrics and `feature_count`, `is_active`, nullable artifact path/hash and `parameters` JSONB, `created_at`.
- Constraints/indexes: unique index on `model_version`; indexes on `is_active`, `experiment_id`.
- ORM relationships: optional `experiment`; collections `predictions` and `monitoring_sessions`, both `passive_deletes=True`. No ORM navigation to runtime validations.
- Evidence: `models.py:155-181`; migrations `20260820_01:16-18`, `20260902_03:115-127`, `20260902_04:40-42`.

### `monitoring_sessions` — `MonitoringSession`

- PK: `id`.
- FKs: non-null `model_id -> models.id` (`RESTRICT`); nullable `created_by_user_id -> users.id` (`SET NULL`).
- Important attributes: target/interface; `selection_mode`; selected model version/hash snapshot; lifecycle status/times/error/handle; extractor identity; artifact key/root and processing state; non-negative flow/prediction/alert counters.
- Constraints: status enumeration; three non-negative counter checks; nullable unique `artifact_key`; partial unique index on `status` for `STARTING|RUNNING|STOPPING`, enforcing at most one active session.
- Indexes: `model_id`, `created_by_user_id`, `status`, `(status, created_at)`, partial active-session unique index.
- ORM relationships: required `model`; optional `created_by_user`; `validation_runs` and `runtime_artifacts` with `all, delete-orphan`. No ORM `predictions` collection despite the FK from predictions.
- Evidence: `models.py:184-245`; migrations `20260904_05:17-57`, `20260904_06:17-20`, `20260905_08:16-21`, `20260917_09:17-33`, `20260917_10:17-24`.

### `traffic_flows` — `TrafficFlow`

- PK: `id`.
- FK: none.
- Important attributes: nullable capture session/interface/PCAP segment/time, source/destination IP/port, protocol; non-null `raw_features` JSONB and `created_at`.
- Constraints/indexes: indexes on capture session, capture time, source IP, destination IP; no checks/uniques.
- ORM relationship: optional single `prediction`, `all, delete-orphan`, `single_parent=True`, `passive_deletes=True`. One-to-at-most-one is physically enforced by unique `predictions.traffic_flow_id`.
- Evidence: `models.py:346-366`; migrations `20260820_01:19-22`, `20260820_02:13-21`.

### `predictions` — `Prediction`

- PK: `id`.
- FKs: required unique `traffic_flow_id -> traffic_flows.id` (`CASCADE`); required `model_id -> models.id` (`RESTRICT`); nullable `experiment_id -> experiments.id` (`SET NULL`); nullable `monitoring_session_id -> monitoring_sessions.id` (`SET NULL`); nullable `runtime_artifact_id -> runtime_capture_artifacts.id` (`SET NULL`).
- Important attributes: nullable `source_type`, `external_key`; constrained label; confidence; `class_probabilities` JSONB; prediction/create timestamps.
- Constraints: label in `Normal|DDoS|PortScan`; unique `traffic_flow_id`; unique `(source_type, external_key)`.
- Indexes: each non-flow FK (`model_id`, `experiment_id`, `monitoring_session_id`, `runtime_artifact_id`), `source_type`, `predicted_label`, and `(predicted_label, prediction_time)`. The unique constraint supplies the relationship lookup for `traffic_flow_id`.
- ORM relationships: required `traffic_flow`, required `model`, optional `experiment`, optional `runtime_artifact`, optional single `alert` with `all, delete-orphan`, `single_parent=True`, `passive_deletes=True`; no ORM monitoring-session navigation.
- Evidence: `models.py:369-415`; migrations `20260820_01:23-26`, `20260902_03:129-144`, `20260904_05:51-57`, `20260905_08:51-54`.

### `alerts` — `Alert`

- PK: `id`.
- FKs: required unique `prediction_id -> predictions.id` (`CASCADE`); nullable `acknowledged_by_user_id -> users.id` (`SET NULL`).
- Important attributes: constrained `severity`, title, description, constrained `status`, nullable acknowledgement time/user, created time.
- Constraints: severity in `HIGH|MEDIUM`; status in `ACTIVE|ACKNOWLEDGED`; unique `prediction_id`.
- Indexes: acknowledgement user, severity, status, `(status, severity)`.
- ORM relationships: required `prediction`; optional `acknowledged_by_user`.
- Evidence: `models.py:418-443`; migrations `20260820_01:27-30`, `20260902_03:146-155`.

### `runtime_capture_artifacts` — `RuntimeCaptureArtifact`

- PK: `id`.
- FK: non-null `monitoring_session_id -> monitoring_sessions.id`, `ON DELETE CASCADE`.
- Important attributes: artifact/window identity, constrained state, nullable PCAP/CSV relative paths/hashes/sizes, extractor identity, row counters, error fields, lifecycle timestamps.
- Constraints: state in `CAPTURING|CAPTURED|EXTRACTED|COMMITTED|FAILED`; unique `(monitoring_session_id, window_number)`; unique `artifact_key`.
- Indexes: `monitoring_session_id`; `(monitoring_session_id, state)`.
- ORM relationships: required `monitoring_session`; collection `predictions`.
- Evidence: `models.py:248-289`; migration `20260905_08:22-50`.

### `runtime_validation_runs` — `RuntimeValidationRun`

- PK: `id`.
- FKs: non-null `monitoring_session_id -> monitoring_sessions.id` (`CASCADE`); non-null `model_id -> models.id` (`RESTRICT`).
- Important attributes: scenario/status; target/interface; timing; PCAP/flow/prediction/alert/class counters; pipeline/detection results; extractor/adapter/model snapshots; `evidence_json`; notes.
- Constraints: enumerated scenario, status, pipeline result, detection result.
- Indexes: `monitoring_session_id`; `(monitoring_session_id, created_at)`. No `model_id` index.
- ORM relationship: required `monitoring_session` only; model FK has no `relationship()` definition. Parent monitoring collection uses `all, delete-orphan`.
- Evidence: `models.py:292-343`; migration `20260904_07:16-50`.

## 5. Verified Foreign Keys

| Child FK | Parent PK | Child optional? | Delete action | Relationship index |
|---|---|---:|---|---|
| `datasets.created_by_user_id` | `users.id` | Yes | SET NULL | Yes |
| `experiments.dataset_id` | `datasets.id` | Yes | SET NULL | Yes |
| `evaluation_results.experiment_id` | `experiments.id` | No | CASCADE | Yes |
| `models.experiment_id` | `experiments.id` | Yes | SET NULL | Yes |
| `monitoring_sessions.model_id` | `models.id` | No | RESTRICT | Yes |
| `monitoring_sessions.created_by_user_id` | `users.id` | Yes | SET NULL | Yes |
| `runtime_capture_artifacts.monitoring_session_id` | `monitoring_sessions.id` | No | CASCADE | Yes |
| `runtime_validation_runs.monitoring_session_id` | `monitoring_sessions.id` | No | CASCADE | Yes |
| `runtime_validation_runs.model_id` | `models.id` | No | RESTRICT | **No** |
| `predictions.traffic_flow_id` | `traffic_flows.id` | No | CASCADE | Unique constraint/index |
| `predictions.model_id` | `models.id` | No | RESTRICT | Yes |
| `predictions.experiment_id` | `experiments.id` | Yes | SET NULL | Yes |
| `predictions.monitoring_session_id` | `monitoring_sessions.id` | Yes | SET NULL | Yes |
| `predictions.runtime_artifact_id` | `runtime_capture_artifacts.id` | Yes | SET NULL | Yes |
| `alerts.prediction_id` | `predictions.id` | No | CASCADE | Unique constraint/index |
| `alerts.acknowledged_by_user_id` | `users.id` | Yes | SET NULL | Yes |

`evidence_sources.owner_type/owner_key` is deliberately excluded: there is no FK (`models.py:137-152`).

## 6. Verified Cardinalities

Cardinality describes what the FK nullability and uniqueness permit, not merely current sample data.

- `users 1 ---- 0..N datasets`; each dataset has `0..1` creator.
- `users 1 ---- 0..N monitoring_sessions`; each session has `0..1` creator.
- `users 1 ---- 0..N alerts` in the acknowledgement role; each alert has `0..1` acknowledging user.
- `datasets 1 ---- 0..N experiments`; each experiment references `0..1` dataset.
- `experiments 1 ---- 0..N evaluation_results`; each evaluation result references exactly `1` experiment.
- `experiments 1 ---- 0..N models`; each model references `0..1` experiment.
- `experiments 1 ---- 0..N predictions`; each prediction references `0..1` experiment.
- `models 1 ---- 0..N monitoring_sessions`; each monitoring session references exactly `1` model.
- `models 1 ---- 0..N predictions`; each prediction references exactly `1` model.
- `models 1 ---- 0..N runtime_validation_runs`; each validation run references exactly `1` model (FK-only; no ORM relationship navigation).
- `monitoring_sessions 1 ---- 0..N runtime_capture_artifacts`; each artifact references exactly `1` session.
- `monitoring_sessions 1 ---- 0..N runtime_validation_runs`; each run references exactly `1` session.
- `monitoring_sessions 1 ---- 0..N predictions`; each prediction references `0..1` session (FK-only in ORM navigation).
- `runtime_capture_artifacts 1 ---- 0..N predictions`; each prediction references `0..1` artifact.
- `traffic_flows 1 ---- 0..1 predictions`; every prediction references exactly `1` flow.
- `predictions 1 ---- 0..1 alerts`; every alert references exactly `1` prediction.

These follow directly from `models.py:68-69,85-86,112-113,167-168,208-218,264-265,316-338,382-395,428-437` and the matching migrations.

## 7. Historical Evidence Data Model

Historical/scientific presentation tables are `datasets`, `experiments`, `evaluation_results`, and `evidence_sources`; `models` is shared. `synchronize_evidence()` reads an allowlisted set of report/model files, validates them, and writes presentation records (`src/application/evidence_sync.py:27-61,640-676`). `evidence_sources` records file paths/hashes but has no physical FK to owners. Experiments link to the dataset, evaluations link to experiments, and the selected model can link to an experiment (`evidence_sync.py:407-420,596-618`).

Streamlit does **not** read scientific report files directly. Dataset/Evaluation/Model pages call the HTTP client (`dashboard/pages/dataset.py:10-46`, `evaluation.py:27-40,102-109`, `model_info.py:13-58`); that client calls FastAPI endpoints (`dashboard/api_client.py:113-135`), and those endpoints query presentation tables (`src/api/main.py:396-559`). Evidence files are read by the separate synchronization application path, not by page rendering.

## 8. Runtime Monitoring Data Model

Runtime tables are `monitoring_sessions`, `traffic_flows`, `predictions`, `alerts`, `runtime_capture_artifacts`, and `runtime_validation_runs`; `users` and `models` are shared. Runtime inference persists a new flow and prediction atomically and creates an alert only for `DDoS`/`PortScan` (`src/api/service.py:11,76-130`). Monitoring freezes model identity on each session (`src/api/monitoring.py:114-133`). Runtime artifacts identify capture/extraction windows; predictions optionally link to both their session and artifact (`src/api/runtime_monitoring.py:392-520`). Validation derives its evidence from committed artifacts and their predictions (`src/api/runtime_validation.py:77-200`).

The two paths are separated by purpose and ingestion: evidence synchronization imports frozen scientific files into presentation tables, while monitoring/inference writes operational records. They meet at shared model metadata and, optionally, `predictions.experiment_id`; normal runtime persistence does not set `experiment_id` (`src/api/service.py:88-98`).

## 9. ERD-Ready Specification

### Full physical implementation ERD (authoritative)

```text
ENTITY users
  PK id
  FK none
  ATTR name, email, password_hash, role, is_active, created_at, updated_at

ENTITY datasets
  PK id
  FK created_by_user_id -> users.id [nullable, SET NULL]
  ATTR name, source_path, source_sha256, total_rows, total_features,
       label_column, class_distribution, created_at, updated_at

ENTITY experiments
  PK id
  FK dataset_id -> datasets.id [nullable, SET NULL]
  ATTR experiment_code, experiment_name, experiment_type, description, status,
       source_path, source_sha256, schema_version, imported_at, created_at, updated_at

ENTITY evaluation_results
  PK id
  FK experiment_id -> experiments.id [required, CASCADE]
  ATTR class_name, metric_key, accuracy, precision_score, recall_score, f1_score,
       macro_precision, macro_recall, macro_f1, false_positive_rate,
       true_positive, true_negative, false_positive, false_negative,
       confusion_matrix, notes, source_path, source_sha256, created_at

ENTITY evidence_sources
  PK id
  FK none
  ATTR owner_type, owner_key, evidence_role, source_path, source_sha256,
       schema_version, imported_at

ENTITY models
  PK id
  FK experiment_id -> experiments.id [nullable, SET NULL]
  ATTR model_name, model_version, algorithm, accuracy, macro_f1, ddos_recall,
       portscan_recall, feature_count, is_active, artifact_path, artifact_sha256,
       parameters, created_at

ENTITY monitoring_sessions
  PK id
  FK model_id -> models.id [required, RESTRICT]
  FK created_by_user_id -> users.id [nullable, SET NULL]
  ATTR target_ip, interface_name, selection_mode, selected_model_version,
       selected_model_sha256, status, started_at, stopped_at, created_at, updated_at,
       last_error, runtime_handle, extractor_name, extractor_version,
       extractor_identity, artifact_key, artifact_root, processing_state,
       latest_processing_at, flow_count, prediction_count, alert_count

ENTITY runtime_capture_artifacts
  PK id
  FK monitoring_session_id -> monitoring_sessions.id [required, CASCADE]
  ATTR artifact_key, window_number, state, pcap_relative_path, pcap_sha256,
       pcap_size, csv_relative_path, csv_sha256, csv_size, extractor_identity,
       extracted_row_count, adapted_row_count, error_stage, error_message,
       capture_started_at, capture_finished_at, extraction_finished_at,
       committed_at, created_at

ENTITY runtime_validation_runs
  PK id
  FK monitoring_session_id -> monitoring_sessions.id [required, CASCADE]
  FK model_id -> models.id [required, RESTRICT]
  ATTR scenario, status, target_ip, interface_name, started_at, finished_at,
       pcap_files_processed, pcap_bytes_processed, flows_extracted,
       flows_adapter_valid, predictions_committed, alerts_committed,
       normal_predictions, portscan_predictions, ddos_predictions,
       pipeline_result, detection_result, extractor_identity, adapter_identity,
       model_version, evidence_json, notes, created_at

ENTITY traffic_flows
  PK id
  FK none
  ATTR capture_session_id, capture_interface, pcap_segment, capture_time,
       source_ip, source_port, destination_ip, destination_port, protocol,
       raw_features, created_at

ENTITY predictions
  PK id
  FK traffic_flow_id -> traffic_flows.id [required, unique, CASCADE]
  FK model_id -> models.id [required, RESTRICT]
  FK experiment_id -> experiments.id [nullable, SET NULL]
  FK monitoring_session_id -> monitoring_sessions.id [nullable, SET NULL]
  FK runtime_artifact_id -> runtime_capture_artifacts.id [nullable, SET NULL]
  ATTR source_type, external_key, predicted_label, confidence_score,
       class_probabilities, prediction_time, created_at

ENTITY alerts
  PK id
  FK prediction_id -> predictions.id [required, unique, CASCADE]
  FK acknowledged_by_user_id -> users.id [nullable, SET NULL]
  ATTR severity, title, description, status, acknowledged_at, created_at
```

### Thesis-level option

For section 3.2.1, the safest recommendation is the full 12-entity ERD because every item is persistent and thesis-relevant. Visually group core/shared entities (`users`, `models`, `monitoring_sessions`, `traffic_flows`, `predictions`, `alerts`) and supporting/provenance entities (`datasets`, `experiments`, `evaluation_results`, `evidence_sources`, `runtime_capture_artifacts`, `runtime_validation_runs`). A simplified figure may collapse the latter visually, but must be labelled a conceptual view; it is not the physical implementation ERD.

Do not include tcpdump, CICFlowMeter V3, Feature Adapter, Random Forest engine, FastAPI, or Streamlit as ERD entities: none is a table.

## 10. ERD-to-LRS Transformation

| Parent PK | Child FK | Cardinality | Transformation |
|---|---|---|---|
| `users.id` | `datasets.created_by_user_id` | 1 : 0..N; child optional | Copy parent key as nullable FK |
| `users.id` | `monitoring_sessions.created_by_user_id` | 1 : 0..N; child optional | Copy parent key as nullable FK |
| `users.id` | `alerts.acknowledged_by_user_id` | 1 : 0..N; child optional | Copy parent key as nullable FK |
| `datasets.id` | `experiments.dataset_id` | 1 : 0..N; child optional | Copy parent key as nullable FK |
| `experiments.id` | `evaluation_results.experiment_id` | 1 : 0..N; child required | Copy parent key as non-null FK |
| `experiments.id` | `models.experiment_id` | 1 : 0..N; child optional | Copy parent key as nullable FK |
| `experiments.id` | `predictions.experiment_id` | 1 : 0..N; child optional | Copy parent key as nullable FK |
| `models.id` | `monitoring_sessions.model_id` | 1 : 0..N; child required | Copy parent key as non-null FK |
| `models.id` | `predictions.model_id` | 1 : 0..N; child required | Copy parent key as non-null FK |
| `models.id` | `runtime_validation_runs.model_id` | 1 : 0..N; child required | Copy parent key as non-null FK |
| `monitoring_sessions.id` | `runtime_capture_artifacts.monitoring_session_id` | 1 : 0..N; child required | Copy parent key as non-null FK |
| `monitoring_sessions.id` | `runtime_validation_runs.monitoring_session_id` | 1 : 0..N; child required | Copy parent key as non-null FK |
| `monitoring_sessions.id` | `predictions.monitoring_session_id` | 1 : 0..N; child optional | Copy parent key as nullable FK |
| `runtime_capture_artifacts.id` | `predictions.runtime_artifact_id` | 1 : 0..N; child optional | Copy parent key as nullable FK |
| `traffic_flows.id` | `predictions.traffic_flow_id` | 1 : 0..1; child required | Copy parent key as non-null **unique** FK |
| `predictions.id` | `alerts.prediction_id` | 1 : 0..1; child required | Copy parent key as non-null **unique** FK |

No transformation is defined for `evidence_sources.owner_key` because it is not an FK.

## 11. Final LRS Specification

```text
USERS
PK: id
FK: —
Attributes: name, email, password_hash, role, is_active, created_at, updated_at
Relationships: creates datasets/sessions; acknowledges alerts

DATASETS
PK: id
FK: created_by_user_id -> users.id
Attributes: name, source_path, source_sha256, total_rows, total_features,
            label_column, class_distribution, created_at, updated_at
Relationships: belongs optionally to creator; has experiments

EXPERIMENTS
PK: id
FK: dataset_id -> datasets.id
Attributes: experiment_code, experiment_name, experiment_type, description,
            status, source_path, source_sha256, schema_version, imported_at, timestamps
Relationships: belongs optionally to dataset; has evaluations/models/predictions

EVALUATION_RESULTS
PK: id
FK: experiment_id -> experiments.id
Attributes: metric_key, class_name, metric fields, confusion_matrix, notes,
            source_path, source_sha256, created_at
Relationships: belongs to one experiment

EVIDENCE_SOURCES
PK: id
FK: —
Attributes: owner_type, owner_key, evidence_role, source_path, source_sha256,
            schema_version, imported_at
Relationships: no FK relationship; logical owner reference only

MODELS
PK: id
FK: experiment_id -> experiments.id
Attributes: model_name, model_version, algorithm, metrics, feature_count,
            is_active, artifact_path, artifact_sha256, parameters, created_at
Relationships: optional experiment; has sessions/predictions/validation runs

MONITORING_SESSIONS
PK: id
FK: model_id -> models.id; created_by_user_id -> users.id
Attributes: target/interface, model snapshot, status/times, extractor/artifact state,
            flow/prediction/alert counts
Relationships: required model; optional creator; has artifacts/validations/predictions

RUNTIME_CAPTURE_ARTIFACTS
PK: id
FK: monitoring_session_id -> monitoring_sessions.id
Attributes: artifact/window/state, PCAP/CSV provenance, row counts, errors, timestamps
Relationships: belongs to one session; has predictions

RUNTIME_VALIDATION_RUNS
PK: id
FK: monitoring_session_id -> monitoring_sessions.id; model_id -> models.id
Attributes: scenario/status, target/interface, counters, validation outcomes,
            extractor/adapter/model snapshots, evidence_json, notes, timestamps
Relationships: belongs to one session and one model

TRAFFIC_FLOWS
PK: id
FK: —
Attributes: capture provenance, endpoints, protocol, raw_features, created_at
Relationships: has zero or one prediction

PREDICTIONS
PK: id
FK: traffic_flow_id -> traffic_flows.id; model_id -> models.id;
    experiment_id -> experiments.id; monitoring_session_id -> monitoring_sessions.id;
    runtime_artifact_id -> runtime_capture_artifacts.id
Attributes: source_type, external_key, predicted_label, confidence_score,
            class_probabilities, prediction_time, created_at
Relationships: one flow/model; optional experiment/session/artifact; optional alert

ALERTS
PK: id
FK: prediction_id -> predictions.id; acknowledged_by_user_id -> users.id
Attributes: severity, title, description, status, acknowledged_at, created_at
Relationships: belongs to one prediction; optional acknowledging user
```

## 12. Normalization Assessment

The schema is reasonably relational but should not be claimed as formally proven 3NF without a complete functional-dependency analysis of the application domain.

- **1NF:** scalar relational columns are used, but JSON/JSONB intentionally stores structured payloads: `datasets.class_distribution`, `evaluation_results.confusion_matrix`, `models.parameters`, `traffic_flows.raw_features`, `predictions.class_probabilities`, and `runtime_validation_runs.evidence_json`. These are atomic application payloads at the chosen design boundary, particularly for high-dimensional features and immutable provenance, but are not normalized into child relations.
- **2NF:** every table has a single-column surrogate PK, so no non-key attribute depends on only part of a composite PK. Composite unique constraints are alternate keys, not primary keys.
- **3NF:** entity separation generally avoids direct transitive dependencies. Some intentional snapshots/denormalization exist: session `selected_model_version/sha256`, validation `model_version`, and session counters duplicate derivable facts. They preserve historical/audit identity and efficient status display. `evidence_sources.owner_type/owner_key` is a polymorphic logical reference without referential integrity. Thus the defensible thesis statement is “reasonably consistent with 1NF–3NF principles, with deliberate JSON payloads and audit snapshots,” not strict formal 3NF compliance.

## 13. Final Thesis Database Specification Table

**Tabel 3.1 Spesifikasi Tabel Basis Data Sistem RF-NIDS**

| No | Table | Function |
|---:|---|---|
| 1 | `users` | Stores administrator identity and audit attribution |
| 2 | `datasets` | Stores imported canonical dataset metadata |
| 3 | `experiments` | Stores imported experiment metadata and provenance |
| 4 | `evaluation_results` | Stores overall and per-class evaluation metrics |
| 5 | `evidence_sources` | Stores canonical evidence-file provenance and hashes |
| 6 | `models` | Registers model versions, metrics, artifacts, and active state |
| 7 | `monitoring_sessions` | Records runtime monitoring lifecycle and frozen model selection |
| 8 | `traffic_flows` | Stores flow metadata and adapted feature payloads |
| 9 | `predictions` | Stores model classifications, probabilities, and runtime links |
| 10 | `alerts` | Stores deterministic attack alerts and acknowledgement state |
| 11 | `runtime_capture_artifacts` | Stores per-window PCAP/CSV extraction provenance |
| 12 | `runtime_validation_runs` | Stores server-derived runtime validation evidence and outcomes |

## 14. Class Diagram Recommendation

For a persistence-oriented class diagram, include all 12 ORM classes: `User`, `Dataset`, `Experiment`, `EvaluationResult`, `EvidenceSource`, `ModelRecord`, `MonitoringSession`, `RuntimeCaptureArtifact`, `RuntimeValidationRun`, `TrafficFlow`, `Prediction`, and `Alert` (`src/api/models.py:34-443`). Use the attributes and relationships in Sections 4 and 6. Do not invent entity methods: these ORM classes define mapped attributes/relationships only, apart from no domain behaviors.

For an academically clearer component/domain class diagram, show those entity classes plus separate service/controller classes only when actually present: `MonitoringService` (`src/api/monitoring.py:54-213`), `RuntimeCollectorController` (`src/api/runtime_monitoring.py:313-630`), `RuntimeValidationService` (`src/api/runtime_validation.py:30-200`), `InferenceEngine` (used at `src/api/main.py:251-303`), and `RFNIDSClient` (`dashboard/api_client.py:25-226`). Methods such as login/logout are FastAPI route functions, while prediction persistence is the function `persist_predictions`; they are not methods on `User` or `Prediction`. Keep component dependencies separate from ERD associations.

## 15. Use Case Audit

| Administrator capability | Verdict | Current evidence / correction |
|---|---|---|
| Login | SUPPORTED | Login form `dashboard/app.py:41-68`; API `main.py:337-365` |
| View Dashboard | SUPPORTED | `dashboard/pages/overview.py:10-31` |
| View Dataset | SUPPORTED | Read-only presentation `dashboard/pages/dataset.py:10-48` |
| Upload Dataset | NOT SUPPORTED | Dataset client/API expose GET/export only (`api_client.py:122-129,213-217`; `main.py:494-540,973-1026`) |
| Train Random Forest through UI | NOT SUPPORTED | Models page explicitly says training cannot be triggered (`model_info.py:39-52`); no training endpoint |
| View Models | SUPPORTED | `model_info.py:13-69`; `main.py:396-474` |
| Select/activate model | PARTIAL | Monitoring page can select a registered runtime model per session (`monitoring.py:72-120`); there is no endpoint/UI to change global `models.is_active`. Startup synchronization sets active state internally (`service.py:25-50`). |
| View Evaluation | SUPPORTED | `evaluation.py:27-109` |
| Start Monitoring | SUPPORTED | UI `monitoring.py:62-121`; API `main.py:820-873` |
| Stop Monitoring | SUPPORTED | UI `monitoring.py:161-164`; API `main.py:875-885` |
| View Predictions | SUPPORTED | `predictions.py:91-127`; API list `main.py:600-621` |
| View Prediction Detail | SUPPORTED | `predictions.py:28-88,122-127`; API `main.py:943-953` |
| View Alerts | SUPPORTED | `alerts.py:84-140`; API `main.py:954-972,1084-1092` |
| Acknowledge Alert | SUPPORTED | UI `alerts.py:142-150`; API `main.py:1093-1107` |
| Export CSV/JSON | SUPPORTED | Dataset JSON, evaluation JSON/CSV, prediction CSV/JSON API, alert CSV/JSON API (`api_client.py:213-226`; `main.py:973-1082`). UI directly offers dataset JSON, evaluation JSON/CSV, and filtered prediction/alert CSV. |

`POST /api/predict` and batch inference are implemented (`main.py:561-599`) but are internal/API processing, not an administrator UI use case. tcpdump, CICFlowMeter, feature adaptation, inference, persistence, and alert generation are internal system processes.

## 16. Current UI/Page Inventory

Login is a separate unauthenticated view labelled “Administrator login” (`dashboard/app.py:41-53`). After authentication, exact navigation labels are (`dashboard/components/sidebar.py:16-20`):

1. `Dashboard`
2. `Dataset`
3. `Models`
4. `Evaluation`
5. `Monitoring`
6. `Predictions`
7. `Alerts`

`dashboard/app.py:109-114` maps those labels to the seven page modules. Logout, auto-refresh, and refresh are sidebar controls, not pages (`sidebar.py:21-31`).

## 17. Chapter III Draft Corrections

| Draft assumption | Verdict | Required correction |
|---|---|---|
| 1. Table named `flows` | INCORRECT | Replace with exact table name `traffic_flows`. |
| 2. Ten database tables | OUTDATED | Use 12 application tables at Alembic head. |
| 3. `runtime_validation_runs` included | CORRECT | Retain as a supporting runtime evidence entity. |
| 4. `evaluation_results` included | CORRECT | Retain as historical scientific presentation entity. |
| 5. `monitoring_sessions` included | CORRECT | Retain as a core runtime entity. |
| 6. No `evidence_sources` entity | INCORRECT | Add it, while showing that owner fields are not FKs. |
| 7. No `runtime_capture_artifacts` entity | INCORRECT | Add it and its session/prediction relationships. |
| 8. Dataset can be uploaded by Administrator | INCORRECT | Describe read-only viewing/export of synchronized evidence; remove upload use case. |
| 9. Random Forest can be trained from dashboard | INCORRECT | Remove UI training use case; page explicitly presents recorded configuration only. |
| 10. tcpdump/CICFlowMeter operations shown as Use Cases | INCORRECT | Move them to internal activity/component/sequence flow, not actor use cases. |
| 11. Placeholder Class Diagram attributes/methods | OUTDATED | Replace with verified ORM attributes/associations and real service operations; do not attach invented login/predict/save/validate methods to entities. |

Further corrections:

- Do not draw a database relationship from `evidence_sources` to other entities unless labelled “logical/unconstrained”; no FK exists.
- Show flow-to-prediction and prediction-to-alert as one-to-zero-or-one, not one-to-many.
- Show model-to-validation-run even though ORM navigation is missing; the database FK is authoritative.
- Show session-to-prediction even though ORM navigation is missing; the database FK is authoritative.
- Use optionality on dataset creator, experiment dataset, model experiment, prediction experiment/session/artifact, and alert acknowledging user.
- Keep all 12 tables in the physical ERD/LRS/database specification. Components must not become entities.

## 18. Final Recommendation

Use the same exact 12 persistent entities in sections 3.2.1 (full physical ERD), 3.2.2 (ERD-to-LRS), 3.2.3 (LRS), and 3.2.5 (database specification). For 3.3.4, use the 12 ORM entity classes if the figure is a persistence class diagram; if the thesis needs behavior, add the verified service/controller classes in a separate layer rather than inventing methods on entities.

Visually distinguish:

- **Core/shared:** `users`, `models`.
- **Historical/scientific evidence presentation:** `datasets`, `experiments`, `evaluation_results`, `evidence_sources`.
- **Runtime monitoring/detection:** `monitoring_sessions`, `traffic_flows`, `predictions`, `alerts`, `runtime_capture_artifacts`, `runtime_validation_runs`.

For a compact thesis figure, these can be grouped into packages or color bands, but no persistent table should be silently omitted from a diagram claimed to represent the physical implementation.

# CHAPTER III FINAL FACTS

FINAL_TABLE_COUNT:
12 application tables at Alembic head (excluding `alembic_version`).

FINAL_TABLE_NAMES:
`users`, `datasets`, `experiments`, `evaluation_results`, `evidence_sources`, `models`, `monitoring_sessions`, `traffic_flows`, `predictions`, `alerts`, `runtime_capture_artifacts`, `runtime_validation_runs`.

FINAL_ERD_ENTITIES:
Full physical ERD: all 12 final table names above. Group supporting/provenance entities visually; do not rename or omit them.

FINAL_LRS_ENTITIES:
All 12 final table names above.

FINAL_CLASS_DIAGRAM_CLASSES:
Persistence view: `User`, `Dataset`, `Experiment`, `EvaluationResult`, `EvidenceSource`, `ModelRecord`, `MonitoringSession`, `TrafficFlow`, `Prediction`, `Alert`, `RuntimeCaptureArtifact`, `RuntimeValidationRun`. Optional behavioral layer: `MonitoringService`, `RuntimeCollectorController`, `RuntimeValidationService`, `InferenceEngine`, `RFNIDSClient`.

FINAL_UI_PAGES:
Separate `Login` view; authenticated navigation: `Dashboard`, `Dataset`, `Models`, `Evaluation`, `Monitoring`, `Predictions`, `Alerts`.

FINAL_ADMIN_USE_CASES:
Login/logout; view dashboard; view/export dataset metadata; view models; select a registered model for a monitoring session; view/export evaluation; start/stop monitoring; view predictions and prediction detail; export predictions; view alerts and alert detail; acknowledge alerts; export alerts; initiate/complete and view runtime validation from the Monitoring page.

INTERNAL_SYSTEM_PROCESSES:
Evidence synchronization; active-model registration; tcpdump capture; PCAP handling; CICFlowMeter V3 extraction; 78-feature adaptation; Random Forest inference; atomic flow/prediction persistence; deterministic DDoS/PortScan alert generation; counter updates; runtime validation evidence derivation.

KNOWN_SCHEMA_MISMATCHES:
No table-level ORM/Alembic mismatch. Narrow mismatches: runtime validation `evidence_json` is ORM JSONB versus migration JSON; several ORM Python defaults correspond to migration server defaults; `runtime_validation_runs.model_id` and `predictions.monitoring_session_id` are valid FKs without ORM `relationship()` navigation; validation `model_id` lacks an index; monitoring artifact-key uniqueness has different naming expression. Live drift is unknown because PostgreSQL was unavailable.

CHAPTER_III_REQUIRED_CORRECTIONS:
Replace `flows` with `traffic_flows`; replace “ten tables” with 12; add `evidence_sources` and `runtime_capture_artifacts`; retain `evaluation_results`, `monitoring_sessions`, and `runtime_validation_runs`; correct optionalities and one-to-zero-or-one relationships; remove dataset upload and UI model-training claims; describe model selection as per-session selection rather than global activation; move tcpdump/CICFlowMeter/adapter/inference to internal system flow; replace placeholder entity methods/attributes with verified classes, fields, FKs, and services.

AUDIT_CONFIDENCE:
HIGH for current source, ORM, Alembic-head schema, endpoints, and UI; MEDIUM for deployed/live schema because it could not be reached.

AUDIT_LIMITATIONS:
The configured PostgreSQL endpoint refused connection, `psql` was unavailable, and Docker state could not be inspected due to socket access. Therefore `\dt`, `\d+`, live Alembic revision, live constraints/indexes, and possible live drift were not verified. No migrations were run. Conclusions about the physical target schema derive from the complete current Alembic chain through `20260917_10`, cross-checked against current ORM metadata and application use.
