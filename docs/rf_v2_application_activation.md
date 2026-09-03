# RF-v2 Application Activation

Activated: 2026-09-03
Scope: controlled reopening of the thesis application freeze for model-version integration only.

## Reason for reopening the freeze

Experiment D D6 showed that RF-v2 improved external generalization relative to RF-v1 on the identical sealed final-test rows. The application freeze was explicitly reopened only to make this already-frozen model the default for new runtime predictions. Authentication, database schema, inference preprocessing, feature adaptation, alert semantics, historical predictions, Experiment C, and Experiment D scientific evidence remain unchanged.

This activation is not a claim that RF-v2 is perfect or that D6 results guarantee runtime behavior. D6 PortScan recall improved strongly to 0.967963. DDoS recall improved from zero but remains weak at 0.076928. Normal recall was 0.933333.

## Model identities

| Role | Version | Artifact | SHA-256 |
|---|---|---|---|
| Previous/default rollback | `rf-v1.0` | `models/random_forest_active.joblib` | `73d86cb98f35c228d6e619e0f746a2b659d94deabe86d57e801c58bcf935f647` |
| Active runtime | `rf-v2.0` | `models/experiment_d/random_forest_rf_v2.joblib` | `fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31` |

RF-v1 was not overwritten, renamed, or deleted. `random_forest_tuned.joblib` and `random_forest_baseline.joblib` are also unchanged.

## Derived runtime metadata

The frozen scientific metadata remains `models/experiment_d/random_forest_rf_v2_metadata.json` with SHA-256 `0bef82122fbebede27cd14f9dae925f4f48f3f1700c4b6c46ae29f238731e2c2`.

The separate application artifact is:

- path: `models/experiment_d/random_forest_rf_v2_runtime_metadata.json`;
- SHA-256: `1c97466a9c987b161e516557d41e63c428d987129f39dcdeb6a735c9097443c0`;
- schema: `rf_nids_runtime_model_metadata`, version 1;
- application version: `rf-v2.0`;
- features: the exact 78 frozen ordered features;
- classes: Normal, DDoS, PortScan;
- scientific source: Experiment D and frozen RF-v2 identity `3903c87a9eb46e21b56672c08bd9e15d678d598898ea378d0cd1b5c4fc0633cf`.

`InferenceEngine` now validates the configured artifact path, artifact hash, feature count/order, classes, frozen scientific-metadata hash, and D6 metrics-document hash. It still uses the stored sklearn pipeline for preprocessing and prediction; no fit/refit path was added.

## Activation mechanism

RF-v2 is selected through the existing configuration boundary. Default `Settings`, `.env.example`, and Docker Compose now pair:

```text
MODEL_PATH=models/experiment_d/random_forest_rf_v2.joblib
MODEL_METADATA_PATH=models/experiment_d/random_forest_rf_v2_runtime_metadata.json
```

At API startup the application loads this pair once, verifies it, registers/updates `rf-v2.0`, and marks other model records inactive. There is no request-supplied model selector and no filesystem path exposed through the API.

The default files and Compose configuration make RF-v2 active for all new predictions after the API starts/restarts. Existing deployments with explicit environment overrides retain those overrides until corrected and restarted; this is intentional configuration precedence.

## Database model records

No migration was required. The existing `models` table stores version, active state, artifact path/hash, feature count, parameters, metrics, and optional experiment linkage.

The isolated actual-application validation produced:

| Version | State after validation | Purpose |
|---|---|---|
| `rf-v2.0` | active | new runtime inference |
| `rf-v1.0` | inactive / previous | rollback |

The Models API now provides both the active record and model history. The Models page presents RF-v2 as Active and RF-v1 as Previous / rollback, including artifact identities. Experiment D is shown as RF-v2's verified metadata source without inserting a partial Experiment D evaluation record. Historical RF-v1 predictions retain their original `model_id`; no record rewrite occurs. Evaluation A/B/C remains intact; D presentation is deferred until the evidence synchronizer has a complete, separately approved D mapping.

## Runtime provenance

New predictions created by the activated process use RF-v2's database model ID. Persistence continues to record the predicted class, confidence, genuine three-class probability vector, `source_type="RUNTIME"`, timestamp, and one-to-one traffic-flow relationship. Prediction list/export and Prediction Detail resolve `model_version="rf-v2.0"` from the model relationship.

The activation test used a unique capture session in a disposable database. Its rows were not copied into the development/scientific database.

## Alert behavior

The Phase 5 model-agnostic rule is unchanged:

- Normal: no alert;
- PortScan: MEDIUM;
- DDoS: HIGH.

No confidence threshold or RF-v2-specific alert logic was added.

## End-to-end validation

The real RF-v2 pipeline was exercised through the real FastAPI application, SQLAlchemy persistence, read APIs, acknowledgment, and exports using a disposable SQLite database. The controlled fixtures in `tests/fixtures/rf_v2_integration/functional_vectors.json` were created solely for branch coverage and are not captured traffic or performance evidence.

| Expected branch | Actual prediction | Confidence | Alert |
|---|---:|---:|---|
| Normal | Normal | 0.839546723 | none |
| PortScan | PortScan | 0.500391369 | MEDIUM |
| DDoS | DDoS | 0.555178004 | HIGH |

All outputs contained genuine RF-v2 probability maps for Normal, DDoS, and PortScan. The test validated administrator login, active/model-history APIs, three persisted flows and predictions, two alerts, Monitoring, Dashboard counters, Predictions, Prediction Detail, Alert Detail, acknowledgment, prediction export, alert export, and model linkage.

Dashboard totals were three flows: one Normal, one PortScan, and one DDoS; one HIGH and one MEDIUM alert were active before acknowledgment. Prediction export contained all three records with `rf-v2.0`. Alert export retained both linked alert records. Existing alert export fields were not expanded because prediction export and alert detail already expose model provenance and the requested integration scope otherwise preserves exports.

## Rollback procedure

Rollback never copies model bytes and never deletes either model or any prediction.

For a host process:

```text
MODEL_PATH=models/random_forest_active.joblib
MODEL_METADATA_PATH=models/model_metadata.json
```

Restart the API after setting the pair. Startup verifies RF-v1's artifact hash against its metadata, loads RF-v1, marks `rf-v1.0` active, and leaves `rf-v2.0` registered but inactive. To reactivate RF-v2, restore the two RF-v2 values above and restart again.

For Docker Compose, supply the same RF-v1 environment overrides to the API/migration environment and recreate the API service. Do not edit or replace either artifact.

The isolated validation activated RF-v1, confirmed RF-v2 remained registered and all RF-v2 predictions retained their model relationship, then restored RF-v2. RF-v2 was active at validation completion.

## Automated and black-box tests

Command:

```text
PYTHONPATH=. .venv/bin/python -m pytest -q
```

Result: **192 passed, 0 failed**, with 1,933 dependency deprecation warnings. The increase is primarily repeated Joblib/NumPy warnings from loading both real pipelines; it is not a functional failure.

RFV2-01 through RFV2-08 all passed and are recorded in `reports/application/black_box_test_results.csv`. The authoritative actual-run record is `reports/application/rf_v2_activation_validation.json`.

## Scientific integrity

The integration runner hashed 133 frozen scientific files before and after validation. Both aggregate identities were `b14d16a943c99d1c75e78fac9ddb2abf3414230cac43eeef344aedf4482b1e14`.

Verified unchanged:

- RF-v1 active/tuned/baseline artifacts and RF-v1 metadata;
- RF-v2 scientific artifact at the required SHA-256;
- RF-v2 frozen scientific metadata;
- Experiment C evidence;
- Experiment D D2-D6 evidence;
- sealed final-test artifacts and identity;
- CICFlowMeter V3 adapter and crosswalk.

No training, retraining, refitting, scientific evaluation, threshold selection, or use of Experiment C/D traffic occurred.

## Files changed

Activation/configuration:

- `.env.example`
- `docker-compose.yml`
- `src/common/config.py`
- `src/inference/predictor.py`
- `src/api/service.py`
- `src/api/schemas.py`
- `src/api/main.py`
- `dashboard/api_client.py`
- `dashboard/presentation.py`
- `dashboard/pages/model_info.py`
- `models/experiment_d/random_forest_rf_v2_runtime_metadata.json` (new derived artifact)

Validation/evidence:

- `scripts/run_rf_v2_application_integration.py`
- `tests/fixtures/rf_v2_integration/functional_vectors.json`
- `tests/integration/test_rf_v2_application_integration.py`
- `reports/application/rf_v2_activation_validation.json`
- `reports/application/black_box_test_results.csv`
- `docs/final_black_box_testing.md`
- `docs/rf_v2_application_activation.md`
- `docs/rf_v2_application_integration_readiness.md` (the preceding audit, previously uncommitted)

## Limitations

- Scientific D6 DDoS recall remains weak despite improvement; activation does not remove that limitation.
- Functional vectors prove plumbing and deterministic alert branches, not traffic accuracy.
- Validation used the actual application with disposable SQLite rather than the normal PostgreSQL database to prevent record contamination. Compose remains configured for PostgreSQL and required no migration.
- A currently running API process must be restarted to load RF-v2; models are intentionally loaded once at startup.
- Aggregate runtime counters combine model histories if a shared database contains predictions from both versions. Prediction/detail/export provenance remains model-specific.
- Browser screenshots were not generated; UI-facing contracts and presentation mappings were exercised automatically.

RF-v2 APPLICATION ACTIVATION COMPLETE
