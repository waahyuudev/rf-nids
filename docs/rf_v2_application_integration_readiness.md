# RF-v2 Application Integration Readiness Audit

Date: 2026-09-03
Scope: audit only; no model loading, inference, database write, application behavior change, or scientific-evidence change was performed.

## 1. Current model-loading architecture

The application selects one model/metadata pair through `Settings` in `src/common/config.py`. `MODEL_PATH` defaults to `models/random_forest_active.joblib`, and `MODEL_METADATA_PATH` defaults to `models/model_metadata.json`. Relative paths are resolved beneath the project root. Both paths are environment-configurable, but they are process-wide settings rather than request-level choices.

During FastAPI lifespan startup, `create_app()` constructs exactly one `InferenceEngine` from those two paths and stores it in `application.state.inference`. It then calls `sync_active_model()` and stores one corresponding database record in `application.state.model_record`. The model is therefore loaded once at application startup, not once per request. Both `/api/predict` and `/api/predict/batch` always use that single engine and that single model-record ID.

`InferenceEngine` provides the following fail-closed checks:

- metadata must contain a unique ordered `feature_names` list;
- the artifact SHA-256 is checked against `model_sha256` when present;
- the deserialized artifact must be an sklearn `Pipeline`;
- the pipeline feature order must equal metadata feature order;
- every request must provide all 78 required features, with extra fields rejected by default;
- numeric conversion is explicit, and infinity is converted to `NaN` for the already-fitted pipeline.

The pipeline performs its own frozen inference preprocessing. No runtime fitting is present.

The application can store multiple model versions in the database, but one API process cannot currently host or select multiple engines. Model selection is implicit and fixed for the process lifetime. Changing environment variables requires a restart. There is no request model selector.

RF-v2's frozen metadata is not directly compatible with this runtime contract. It uses `version` rather than the required `model_version`; uses `classes` rather than `class_names`; uses `rf_parameters` rather than `parameters`; and does not contain the runtime `model_path` or the current `metrics` presentation shape. Its artifact hash and ordered feature list are compatible. The frozen metadata must not be edited. A separate, derived runtime metadata document should translate these names and link back to the frozen metadata and RF-v2 hash.

## 2. Model database audit

The `models` table already contains:

- unique `model_version`;
- `model_name`, algorithm, feature count, and presentation metrics;
- `is_active`;
- nullable `experiment_id`;
- artifact path and SHA-256;
- model parameters;
- a one-to-many relationship to predictions.

RF-v2 can therefore be registered as a second row without overwriting RF-v1, and the schema permits an inactive row. No migration is needed for registration or prediction provenance.

There are two limitations in the current behavior:

1. `sync_active_model()` is activation-oriented. It marks every other model inactive and marks the configured model active. It cannot register a model without activating it.
2. The database has an index on `is_active`, but no constraint enforcing at most one active row. The application intends one active model, yet a direct write or evidence-import path could create multiple active rows. The active-model API resolves ambiguity by choosing the newest ID.

Thus Option B is schema-compatible but not service-complete. It would require a separate `register_model(..., activate=False)` operation or equivalent explicit registration path. The recommended isolated approach does not need that change.

## 3. Prediction provenance audit

Every persisted prediction records:

- `model_id` as a required foreign key;
- an internal `traffic_flow_id` linked one-to-one to the stored flow;
- predicted class, confidence, and the full probability vector;
- prediction and creation timestamps;
- `source_type`;
- optional `external_key` and `experiment_id`.

Model version is not duplicated on the prediction row, but it is reliably obtained through the immutable foreign-key relationship to `models.model_version`. Prediction detail and prediction export already join this relationship and expose model name/version. RF-v1 and RF-v2 records are therefore distinguishable if each is registered under a unique version and every write uses the matching `model_id`.

Runtime persistence currently sets `source_type="RUNTIME"`, leaves `external_key` and `experiment_id` unset, and stores request features in `traffic_flows.raw_features`. A runtime flow has an internal database identity and optional capture/session/network metadata, but no persisted deterministic source-flow fingerprint. Consequently, records in a shared database would be distinguishable by model ID/version but would not be strongly tagged as a particular integration run unless a unique `capture_session_id` is used. A dedicated database is the safer isolation boundary.

The response's `model_version` comes from inference output, while the persisted `model_id` is supplied separately by the application state. A future runner must assert that these identities agree before persistence; otherwise a programming error could return one version while linking the row to another model.

## 4. Alert pipeline audit

Alert generation is deterministic and model-agnostic. `src/api/service.py` defines:

- Normal -> no alert;
- DDoS -> HIGH;
- PortScan -> MEDIUM.

The rule depends only on `output["prediction"]`; there is no model-version or confidence threshold. Low-confidence attack predictions intentionally still create alerts. Each alert is linked one-to-one to its prediction, so model provenance remains available through `alert -> prediction -> model`.

RF-v2 requires no alert-rule change. Changing the rule for RF-v2 would be scientifically and operationally unnecessary for this integration test.

## 5. API audit

Runtime inference endpoints are:

- `POST /api/predict` for one flow;
- `POST /api/predict/batch` for an atomic bounded batch.

The request carries a feature mapping plus optional flow/capture metadata. It does not accept model identity. CICFlowMeter conversion occurs upstream in the ingestion process (`FlowCsvExtractor` and `FeatureAdapter`); the API receives the model-facing feature mapping. `InferenceEngine` then normalizes names, validates completeness/order, converts numeric values, and passes the ordered frame to the stored sklearn pipeline.

Model selection is implicit: both endpoints use `application.state.inference` and `application.state.model_record`. Accepting an arbitrary model path in the API would create an unsafe file-access and integrity boundary and must not be introduced.

A public model selector is not needed for isolated integration validation. If multi-model selection is ever required later, it should accept only an allow-listed model registry ID, resolve the artifact and metadata server-side, verify both hashes, and ensure the selected engine's version equals the selected database record. That would be an application feature and would reopen the implementation freeze.

## 6. UI and monitoring audit

Current behavior by surface is:

| Surface | Model/version visibility | Coexistence behavior |
|---|---|---|
| Dashboard counters/timeline | Counters have no per-model breakdown; recent-predictions table includes version | Counts all `RUNTIME` predictions, regardless of model |
| Monitoring summary | Shows the currently active model version, not each row's model | Counts all runtime rows; can be misleading for mixed-model history |
| Monitoring table | Does not expose model ID/version | Ambiguous if RF-v1 and RF-v2 rows coexist |
| Predictions list | Includes `model_version` | Reliably distinguishable |
| Prediction Detail | Includes model ID, name, version, probabilities, source type, and flow context | Reliably distinguishable |
| Alerts list | API objects contain model name/version, but the table does not display them | List presentation is ambiguous |
| Alert Detail | Displays model name/version and related prediction context | Reliably distinguishable |
| Prediction export | Includes model name/version and runtime provenance | Reliably distinguishable |
| Alert export | Omits model name/version although the relationship exists | Ambiguous without following `prediction_id` |

The dashboard and monitoring queries deliberately exclude imported scientific predictions and include `source_type IS NULL` legacy rows plus `source_type="RUNTIME"` rows. This protects Experiment C/D imported context. In a shared runtime database, however, aggregate counts combine all runtime model versions. A dedicated integration database avoids that ambiguity without changing the UI.

## 7. Safe integration options

Safest to riskiest:

1. **Option C — Dedicated integration-test runner.** Construct a separate application instance with an isolated database, RF-v2's fixed artifact path, and a derived hash-linked runtime metadata document. Exercise the existing API, persistence, alert, dashboard, detail, acknowledgment, and export paths. The production/default configuration remains RF-v1. This gives the strongest state isolation and needs no selector or migration.
2. **Option B — Register RF-v2 inactive, then use a dedicated test inference path.** The schema supports this, but the current service cannot register inactive models and the API has only one process-wide engine. Implementing a private allow-listed selector increases identity-consistency and authorization complexity.
3. **Option A — Temporary configuration switch.** Environment variables already make this technically possible after creating compatible runtime metadata. It is acceptable only in a disposable process and dedicated database. Against the normal development database, startup deactivates RF-v1's model row and aggregate runtime views mix histories.
4. **Option D — Temporarily activate RF-v2 and restore RF-v1.** This mutates shared state twice, depends on successful restoration, can leave an incorrect active row after interruption, and makes records created during the interval harder to interpret. It should not be used.

## 8. Recommended approach

Use Option C as isolated post-freeze validation:

1. Create a derived runtime metadata file outside the frozen Experiment D evidence tree. It must contain the runtime keys expected by `InferenceEngine` and `sync_active_model`, include RF-v2 SHA-256 `fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31`, retain exactly the frozen 78-feature order, use a unique version such as `rf-v2.0-experiment-d-integration`, and record the source frozen-metadata SHA-256.
2. Start a dedicated API instance through a test runner with explicit `Settings`: RF-v2 artifact, derived metadata, a new SQLite database under a temporary directory, test-only ports, and `APP_ENV=integration-test`.
3. Use a unique capture session such as `rf-v2-integration-<run-id>` on every request. Because the database is disposable, `source_type="RUNTIME"` can remain unchanged and all standard runtime views are exercised accurately.
4. Point a dedicated dashboard process at that API for presentation checks.
5. Verify the RF-v1/RF-v2/scientific hashes before and after, preserve the integration report separately, and delete or retain the disposable database according to the test evidence policy. Never copy its rows into the thesis/scientific database.

## 9. Minimum required changes

### REQUIRED

| File | Change |
|---|---|
| `models/runtime/random_forest_rf_v2_integration_metadata.json` (new) | Runtime-compatible, derived metadata with RF-v2 hash, ordered features, version, classes, parameters, D6 presentation metrics, and source-metadata hash. Do not change the frozen RF-v2 metadata. |
| `scripts/run_rf_v2_application_integration.py` (new) | Fail-closed orchestration for temporary DB, fixed allow-listed RF-v2 paths, integrity checks, unique run ID, API/dashboard lifecycle, assertions, and cleanup/reporting. |
| `tests/integration/test_rf_v2_application_integration.py` (new) | Actual RF-v2 startup/hash/schema test plus end-to-end persistence, alert, queries, exports, acknowledgment, isolation, and RF-v1-preservation assertions. |
| `tests/fixtures/rf_v2_integration/` (new) | New non-scientific controlled fixtures and provenance; no Experiment C/D traffic or rows. |
| `docs/rf_v2_application_integration_test.md` (new, produced during the future phase) | Commands, fixture provenance, results, hashes, limitations, and explicit statement that this is functional validation rather than performance evaluation. |

### OPTIONAL

| File | Change |
|---|---|
| `src/api/service.py` | Add an explicit identity-consistency assertion or reusable inactive registration helper if Option B is later chosen. Not needed for isolated Option C. |
| `src/api/schemas.py`, `src/api/main.py` | Add model ID/version to `MonitoringRecord` and optional model filters if mixed-model operation becomes a real requirement. |
| `dashboard/components/tables.py`, `dashboard/pages/monitoring.py` | Display model version on each monitoring row. |
| `src/api/exports.py`, `src/api/main.py` | Include model name/version in alert exports. Prediction exports already include them. |
| `dashboard/components/tables.py`, `dashboard/pages/alerts.py` | Display model version in the alert list; alert detail already displays it. |

### NOT REQUIRED

| Area/file | Reason |
|---|---|
| Database migration | Existing model/prediction/alert schema supports separate model rows and model-linked predictions. |
| `src/common/config.py` | Existing settings already accept explicit model, metadata, and database paths. |
| `src/inference/predictor.py` | It already validates hashes, feature order, and frozen pipelines. A derived metadata file satisfies its contract. |
| Public API request schemas/model selector | A dedicated process chooses RF-v2 server-side; callers must not supply paths. |
| Alert rule | It is already deterministic and model-agnostic. |
| RF-v1 artifacts or metadata | They remain the production/default model and must not change. |
| RF-v2 frozen artifact/metadata | Scientific artifacts must not change; runtime compatibility belongs in a derived sidecar. |
| Experiment C/D evidence or freeze documents | They are immutable and unrelated to functional integration inputs. |

## 10. Test-data policy

Do not use sealed D6 rows, Experiment C PCAPs, Experiment D adaptation traffic, or any copied/derived scientific rows. Create a new integration-only fixture family with its own capture/generation provenance and hashes.

The test validates plumbing, not classifier performance. A legitimate fresh Normal flow should demonstrate extraction, adaptation, prediction persistence, and display even if the predicted label is unexpected. For deterministic DDoS/PortScan alert-branch coverage, controlled 78-feature fixtures may be used only after documenting that they were created independently for functional testing. Their expected RF-v2 outputs are branch fixtures, not accuracy evidence, and must not influence training, thresholds, or scientific claims.

## 11. Future integration-test plan

The approved future implementation phase should:

1. Hash RF-v1, RF-v2, frozen metadata, Experiment C evidence, Experiment D D2-D6 evidence, and the sealed manifest before startup.
2. Create a unique temporary directory and dedicated SQLite database; prove the configured URL does not reference the normal application database.
3. Validate the derived runtime metadata against RF-v2's frozen metadata, artifact hash, class set, and exact feature order.
4. Start the API with RF-v2 and confirm its isolated database contains one active RF-v2 model record while the normal database is untouched.
5. Submit a new legitimate Normal runtime flow using a unique capture-session/run ID; assert one flow and one RF-v2-linked prediction persist.
6. Submit an independently created fixture known to produce PortScan; assert a MEDIUM alert is created.
7. Submit an independently created fixture known to produce DDoS; assert a HIGH alert is created. Correct classification of arbitrary generated attack traffic is not a prerequisite.
8. Verify Monitoring displays all records and its counters update. Record the known limitation that per-row model version is absent from the monitoring table unless the optional enhancement is approved.
9. Verify Predictions displays RF-v2 version and Prediction Detail displays model ID/name/version, confidence, all class probabilities, unique session provenance, and alert linkage.
10. Verify Alert Detail displays the related RF-v2 model/version, prediction context, probability vector, and correct severity.
11. Verify Dashboard counters/timeline/recent predictions update only from the isolated runtime database.
12. Verify prediction export contains the RF-v2 record and model version. Verify alert export contains the record; document its current lack of model version unless the optional export enhancement is approved.
13. Acknowledge an alert and verify repeat-safe persisted acknowledgment, timestamp, and user identity.
14. Shut down the isolated processes cleanly and verify the dedicated database contains only the uniquely tagged run.
15. Recompute every pre-test scientific hash and assert exact equality. Confirm `models/random_forest_active.joblib` and its metadata remain the default configuration.

## 12. Test-isolation plan

Use layered isolation:

- **Primary boundary:** a dedicated temporary SQLite database, never the normal PostgreSQL/development database.
- **Process boundary:** dedicated API and dashboard processes with explicit test-only environment variables and ports.
- **Artifact boundary:** fixed allow-listed paths for RF-v2 and derived runtime metadata; no request-supplied path.
- **Record boundary:** unique `capture_session_id` and PCAP-segment/run identifiers for every fixture.
- **Evidence boundary:** fixtures and reports live outside Experiment C/D directories and are labeled functional integration evidence.
- **Cleanup boundary:** terminate processes first, then retain the DB as test evidence or remove the exact temporary directory. Never perform broad deletion.

Transaction rollback alone is insufficient because the test must verify persistence, API reads, exports, and acknowledgment across transactions. A test-specific `source_type` is also not recommended for this minimal test because existing runtime views intentionally include only `RUNTIME`/legacy rows; changing it would bypass the very UI paths under test. The dedicated database supplies stronger isolation while preserving legitimate runtime behavior.

## 13. Impact on the thesis implementation freeze

The safest interpretation is **A: isolated post-freeze validation**. Adding a dedicated runner, fixtures, derived runtime metadata, tests, and a validation report does not change the frozen application's default behavior or scientific artifacts. RF-v1 remains the default.

The freeze does not need to be reopened for that minimal scope. It must be reopened if any optional product behavior is approved, including a public/private multi-model selector in the existing API, per-model filtering, monitoring schema changes, alert-export changes, or dashboard presentation changes. The existing freeze document must remain unchanged during either audit or isolated validation.

## 14. Risks

- **Metadata mismatch:** pointing the current app directly at frozen RF-v2 metadata fails because required runtime keys are absent. Mitigation: derived hash-linked sidecar with validation.
- **Wrong model linkage:** inference output version and persisted model ID are passed through different objects. Mitigation: assert their equality in the runner before any test request and verify every stored join afterward.
- **Shared-state activation:** normal startup deactivates other database model rows. Mitigation: dedicated database; never use Option D.
- **Mixed runtime aggregates:** dashboard/monitoring aggregate all runtime models. Mitigation: dedicated database; optional per-model filters only in a separately approved phase.
- **Incomplete UI provenance:** monitoring rows and alert lists/exports do not consistently show model version. Mitigation: use detail views and prediction export for the minimal test; treat display enhancements as optional freeze-reopening work.
- **Fixture misuse:** controlled classifier-output fixtures could be mistaken for performance evidence. Mitigation: separate directories, explicit functional-only labels, hashes, and prohibition on scientific interpretation.
- **Scientific contamination:** using Experiment C/D traffic would invalidate isolation. Mitigation: reject paths/hashes that overlap frozen manifests.
- **Large artifact handling:** RF-v2 must be referenced in place, never copied over RF-v1. Verify the exact hash before and after.

## 15. Readiness verdict and summary

RF-v2 is not ready for immediate application integration execution because its frozen metadata does not satisfy the runtime metadata contract and an isolated integration runner/fixture set has not yet been implemented. The underlying application and database are structurally suitable.

- **Safest integration strategy:** Option C, a dedicated runner using a temporary database, explicit fixed RF-v2 paths, derived runtime metadata, and new functional-only fixtures.
- **Files needing changes:** only new runtime metadata, runner, fixture/test, and validation-document files are required for the minimal strategy. Existing application files are optional enhancements, not prerequisites.
- **Schema migration needed:** no.
- **RF-v1 remains default:** yes.
- **Application freeze reopened:** no for isolated post-freeze validation; yes only if optional existing API/UI/export behavior is changed.
- **Recommended next phase:** implement and review the isolated RF-v2 application-integration harness, then run it once using new non-scientific fixtures after explicit approval.

RF-v2 APPLICATION INTEGRATION NOT READY
