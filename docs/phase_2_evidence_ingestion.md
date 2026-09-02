# Phase 2 — Scientific Evidence Ingestion

Completed: 2026-09-02  
Scope: read-only synchronization of canonical scientific evidence into application presentation tables, plus read-only APIs. No Phase 3 Streamlit pages were implemented.

## Scientific Integrity Boundary

The synchronizer reads scientific artifacts as immutable byte streams, hashes and validates them, then writes only to the application database. It never invokes training, preprocessing fitting, inference, Experiment C execution, CICFlowMeter, or the feature adapter.

Before/after frozen hashes match:

| Frozen artifact | SHA-256 |
|---|---|
| `models/random_forest_active.joblib` | `73d86cb98f35c228d6e619e0f746a2b659d94deabe86d57e801c58bcf935f647` |
| `models/model_metadata.json` | `c632b16d30efb8f5a642070520c43cc1caaf36cbead33bddf9b5359b0fb531f2` |
| `reports/metrics/experiment_c_v3_final.json` | `6e091fdc1f0113fd34403d60dafdea83e6aa6ee957bf4a77632da31c6478f02b` |

No Phase 2 operation wrote under `models/`, `reports/`, or `data/lab/pcap/`. Modified/untracked scientific files that predated Phase 2 were preserved and were not cleaned, reset, or rewritten.

## Canonical Allowlist and Hashes

Only these exact repository-relative paths are accepted:

| Owner | Role | Canonical path | SHA-256 |
|---|---|---|---|
| Dataset | Data understanding | `reports/metrics/data_understanding.json` | `f3eb36a4949a7fc157d731b6a20cf732c718d8cf1ce9a75b67edcd43df3c0543` |
| Model | Model metadata | `models/model_metadata.json` | `c632b16d30efb8f5a642070520c43cc1caaf36cbead33bddf9b5359b0fb531f2` |
| Experiment A | Selected tuned metrics | `reports/metrics/tuned_metrics.json` | `1d5790ff92b438c5dd58cc7877c40dfaa67c7d223fcd98dab773f6670260d8d3` |
| Experiment A | Baseline support | `reports/metrics/baseline_metrics.json` | `5c3527b3c77fc83d4e2568d21d9aae207bcab0f5530e691ead1da6b29be92836` |
| Experiment A | Model comparison | `reports/metrics/model_comparison.json` | `2c66f07dcd54286fce08b8c0fea09b4a3fe117e275a946ac572f4771b48309fa` |
| Experiment B | Scenario metrics | `reports/metrics/scenario_validation_metrics.json` | `2bfff64e82150d28cf2b85440923c061e92c9f45fe2c0e79856a3f74722a9ea7` |
| Experiment B | A/B comparison | `reports/metrics/validation_comparison.json` | `cef801192da3b6bdc8816ec9426491e9f3a520ee84998bbf6ef8f26fa8e28864` |
| Experiment C | Final report | `reports/metrics/experiment_c_v3_final.json` | `6e091fdc1f0113fd34403d60dafdea83e6aa6ee957bf4a77632da31c6478f02b` |
| Experiment C | Final confusion matrix | `reports/tables/experiment_c_final_confusion_matrix.csv` | `7e269d96d4fd266d6937f69d2b7e9c70e1c000d1ad9f255acf9645bbcbeb2a31` |
| Experiment C | Final class metrics | `reports/tables/experiment_c_final_class_metrics.csv` | `1f5d67a772258ed2120033c706ad0aeba989dd656eac56cfe50f2756e30aad8e` |

The completed Experiment C script identifies these final per-flow tables:

- `reports/tables/experiment_c_v3_normal_predictions_final.csv`
- `reports/tables/experiment_c_v3_ddos_predictions.csv`
- `reports/tables/experiment_c_v3_portscan_predictions_final.csv`

They are documented but intentionally excluded from the Phase 2 allowlist and database import. No per-flow historical predictions or alerts are created.

Archive paths, diagnostic files, arbitrary paths, traversal, symlinks, and the schema-only `reports/experiment_c/experiment_manifest.json` are rejected.

## Importer Architecture

Implementation:

- `src/application/evidence_sync.py` — allowlist, read-only loaders, validation, cross-file checks, mapping, conflicts, transactions, and synchronization results.
- `scripts/sync_thesis_evidence.py` — explicit CLI; it is not invoked by API startup.
- `evidence_sources` table — one provenance row per canonical source with owner, role, path, SHA-256, optional schema version, and import time.
- `evaluation_results.metric_key` — stable `OVERALL` and `CLASS:<name>` identities.
- `models.feature_count` — stores the verified 78-feature count alongside artifact metadata.
- Alembic revision `20260902_04` — additive schema update; PostgreSQL DDL generation and SQLite migration tests pass.

All selected documents are parsed and structurally validated before presentation writes. Experiment C additionally requires completed status, no database persistence during the historical run, no fitting, exact three-class coverage, and identical JSON/CSV confusion matrices. The active model bytes are checked against the SHA-256 declared by model metadata when the artifact is present.

Synchronization is one transaction. Validation, conflict, constraint, or mapping failure rolls it back completely.

## Dataset Mapping

One presentation dataset is keyed by canonical data-understanding evidence:

- Name: explicit `dataset_name` (`cicids2017`)
- Source path/hash: data-understanding JSON
- Total rows: explicit `rows` (`2,830,743`)
- Total features: explicit active-model `feature_count` (`78`), rather than treating the label column as a model feature
- Label column: explicit `label_column` (`label`)
- Class distribution: explicit mapped distribution from the source report
- Creating user: NULL, because no historical application user is evidenced

Experiment A, B, and C presentation records link to this verified dataset. No raw dataset rows are stored in PostgreSQL.

## Experiment A Mapping

Stable identity: `EXPERIMENT_A`  
Type: `STRATIFIED_RANDOM_SPLIT`

The selected tuned metrics are the primary evaluation snapshot. Overall and Normal/DDoS/PortScan rows preserve source accuracy, macro metrics, class precision/recall/F1, one-vs-rest FPR values, confusion matrix, warnings, and model-selection reason. Baseline and model-comparison files remain separate `evidence_sources`; baseline metrics are not merged into tuned metric rows.

The active `rf-v1.0` model presentation row links to Experiment A and stores:

- repository-relative active artifact path
- verified artifact SHA-256
- actual parameter JSON from model metadata
- feature count 78
- active status and existing metrics

The model artifact itself is untouched.

## Experiment B Mapping

Stable identity: `EXPERIMENT_B`  
Type: `ORDERED_CONTIGUOUS_BLOCK_HOLDOUT`

Overall and per-class values come directly from `scenario_validation_metrics.json`. Notes preserve its limitations, split strategy, and strategy rationale. Its description explicitly identifies Experiment B as scenario/stress validation rather than production validation. `validation_comparison.json` is retained as separate provenance.

## Experiment C Mapping

Stable identity: `EXPERIMENT_C`  
Type: `EXTERNAL_VALIDATION`

The presentation record identifies historical controlled virtual-laboratory validation and states that the fitted pipeline was reused with no training/refitting. The canonical final JSON is primary; the class-metric and confusion-matrix CSVs are separately hashed and cross-validated.

Exact imported results are:

- Normal: 61/61 correct, recall `1.0`
- DDoS-like expected class: 0/10,226 correct, recall `0.0`
- PortScan: 0/1,000 correct, recall `0.0`
- Overall: 61/11,287 correct, accuracy `0.005404447594577833`
- Confusion matrix: `[[61, 0, 0], [10226, 0, 0], [1000, 0, 0]]`

Macro values unavailable in the canonical final sources remain NULL. No negative result is hidden or replaced by a computed value.

## Idempotency and Conflicts

Database protections:

- unique experiment code
- unique evidence owner/type/role
- unique canonical source path
- unique `(experiment_id, metric_key)`

Behavior:

- First identical sync inserts one dataset, three experiments, twelve evaluation rows, ten evidence-source rows, and one model presentation row if it does not already exist.
- A second identical sync inserts zero rows and reports every record unchanged.
- If a stored evidence role/path hash differs from current bytes, synchronization raises `EvidenceConflictError`, preserves the old snapshot, and rolls back all writes.
- Phase 2 deliberately does not offer `--force`. Reconciliation/new revisions require a future explicit design decision; historical snapshots cannot be overwritten silently.

## Dry Run and CLI

Dry run validates, maps, flushes constraints, reports proposed changes, and rolls the database transaction back:

```bash
PYTHONPATH=. .venv/bin/python scripts/sync_thesis_evidence.py --dry-run --verbose
```

Apply all canonical evidence:

```bash
PYTHONPATH=. .venv/bin/python scripts/sync_thesis_evidence.py --verbose
```

Select one experiment while still validating dataset/model evidence:

```bash
PYTHONPATH=. .venv/bin/python scripts/sync_thesis_evidence.py --experiment C --dry-run
```

Accepted experiment values are `A`, `B`, `C`, and `all`.

## Read-only API Endpoints

- `GET /api/datasets`
- `GET /api/datasets/{id}`
- `GET /api/experiments`
- `GET /api/experiments/{id}`
- `GET /api/experiments/{id}/evaluation`
- `GET /api/evaluations`
- `GET /api/evaluations/{id}`

These expose presentation records only. Phase 2 adds no write/import endpoint and no Streamlit page.

## Operational Acceptance Run

A fresh temporary SQLite application database at `/tmp/rf_nids_phase2_acceptance.db` was migrated to head and used for the stop-condition proof:

1. Dry run proposed 1 dataset, 3 experiments, 12 evaluation rows, 10 evidence sources, and 1 model, then left zero committed rows.
2. First real sync inserted those exact counts.
3. Second real sync inserted zero and reported all 27 records unchanged.
4. Database inspection confirmed A/B/C source hashes, metrics, matrices, class rows, NULL fields, and active-model linkage.

The temporary acceptance database is not part of the repository or application deployment.

## Tests

Seven Phase 2 tests were added across evidence synchronization and read APIs, covering:

- exact allowlist and exclusion rules
- traversal rejection
- SHA-256 calculation
- invalid-structure fail-closed behavior
- dataset and A/B/C imports
- exact Experiment C negative results
- all source provenance records
- NULL metrics
- active model → Experiment A linkage
- identical-sync idempotency
- changed-hash conflict preservation
- dry-run rollback
- rollback after a later import failure
- read endpoint lists/details/404s
- migration additions

Full command:

```bash
PYTHONPATH=. .venv/bin/python -m pytest -q
```

Result: **127 passed** in 10.18 seconds. This extends the Phase 1 total of 120 without deleting existing tests.

Warnings: 329 total—the existing FastAPI/Starlette `httpx` deprecation warning and 328 existing Joblib/NumPy shape deprecation warnings. No synchronizer warning or test failure remains.

## Files Added

- `src/application/__init__.py`
- `src/application/evidence_sync.py`
- `scripts/sync_thesis_evidence.py`
- `migrations/versions/20260902_04_evidence_ingestion.py`
- `tests/integration/test_evidence_sync.py`
- `docs/phase_2_evidence_ingestion.md`

## Files Modified

- `src/api/models.py`
- `src/api/schemas.py`
- `src/api/main.py`
- `src/api/service.py`
- `tests/integration/test_api.py`
- `tests/integration/test_migrations.py`
- `docs/thesis_implementation_gap_analysis.md`

## Known Remaining Work

- Phase 3 dashboard/evaluation UI is not implemented.
- No dataset, model, evaluation, or Experiment C Streamlit page exists yet.
- No per-flow historical prediction import was performed.
- No evidence synchronization is triggered automatically or exposed as an HTTP write action.
- Conflict reconciliation/new-revision behavior intentionally stops at explicit refusal; there is no force flag.
- Existing local in-memory authentication-session and warning limitations remain from Phase 1.
- The configured PostgreSQL database was not mutated during acceptance; PostgreSQL offline DDL was generated successfully, while the real operational proof used an isolated SQLite database.

Phase 2 stops here pending approval.
