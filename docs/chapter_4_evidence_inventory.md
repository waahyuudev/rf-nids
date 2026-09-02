# Chapter IV Evidence Inventory

| Evidence | Source path | Description | Chapter IV destination | Recommended form |
|---|---|---|---|---|
| Dataset understanding | `reports/metrics/data_understanding.json` | Canonical CICIDS2017 rows/features/classes/hash source | Data preparation and dataset result | Table + Dataset screenshot |
| Active model metadata | `models/model_metadata.json` | RF identity, 78-feature order, parameters, metrics, timings and artifact hash | Modeling and implementation | Table + Models screenshot |
| Experiment A | `reports/metrics/tuned_metrics.json`; `reports/metrics/baseline_metrics.json`; `reports/metrics/model_comparison.json` | Baseline/tuning/selection evidence | Experiment A results | Metrics table + matrix figure |
| Experiment B | `reports/metrics/scenario_validation_metrics.json`; `reports/metrics/validation_comparison.json` | Scenario-based validation and A/B comparison | Experiment B results | Metrics table + matrix figure |
| Experiment C | `reports/metrics/experiment_c_v3_final.json` | Final external V3 validation; fitted pipeline reused | Experiment C results/limitations | Evaluation screenshot + table |
| Experiment C matrix/classes | `reports/tables/experiment_c_final_confusion_matrix.csv`; `reports/tables/experiment_c_final_class_metrics.csv` | Exact actual-row/predicted-column matrix and per-class outcomes | Experiment C analysis | Table/heatmap |
| A/B/C comparison | `reports/tables/experiment_a_b_c_comparison.csv` | Compact comparison without replacing primary evidence | Comparative discussion | Table |
| Schema/migrations | `src/api/models.py`; `migrations/versions/20260820_01_detection_backend.py`; `migrations/versions/20260820_02_live_capture_metadata.py`; `migrations/versions/20260902_03_application_foundation.py`; `migrations/versions/20260902_04_evidence_ingestion.py` | Nine-table ORM and Alembic head `20260902_04` | Database implementation | ERD/LRS figure + table |
| API | `src/api/main.py`; `src/api/schemas.py`; `src/api/exports.py`; `src/api/auth.py` | Authentication, evidence, runtime, monitoring, alert and export contracts | System implementation | Endpoint table |
| UI | `dashboard/app.py`; `dashboard/pages/` | Login and seven authenticated pages | Interface implementation | Screenshot series 01–15 |
| Evidence ingestion | `src/application/evidence_sync.py`; `scripts/sync_thesis_evidence.py` | Allowlisted, hash-verifying, idempotent read-only synchronization | Evidence provenance | Flow figure + short table |
| Automated tests | pytest output recorded in `docs/phase_8_final_integration_and_thesis_freeze.md` | 156 passed, 0 failed | Application testing | Terminal screenshot + summary table |
| Black-box tests | `reports/application/black_box_test_results.csv`; `docs/final_black_box_testing.md` | 24 executed requirements-oriented cases | Black-box testing | Full test table |
| Export evidence | `tests/integration/test_api.py`; `docs/phase_7_export_reporting.md` | Auth, content, filtering, ordering, headers and NULL preservation | Reporting/export result | Table + screenshots 14–15 |
| Scientific hashes | `docs/phase_2_evidence_ingestion.md`; Phase 8 freeze record | Baseline and final hashes for model, metadata and Experiment C sources | Integrity verification | Hash table |
| Architecture | `docs/phase_8_final_integration_and_thesis_freeze.md` | Actual runtime and historical-presentation paths | System architecture | Two-lane architecture figure |

Performance statements must cite existing artifacts only: baseline training `65.563469582994 s`; selected-model tuning `168.95768716704333 s`; full refit `100.60869579203427 s`; selected-model recorded total prediction `0.6240579169825651 s` and average `1.3476709849665815e-06 s/row`. These are artifact-reported measurements, not Phase 8 reruns.
