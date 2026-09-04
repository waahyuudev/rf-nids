# RF-NIDS RF-v2 Final Runtime Smoke Test

Finalized: 2026-09-03  
Repository branch: `main`  
Initial HEAD: `7a0c976ae93bdcf8fb3be0bb9b7a7218ccc90a49`

## Declaration

**RF-NIDS RF-v2 FINAL RUNTIME VERIFIED**

The actual FastAPI, PostgreSQL, and Streamlit application stack was exercised with RF-v2 as the configured default. The approved non-scientific functional vectors produced and persisted Normal, PortScan, and DDoS predictions through the real HTTP and SQLAlchemy boundaries. The final state leaves `rf-v2.0` active and `rf-v1.0` inactive/available for rollback.

## Startup and pre-start checks

- Git was initially clean on `main` at `7a0c976ae93bdcf8fb3be0bb9b7a7218ccc90a49`.
- Python: `.venv/bin/python`, Python 3.12.13.
- Configuration defaults resolved to `models/experiment_d/random_forest_rf_v2.joblib` and `models/experiment_d/random_forest_rf_v2_runtime_metadata.json`.
- PostgreSQL 16 Compose service was healthy and accessible.
- The database was initially at `20260820_02` while Alembic head was `20260902_04`. The intended development database was upgraded using only the checked-in, approved migrations. Final current/head: `20260902_04`.
- No active administrator existed. The approved interactive bootstrap created active ADMIN `admin@example.local`; its password was hidden, not logged in the report, and not committed.
- RF-v2 artifact exists and its SHA-256 exactly matches `fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31`.
- Runtime metadata exists, declares 78 ordered features and `rf-v2.0`, and has SHA-256 `1c97466a9c987b161e516557d41e63c428d987129f39dcdeb6a735c9097443c0`.

Commands used included:

```text
PYTHONPATH=. .venv/bin/python -m alembic current
PYTHONPATH=. .venv/bin/python -m alembic heads
PYTHONPATH=. .venv/bin/python -m alembic upgrade head
PYTHONPATH=. .venv/bin/python scripts/bootstrap_admin.py --name "RF-NIDS Administrator" --email "admin@example.local"
docker compose build api migration
docker compose up -d api
API_BASE_URL=http://127.0.0.1:8000 .venv/bin/streamlit run dashboard/app.py --server.headless true --server.address 127.0.0.1 --server.port 8501
PYTHONPATH=. .venv/bin/python -m pytest -q
git diff --check
```

## Resolved blocking runtime defects

Two stale/container packaging conditions blocked startup and were corrected minimally:

1. The existing API container retained old RF-v1 environment values. Recreating it from the checked-in Compose configuration removed the stale override and selected RF-v2.
2. The Docker image omitted RF-v2's model/metadata and the frozen D6 metrics document required for startup hash verification. `Dockerfile` and `.dockerignore` were changed only to package the required immutable files. No scientific content or application inference logic changed.

The migration image was also stale and did not contain revision `20260902_04`; rebuilding it from the current source resolved the one-shot migration service failure.

## Runtime results

FastAPI returned HTTP 200 from `/health` with `database=connected` and `model_loaded=true`. Startup completed without application exceptions. Streamlit served HTTP 200 on port 8501 and its process reported no exception. Browser inspection confirmed the Login page and a real `type=password` password input; an invalid login was rejected. Valid ADMIN authentication returned HTTP 200, `/api/auth/me` exposed only the public user record, and the full authentication/dashboard contracts passed the automated suite.

The hash-verifying evidence synchronizer populated one canonical dataset, Experiments A/B/C, 12 evaluation rows, and 10 allowlisted evidence sources. Experiment C remained unchanged. Experiment D is not inserted as a partial Evaluation record; it appears as RF-v2 scientific provenance. This is the approved presentation behavior, not a runtime defect. The shown D6 metrics are explicitly non-perfect, including DDoS recall `0.07692804547216121`.

### Approved runtime inference

Capture session: `final-runtime-smoke-20260903-f98efa91`. Source: `tests/fixtures/rf_v2_integration/functional_vectors.json`, which is explicitly synthetic functional branch coverage and prohibits Experiment C, Experiment D adaptation, and Experiment D final-test overlap.

| Prediction ID | Expected/actual | Confidence | Probabilities | Alert |
|---:|---|---:|---|---|
| 1804 | Normal | 0.8395467229 | DDoS 0.0187312362; Normal 0.8395467229; PortScan 0.1417220409 | none |
| 1805 | PortScan | 0.5003913692 | DDoS 0; Normal 0.4996086308; PortScan 0.5003913692 | MEDIUM, ACTIVE |
| 1806 | DDoS | 0.5551780039 | DDoS 0.5551780039; Normal 0.4221542302; PortScan 0.0226677659 | HIGH, ACKNOWLEDGED |

All three flows and predictions were persisted with `source_type=RUNTIME`, 78 raw features, flow metadata, genuine probability maps, and model provenance `rf-v2.0`. Exactly two alerts were created, one per attack prediction. The DDoS alert acknowledgment stored ADMIN user ID 1, name/email, and a non-null timestamp.

Dashboard values changed from 1,803 to 1,806 total flows. Final runtime counts were 1,804 Normal, one PortScan, one DDoS, two total alerts, one active alert, and one acknowledged alert. Monitoring and Predictions returned all three new records and supported limit/offset and class filters. Prediction Detail returned flow data, raw features, model/version, probabilities, provenance, and related alert information. Alert Detail returned severity, status, confidence, flow data, RF-v2 provenance, and acknowledgment identity.

## Export, logout, restart, and rollback

- Dataset, Prediction, Alert, Experiment A/B/C evaluation JSON, and Experiment A/B/C confusion-matrix CSV exports all returned HTTP 200 with appropriate JSON/CSV content types.
- Prediction export included `model_version=rf-v2.0`; alert export included the expected two alert records.
- Export payload scans found no `password_hash`, access token, or bearer-token leakage.
- Logout returned HTTP 200 and the revoked bearer token returned HTTP 401.
- After API restart, the prior in-memory token returned HTTP 401, login succeeded again, RF-v2 reloaded, and predictions 1804–1806 remained persisted.
- The documented host rollback loaded RF-v1, left RF-v2 registered, and preserved the RF-v2 relationship on existing predictions. Restarting the Compose API restored RF-v2. Final registry state: RF-v2 active, RF-v1 inactive.

## Automated tests and integrity

- Pytest: **192 passed, 0 failed**, 1,933 dependency deprecation warnings, 15.10 seconds.
- `git diff --check`: PASS, no output.
- Frozen scientific aggregate: 133 files, identity `b14d16a943c99d1c75e78fac9ddb2abf3414230cac43eeef344aedf4482b1e14`, unchanged from the activation baseline.
- RF-v1 artifact: `73d86cb98f35c228d6e619e0f746a2b659d94deabe86d57e801c58bcf935f647`.
- RF-v2 artifact: `fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31`.
- RF-v2 frozen metadata: `0bef82122fbebede27cd14f9dae925f4f48f3f1700c4b6c46ae29f238731e2c2`.
- Experiment D final metrics: `56b98bcf2ed4883c2c2cc3beb67e85424c639cf8d2686b2934290133e08562be`.
- CICFlowMeter V3 adapter: `ed433cfc6943f6eb9f58f8a338b3cec301d504909a1447b7989d8e53c644e5fe`.
- 78-feature crosswalk: `66e517cdcea217f19de4d0a2cd45302ede999388393f539fb8ca4a2c68b74cf4`.

No retraining, refitting, scientific evaluation rerun, manual relabeling, sealed-data use, database schema invention, or scientific-evidence modification occurred.

## Stop-condition summary

1. FastAPI startup: PASS
2. Streamlit startup: PASS
3. Database revision: `20260902_04 (head)`
4. Active model after startup: `rf-v2.0`
5. RF-v2 hash verification: PASS — `fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31`
6. Login: PASS
7. Dashboard: PASS
8. Dataset: PASS
9. Models: PASS
10. Evaluation: PASS — Experiments A/B/C; D remains provenance-only by approved design
11. Monitoring: PASS
12. Predictions: PASS
13. Prediction Detail: PASS
14. Alerts: PASS
15. Alert acknowledgment: PASS
16. Export: PASS
17. Logout: PASS
18. API restart/session expiry: PASS
19. Rollback and restore RF-v2: PASS
20. Runtime RF-v2 predictions tested: Normal (1804), PortScan (1805), DDoS (1806)
21. Final pytest count: 192 passed, 0 failed
22. `git diff --check`: PASS
23. Scientific integrity: PASS — 133-file aggregate unchanged
24. Unresolved defects: none; dependency deprecation warnings remain non-blocking

**RF-NIDS RF-v2 FINAL RUNTIME VERIFIED**
