# Phase 1 — Application Foundation

Completed: 2026-09-02  
Scope: additive application-domain schema, provenance relationships, and backend administrator authentication only. Phase 2 evidence ingestion was not started.

## Scientific Freeze Verification

The following canonical hashes were recorded before implementation and verified again after implementation:

| Frozen artifact | SHA-256 before | SHA-256 after | Result |
|---|---|---|---|
| `models/random_forest_active.joblib` | `73d86cb98f35c228d6e619e0f746a2b659d94deabe86d57e801c58bcf935f647` | same | Unchanged |
| `models/model_metadata.json` | `c632b16d30efb8f5a642070520c43cc1caaf36cbead33bddf9b5359b0fb531f2` | same | Unchanged |
| `reports/metrics/experiment_c_v3_final.json` | `6e091fdc1f0113fd34403d60dafdea83e6aa6ee957bf4a77632da31c6478f02b` | same | Unchanged |

No Phase 1 code wrote to `models/`, `reports/`, or `data/lab/pcap/`. The repository already contained modified and untracked scientific/report files before Phase 1; they remain user-owned and were not edited by this implementation.

## Files Added

- `src/api/auth.py` — scrypt password hashing, opaque session creation/revocation, bearer-token parsing, and the protected current-user dependency.
- `scripts/bootstrap_admin.py` — interactive local administrator bootstrap command.
- `migrations/versions/20260902_03_application_foundation.py` — additive Phase 1 schema revision.
- `tests/integration/test_application_foundation.py` — entity, relationship, hashing, bootstrap, nullable compatibility, and idempotency tests.
- `docs/phase_1_application_foundation.md` — this implementation record.

The authoritative audit file `docs/thesis_implementation_gap_analysis.md` was created during the preceding audit and now has an appended Phase 1 progress section.

## Files Modified

- `src/api/models.py` — added application-domain entities and nullable provenance relationships.
- `src/api/schemas.py` — added login/logout/current-user request and response contracts.
- `src/api/main.py` — initialized the session registry and added login, logout, and current-user endpoints.
- `src/api/service.py` — synchronizes available active-model artifact path, hash, and real parameter metadata into the existing model row.
- `src/common/config.py` — added configurable authentication session lifetime.
- `docker-compose.yml` — supplies `AUTH_SESSION_HOURS=8` to the API/migration environment.
- `tests/integration/test_api.py` — added authentication behavior tests.
- `tests/integration/test_migrations.py` — verifies the new schema and preservation of legacy rows.

## New Database Entities

### `users`

Stores local application administrators: name, unique normalized email, scrypt password hash, `ADMIN` role, active flag, and creation/update timestamps. Plaintext passwords are never persisted.

### `datasets`

Stores presentation metadata only: name, source path/hash, nullable row/feature counts, label column, nullable class-distribution JSON, optional creating user, and timestamps. Phase 1 inserts no scientific dataset values.

### `experiments`

Provides stable experiment identities and provenance fields for A/B/C: code, name, type, optional dataset, description, status, source path/hash, optional schema version/import time, and timestamps. Phase 1 does not import or execute experiments.

### `evaluation_results`

Stores nullable overall or per-class metrics, nullable confusion-matrix JSON, notes, and source provenance under an experiment. Scientific absence is represented by NULL; Phase 1 inserts no metrics.

## Existing Entity Extensions

- `models`: nullable `experiment_id`, `artifact_path`, `artifact_sha256`, and parameter JSON. The existing table and fields remain intact.
- `predictions`: nullable `experiment_id`, `source_type`, and `external_key`. A unique constraint on `(source_type, external_key)` rejects duplicate imported identities while allowing multiple ordinary runtime rows with both values NULL.
- `alerts`: nullable `acknowledged_by_user_id` with `ON DELETE SET NULL`. Historical acknowledgments are not assigned a fabricated user.

Existing traffic-flow/model/prediction/alert relationships and runtime prediction behavior are preserved. The confidence-threshold alert rule is deliberately unchanged in Phase 1.

## Migration

- Revision: `20260902_03`
- Parent: `20260820_02`
- Strategy: create four tables, then add nullable columns/indexes/foreign keys to existing tables.
- Delete behavior: scientific/application parents use `SET NULL` where legacy/history preservation is required; evaluation rows use `CASCADE` only when their owning experiment is explicitly deleted.
- SQLite: batch alteration is used for compatibility with the current migration tests.
- PostgreSQL: `PYTHONPATH=. .venv/bin/python -m alembic upgrade head --sql` generated valid PostgreSQL DDL successfully.
- Legacy check: a database migrated to `20260820_02` with existing model/flow/prediction rows upgraded to head with the new fields NULL and the rows preserved.

Apply the migration with:

```bash
PYTHONPATH=. .venv/bin/python -m alembic upgrade head
```

## Authentication Design

- Password KDF: Python standard-library scrypt with a random 16-byte salt; the encoded record includes work parameters and a 32-byte derived key.
- Minimum bootstrap password length: 12 characters.
- Email normalization: surrounding whitespace is removed and the address is case-folded before storage/login lookup.
- Session: 256-bit opaque bearer token; only its SHA-256 digest is held in API process memory.
- Lifetime: eight hours by default, configurable through `AUTH_SESSION_HOURS`.
- Logout: immediately removes the server-side session digest.
- Inactive users: cannot log in and any existing session is rejected when checked.
- Unknown-account login performs a dummy scrypt verification to reduce timing-based email enumeration.

Endpoints:

- `POST /api/auth/login`
- `POST /api/auth/logout` (protected)
- `GET /api/auth/me` (protected)

`get_current_user` in `src/api/auth.py` is the reusable dependency for protecting later endpoints. Existing prediction/dashboard endpoints were not newly protected because full application authorization and Streamlit Login UX are outside Phase 1.

The process-memory session registry is appropriate for the current single-process local thesis prototype. Sessions are intentionally invalidated when the API restarts and are not shared between multiple workers. A persistent session table or signed-token design can be considered only if deployment requirements expand.

## Administrator Bootstrap

Run migrations first, then execute:

```bash
PYTHONPATH=. .venv/bin/python scripts/bootstrap_admin.py \
  --name "RF-NIDS Administrator" \
  --email "admin@example.local"
```

The command prompts twice for the password without echoing it, normalizes the email, hashes the password before insertion, and refuses duplicate email addresses. It does not accept a plaintext password as a command-line argument, preventing shell-history disclosure.

## Tests Added and Results

Coverage added for:

- Phase 1 migration schema and current-head upgrade
- preservation/nullability of legacy rows
- users and database-level duplicate email
- password hashing and verification
- administrator bootstrap and duplicate refusal
- valid and invalid login
- inactive-user rejection
- protected endpoint behavior
- logout revocation
- dataset/user and dataset/experiment relationships
- experiment/evaluation and experiment/model relationships
- nullable evaluation metrics
- runtime prediction NULL provenance compatibility
- imported prediction idempotency constraint
- nullable and populated alert acknowledging-user relationship

Complete verified command:

```bash
PYTHONPATH=. .venv/bin/python -m pytest -q
```

Result: **120 passed** in 9.26 seconds. The pre-Phase 1 baseline was 112 tests, so Phase 1 adds eight passing test cases without deleting existing tests.

Warnings: 329 total. One is the existing FastAPI/Starlette `httpx` compatibility deprecation warning; 328 are existing Joblib/NumPy shape deprecation warnings from inference tests. There were no test failures.

## Known Remaining Work

- Phase 2 must implement allowlisted, hash-verifying, idempotent scientific-evidence ingestion. No evidence was imported in Phase 1.
- Dataset, Experiment, Evaluation, and historical prediction APIs/pages do not yet exist.
- Full Streamlit administrator Login UX and broad endpoint authorization remain later work.
- Sessions are single-process/in-memory and end on restart.
- The frozen unconditional DDoS/PortScan alert rule is intentionally deferred; existing confidence-threshold behavior remains unchanged.
- `acknowledged_by_user_id` is available, but the existing acknowledge endpoint does not populate it until the dedicated authorization/Alerts work.
- Plain `.venv/bin/pytest -q` import-path configuration remains unresolved; the verified command requires `PYTHONPATH=.`.
- Existing deprecation warnings remain unresolved.

## Acceptance Criteria Result

- [x] Existing scientific artifacts unchanged
- [x] Existing runtime prediction behavior preserved
- [x] Existing four tables preserved
- [x] `users` table added
- [x] `datasets` table added
- [x] `experiments` table added
- [x] `evaluation_results` table added
- [x] Model can reference an experiment
- [x] Prediction supports nullable provenance and imported-record idempotency
- [x] Alert can reference an acknowledging user
- [x] Administrator password is securely hashed
- [x] Authentication backend works
- [x] Additive migration works with legacy rows and SQLite/PostgreSQL conventions
- [x] Previous and new tests pass
- [x] Phase 1 documentation created

Phase 1 stops here. No Phase 2 implementation is included.
