# Phase 6 — Administrator Authentication UX

## Scope and Existing Architecture Audit

Phase 6 completes the existing Phase 1 authentication foundation without changing the scientific core. Phase 1 already provided normalized email lookup, salted scrypt password hashes, an interactive administrator bootstrap command, opaque bearer tokens, SHA-256 token digests held in process memory, an eight-hour configurable lifetime, logout revocation, and `/api/auth/me`. Plaintext passwords are neither persisted nor logged. Unknown-email login performs the same scrypt work as a known account to reduce timing differences.

The existing design remains in place. Phase 6 adds the `require_admin` dependency, applies it to human-facing application endpoints, and integrates the bearer session into Streamlit.

## Login and Session UX

When no local session exists, Streamlit renders only the RF-NIDS administrator Login view with email and hidden password fields. A valid active ADMIN response stores only the opaque access token and public user representation in `st.session_state`, then reruns into Dashboard. Invalid, inactive, and unauthorized-role responses produce a normalized user-facing failure and do not create local state; raw backend exception text is not shown on Login.

`dashboard/auth.py` centralizes storage, clearing, current-user verification, role checking, and authentication-failure handling. `require_login` calls `/api/auth/me` before protected navigation is rendered. A 401/403 clears both token and user, stores the message “Your session has expired. Please log in again.”, and returns to Login. An API outage does not erase an otherwise valid local token; the user sees an availability message and can retry after recovery.

The authenticated sidebar shows administrator name, email, and role. Only Dashboard, Dataset, Models, Evaluation, Monitoring, Predictions, and Alerts appear. Logout first asks the API to revoke the bearer session, then clears local state even if the API is unavailable. A successfully revoked token cannot be reused.

## API Client and Endpoint Protection

`RFNIDSClient` accepts a token provider so every protected request reads the current Streamlit session token and automatically sends `Authorization: Bearer <token>`. Pages do not receive or pass tokens manually. The client also exposes login, current-user, and logout operations.

Final endpoint decision:

| Category | Access | Reason |
|---|---|---|
| `GET /health` | Public | Local service readiness check |
| `/api/auth/login` | Public | Session establishment |
| `/api/auth/me`, `/api/auth/logout` | Authenticated ADMIN | Identity and session lifecycle |
| model and active-model metadata | Authenticated ADMIN | Application presentation data |
| datasets, evidence sources, experiments, evaluations | Authenticated ADMIN | Thesis evidence presentation |
| traffic flows, monitoring, predictions, alerts, dashboards | Authenticated ADMIN | Operational and potentially sensitive data |
| alert acknowledgment | Authenticated ADMIN | Audited administrator action; user ID comes only from the bearer session |
| `POST /api/predict` and `/api/predict/batch` | Intentionally local/internal and unauthenticated | Existing capture/ingestion processes submit flows without an interactive administrator session |

The runtime inference exception is an explicit local-prototype trust-boundary decision, not a public deployment recommendation. Network-level restriction or machine credentials are required before exposing the API outside the trusted development environment.

## Administrator Role and Password Security

The prototype supports only `ADMIN`. Login rejects any other role and every protected dependency rechecks it. This is deliberately smaller than general RBAC while leaving a reusable dependency boundary.

Bootstrap remains:

```bash
PYTHONPATH=. .venv/bin/python scripts/bootstrap_admin.py \
  --name "RF-NIDS Administrator" \
  --email "admin@example.local"
```

The password is requested twice with hidden interactive input, requires at least 12 characters, is immediately scrypt-hashed with a random salt, and has no CLI/default-password option. Duplicate normalized email and empty administrator names fail clearly.

## Session Expiration and Restart

Bearer sessions remain intentionally in memory. Restarting FastAPI discards all session digests, so the next protected request returns 401. Streamlit clears the stale local token and user, displays the expiration message, and returns to Login. Stored credentials are never retained or silently replayed. Multi-worker or durable deployments would require a shared session store; this remains outside the local thesis prototype.

## Verification

Automated coverage includes valid and invalid login, inactive users, current-user output, logout/revocation, unknown tokens, missing-token protected access, authorized access, ADMIN enforcement, dynamic client token injection, page-guard behavior, clearing on 401/403, preserving state during an API outage, authenticated acknowledgment identity, and absence of password/hash fields from responses. The complete command `PYTHONPATH=. .venv/bin/python -m pytest -q` reports **153 passed** with 329 pre-existing dependency deprecation warnings.

The live verification used a temporary SQLite development database and real development administrator. Logged-out rendering exposed only Login; invalid credentials were rejected; valid login displayed the identity and all seven protected pages without exceptions; acknowledgment stored that administrator; logout invalidated the old token; and an API restart changed the old token response from 200 to 401 while Streamlit cleared navigation and displayed the session-expired message.

Manual demo checklist:

1. Bootstrap a development administrator and start FastAPI plus Streamlit.
2. Confirm logged-out navigation shows only Login and an invalid password is rejected.
3. Log in and visit all seven protected pages; confirm sidebar identity.
4. Acknowledge an active alert and confirm the current administrator is recorded.
5. Logout and confirm the old bearer token returns 401.
6. Log in again, restart FastAPI, and confirm the prior Streamlit session returns to Login with the expiration message.

## Scientific Integrity and Limitations

Phase 6 does not retrain, refit, tune, or rerun experiments. The model, metadata, reports, PCAPs, inference adapter, and fitted preprocessing remain untouched. Before and after implementation, SHA-256 remained `73d86cb98f35f228d6e619e0f746a2b659d94deabe86d57e801c58bcf935f647` for `models/random_forest_active.joblib`, `c632b16d30efb8f5a642070520c43cc1caaf36cbead33bddf9b5359b0fb531f2` for `models/model_metadata.json`, and `488aac694a82fca60971cbba3712435ccdc9f80a24a0759bcc06e825248d74f0` for `reports/experiment_c/experiment_manifest.json`. Git reports no changes under `models/`, `reports/`, or `data/lab/pcap/`.

Remaining limitations are the in-memory single-process session registry, the trusted-local unauthenticated inference ingress, no rate limiting/account lockout, no password recovery/registration, and no generalized RBAC. These are appropriate documented constraints for the administrator-only local prototype. Phase 7 export/report functionality was not started.
