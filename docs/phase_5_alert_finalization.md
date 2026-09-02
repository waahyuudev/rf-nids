# Phase 5 — Alert Finalization

Completed: 2026-09-02  
Scope: application alert behavior, read presentation, and administrator acknowledgment only. Full Login UX and Export remain outside Phase 5.

## Previous Behavior

Runtime inference persisted every prediction, but `src/api/service.py` created an alert only when the label was non-Normal and confidence met `ALERT_CONFIDENCE_THRESHOLD`. The setting defaulted to `0.70` in `Settings`, `.env.example`, and Docker Compose. This suppressed low-confidence attack predictions even though the classifier label remained DDoS or PortScan.

Alert creation already occurred in the same transaction as flow/prediction persistence. Severity mapping was DDoS → HIGH and PortScan → MEDIUM, new status was ACTIVE, and acknowledgment changed status to ACKNOWLEDGED with a timestamp. The database already enforced one alert per prediction through the unique `alerts.prediction_id` constraint. The acknowledgment endpoint did not require authentication and did not populate `acknowledged_by_user_id`.

## Final Deterministic Rule

Phase 5 implements the frozen application rule:

```text
Normal   → no alert
PortScan → MEDIUM alert
DDoS     → HIGH alert
```

Confidence remains unchanged in predictions, probability vectors, API responses, tables, and details. It no longer participates in alert creation. No classifier threshold, inference output, model artifact, preprocessing, or prediction label was changed.

`ALERT_CONFIDENCE_THRESHOLD` was removed rather than deprecated because it was internal application configuration and had no valid remaining behavior. It was removed from `Settings`, environment loading, Compose, `.env.example`, call sites, tests, and current README guidance.

## Idempotency and Legacy Data

The existing unique constraint on `alerts.prediction_id` remains the authority for at-most-one alert per prediction. Phase 5 does not introduce a second duplicate mechanism. Flow, prediction, and alert writes remain one transaction with rollback on failure.

Existing predictions and alerts are not rewritten. Attack predictions previously suppressed by the confidence gate are not automatically backfilled. Scientific and imported Experiment A/B/C records are not reconciled into runtime alerts. Legacy ACKNOWLEDGED alerts with a null `acknowledged_by_user_id` remain valid and display `Not available` for the user.

## Administrator Acknowledgment

`PATCH /api/alerts/{id}/acknowledge` now requires the existing Phase 1 Bearer administrator session. The first acknowledgment atomically records:

- `status=ACKNOWLEDGED`
- `acknowledged_at` using the current UTC time
- `acknowledged_by_user_id` using the authenticated administrator

Repeated acknowledgment is safe and returns the original user and timestamp without replacing them. No historical user is fabricated.

Phase 5 did not add full Login UX and originally used a development session-token bridge. Phase 6 supersedes that temporary workflow with interactive Streamlit login/logout and session-state bearer handling; `RF_NIDS_ACCESS_TOKEN` is no longer used.

## API and UI

The existing alert endpoints remain backward-compatible read paths:

- `GET /api/alerts` now supports bounded pagination and server-side attack type, severity, status, source-IP, and destination-IP filters for runtime alerts.
- `GET /api/alerts/{id}` now returns joined prediction probabilities, flow endpoints/ports/protocol/capture time, model identity/version, runtime provenance, and acknowledgment identity.
- `PATCH /api/alerts/{id}/acknowledge` now requires the current administrator.

The Alerts page shows Total Alerts, Active Alerts, active HIGH/MEDIUM counts, and Acknowledged count. Its table includes attack type, severity, endpoints, confidence, status, acknowledging user, and acknowledgment time. Alert Detail presents alert, prediction, flow, model, provenance, and stored probability sections. The acknowledge control is enabled only when a session token is configured.

Dashboard now labels the combined count as Total Alerts and the active-only count as Active Alerts. Monitoring exposes and labels both Total Alerts and Active Alerts.

## Tests

Coverage includes:

- Normal creates no alert.
- DDoS and PortScan create HIGH and MEDIUM alerts respectively.
- Low-confidence DDoS and PortScan still alert.
- The unique database constraint rejects a duplicate alert for one prediction.
- Alert list filters and joined detail metadata.
- Unauthorized acknowledgment rejection.
- Administrator user/time recording and repeat-safe acknowledgment.
- ACTIVE/ACKNOWLEDGED counters and legacy null-user compatibility.
- Dashboard API authentication header and alert-filter mapping.

The authoritative command is:

```bash
PYTHONPATH=. .venv/bin/python -m pytest -q
```

## Manual Verification

Manual verification used a temporary SQLite runtime database and an isolated deterministic development inference fixture. This was necessary because the legitimate frozen external-lab rows preserve the documented Experiment C generalization result and must not be relabeled or fabricated for an alert demonstration. The fixture exercised the normal application persistence/API/UI path with Normal, PortScan, DDoS, and low-confidence attack outputs; it was confined to `/tmp` and removed afterward.

The browser confirmed five predictions (one Normal, two DDoS, two PortScan), four deterministic alerts, Alert Detail, and authenticated acknowledgment of a low-confidence PortScan alert. The acknowledged row recorded `Phase 5 Admin`, user ID `1`, and a UTC timestamp. Afterward Dashboard, Monitoring, and Alerts all reported four total alerts and three active alerts. Experiment C per-flow evidence was never imported.

## Scientific Integrity

Before Phase 5 the recorded SHA-256 values were:

- active model: `73d86cb98f35c228d6e619e0f746a2b659d94deabe86d57e801c58bcf935f647`
- model metadata: `c632b16d30efb8f5a642070520c43cc1caaf36cbead33bddf9b5359b0fb531f2`
- Experiment C final report: `6e091fdc1f0113fd34403d60dafdea83e6aa6ee957bf4a77632da31c6478f02b`

These hashes are verified again after implementation. No files under `models/`, `reports/`, or `data/lab/pcap/` are modified.

## Remaining Gaps

- Phase 6: complete interactive Login/logout UX and route/page protection.
- Phase 7: deterministic application Export/Report.
- No automatic alert backfill exists for legacy low-confidence runtime attack predictions; this is deliberate.

Phase 5 stops here.
