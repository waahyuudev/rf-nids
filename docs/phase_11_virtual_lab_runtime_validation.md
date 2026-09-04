# Phase 11 — Virtual Lab Runtime Validation

## 1. Purpose

Phase 11 validates that real, manually generated laboratory traffic traverses the complete production-like path: capture interface → `tcpdump` → bounded PCAP → pinned CICFlowMeter V3 → audited 78-feature adapter → active Random Forest inference → database → alerts → dashboard. It evaluates runtime integration; it does not retrain the model or improve accuracy.

## 2. Architecture

RF-NIDS owns capture and processing on its host. Each prediction retains the monitoring session, model, PCAP segment, and runtime external key. A validation run snapshots session/model/extractor/adapter identity at creation and computes its final evidence from committed rows and session-owned artifacts. Browser-supplied counts, identities, distributions, and paths are rejected by the API schema.

## 3. Preconditions

- Kali and Ubuntu are isolated laboratory machines on a private network.
- The target is a private lab address only; confirm routing and the RF-NIDS capture interface.
- `tcpdump`, Docker, the pinned CICFlowMeter V3 image, PostgreSQL (or the configured database), the API, and Streamlit are available.
- The active scientific model is the intended frozen model (`rf-v1.0` for this phase).
- Apply `alembic upgrade head` before starting the API.

RF-NIDS does not generate attack traffic, automate Kali/SSH, invoke Nmap, or implement DDoS generation. A human operator may use their own laboratory tooling outside the application.

## 4. Network roles

- Kali: manually operated traffic source.
- Ubuntu: private-address target for normal HTTP and operator-controlled PortScan traffic.
- RF-NIDS host: passive capture, flow extraction, inference, persistence, alerting, and presentation.

Do not target public addresses or systems outside the isolated lab.

## 5. Normal HTTP validation

1. Start the Ubuntu HTTP service manually and confirm its private IP.
2. Start RF-NIDS monitoring for that IP and the correct capture interface.
3. Create a `NORMAL_HTTP` validation from the Monitoring page (or API).
4. Generate ordinary HTTP requests manually and wait for at least one completed capture window.
5. Confirm recent predictions appear, then complete the validation.
6. Record the returned validation ID and evidence. Normal detection passes when at least half of committed predictions are `Normal`; the full observed distribution is always retained.

## 6. PortScan validation

1. While monitoring the Ubuntu private IP, create a `PORTSCAN` validation.
2. From Kali, manually generate the approved lab scan with operator-owned tooling.
3. Wait for capture, extraction, inference, and persistence, then complete the validation.
4. Interpret pipeline and detection separately. `pipeline_result=PASS` with `detection_result=FAIL` is legitimate and consistent with a model that received the traffic but predicted every flow as Normal.

RF-NIDS contains no scan command and does not automate this activity.

## 7. Stop/restart validation

1. On the first session, create a `STOP_RESTART` validation after at least one processing cycle.
2. Stop monitoring and verify the session reaches `STOPPED`.
3. Start a second session normally on the lab target and observe its status.
4. Complete the validation using the first session ID.
5. The server checks the cleared runtime handle, first-session processing, a later second session, and absence of predictions written to the first session after its stop time.

## 8. Evidence captured

Evidence includes session/target/interface, timestamps, PCAP filename/SHA-256/bytes, extracted CSV row count, 78-feature-valid persisted flows, prediction and alert counts, prediction IDs/range, label distribution, probability min/mean/max by class, model ID/version, extractor identity, adapter identity, and lifecycle facts where applicable. Values are calculated server-side from session artifacts and committed database rows.

## 9. PASS/FAIL definitions

- Normal/PortScan pipeline PASS: a processed PCAP exists, extraction yields rows, at least one persisted flow has exactly 78 adapted features, predictions are committed against the session model, and session provenance is present.
- Normal detection PASS: at least an agreed majority (implemented as at least half) of the validation predictions are Normal.
- PortScan detection PASS: at least one validation prediction is PortScan.
- Stop/restart pipeline PASS: first session stopped after processing, its owned handle is cleared, a later session starts, and no stale writes occur after the first stop.
- Stop/restart detection: `NOT_APPLICABLE`.
- No predictions: detection remains `NOT_EVALUATED`.

## 10. Known limitations

Automated CI tests control flow and evidence aggregation; they do not claim real Kali traffic or scientific detection success. Files removed outside RF-NIDS before completion cannot be hashed. Process termination is represented by controller-owned handle clearance and the session lifecycle; operating-system inspection remains an operator observation. Only flows committed after validation start belong to its prediction evidence window.

## 11. Scientific interpretation

Pipeline correctness and detection effectiveness are independent outcomes. A successful pipeline proves integration and provenance, not classifier sensitivity. Preserve observed failures and distributions without changing thresholds, class mappings, preprocessing, the audited adapter, CICFlowMeter compatibility, or frozen Experiment A/B/C evidence.

## Manual commands

From the RF-NIDS project host:

```bash
.venv/bin/alembic upgrade head
.venv/bin/uvicorn src.api.main:create_app --factory --host 127.0.0.1 --port 8000
.venv/bin/streamlit run dashboard/app.py
```

Use the Streamlit Monitoring page to start sessions and validation runs. Traffic generation stays manual and outside RF-NIDS. If the required virtual machines are unavailable, record exactly:

`MANUAL_LAB_VALIDATION = NOT_EXECUTED`
