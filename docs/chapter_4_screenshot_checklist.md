# Chapter IV Screenshot Checklist

Capture these from a development/test deployment containing no real credentials, tokens, or sensitive addresses. Browser screenshots must come from the actual application; none is fabricated by Phase 8.

| File | Required state | Must be visible | Chapter IV support | Masking |
|---|---|---|---|---|
| `01_login.png` | Logged out | RF-NIDS title, administrator email/password form | Authentication implementation/test | Mask entered email; never show password |
| `02_dashboard.png` | Logged in; safe runtime rows loaded | Active model, runtime class counters, alert counters, timeline/recent activity | Dashboard result | Mask operational IPs if not synthetic |
| `03_dataset.png` | Evidence synchronized | CICIDS2017 identity, 2,830,743 rows, 78 features, distribution/provenance | Dataset/evidence presentation | Source path may be cropped if it reveals a username |
| `04_models.png` | Active model synchronized | Random Forest, `rf-v1.0`, 78 inputs, parameters, metrics, artifact hash | Model/training information | Mask local absolute-path username |
| `05_evaluation_a.png` | Experiment A selected | identity, metrics, per-class values, confusion matrix | Experiment A evaluation | None beyond local paths |
| `06_evaluation_b.png` | Experiment B selected | scenario-validation identity, metrics, matrix/notes | Experiment B evaluation | None beyond local paths |
| `07_evaluation_c.png` | Experiment C selected | external/no-refit warning, 0.5404%, NULL macro display, zero attack recall, exact matrix | External validation/generalization result | None beyond local paths |
| `08_monitoring.png` | Safe runtime records present | totals, active model/latest time, filters, flow rows | Runtime monitoring | Mask non-synthetic IPs/interfaces |
| `09_predictions.png` | Safe runtime predictions present | filters, label/confidence/model/alert columns, export action | Prediction list | Mask non-synthetic IPs |
| `10_prediction_detail.png` | One prediction selected | probabilities, flow/model/provenance, stored feature section | Prediction traceability | Mask non-synthetic endpoints |
| `11_alerts.png` | Active HIGH and MEDIUM alerts present | summary, filters, alert list | Deterministic alert behavior | Mask non-synthetic endpoints/user email |
| `12_alert_detail.png` | Active alert selected | alert, prediction, flow, model, probabilities | Alert traceability | Mask non-synthetic endpoints/user email |
| `13_alert_acknowledged.png` | Alert acknowledged by test admin | ACKNOWLEDGED status, administrator, UTC timestamp | Acknowledgment audit trail | Mask administrator email |
| `14_dataset_export.png` | Authenticated dataset download completed | browser download plus opened JSON metadata/provenance | Dataset export | Mask exporter email and local paths |
| `15_evaluation_export.png` | Experiment C export downloaded | JSON/CSV with exact accuracy, NULL macros, matrix/provenance | Evaluation export/integrity | Mask exporter email and local paths |

Optional supporting captures: filtered prediction CSV, filtered alert CSV, invalid-login message, protected-access denial, session-expired Login notice, and Alembic head/pytest terminal result.
