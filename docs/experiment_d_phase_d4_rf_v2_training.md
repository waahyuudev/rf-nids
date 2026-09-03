# Experiment D Phase D4: RF-v2 Training and Internal Validation

## Outcome

`RF-v2-D3C` was trained exactly once under the frozen D3 plan and passed every pre-registered internal gate. It is frozen as an Experiment D candidate, not an active application model. No final-test artifact was generated or inspected.

Declaration: **RF-v2 INTERNAL CANDIDATE ACCEPTED**.

## Training inputs and split boundaries

The CICIDS2017 component used the eight canonical, hash-verified source CSVs and the exact compressed training membership frozen in D3. The adaptation component used D3-C's deterministic row identities from:

- Normal training: sessions 01 and 02
- DDoS training: sessions 01 and 02
- PortScan training: sessions 01 and 02

The adaptation validation captures remained whole and unresampled: Normal session 03 (23 rows), DDoS replacement session 04 (7,116 rows), and PortScan session 03 (16 rows). Invalid DDoS session 03 remained excluded. The CICIDS2017 internal-control partition remained held out with 463,063 rows.

The exact combined training distribution was Normal 1,677,198, DDoS 103,613, and PortScan 73,768, totaling 1,854,579 rows. Adaptation contributed 13 Normal, 1,200 DDoS, and 1,113 PortScan rows. No duplication, synthesis, SMOTE, validation capping, threshold tuning, or hyperparameter search occurred.

## Preprocessing and classifier

The fitted sklearn pipeline is `SimpleImputer(strategy="median")` followed by `RandomForestClassifier`. The imputer was fitted only through the combined training data. No scaling or feature selection was used, and exactly the frozen 78 ordered features reached the pipeline.

The Random Forest used 200 estimators, Gini criterion, unlimited depth, minimum split 5, minimum leaf 4, `max_features="log2"`, `class_weight="balanced"`, `bootstrap=False`, `random_state=42`, `n_jobs=-1`, and `ccp_alpha=0.0`.

Training ran from 2026-09-03 04:18:43 UTC to 04:20:15 UTC and took 91.687 seconds. The process-lifetime resident-memory high-water mark reported by macOS was 5,018,976,256 bytes; this is an observed process measurement, not a hardware-performance claim.

## Candidate artifact

The candidate is `models/experiment_d/random_forest_rf_v2.joblib`, size 14,150,634 bytes, SHA-256 `fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31`. Metadata identifies it as `rf-v2.0-experiment-d`, role `Experiment D candidate`, with `active=false`. The metadata and training manifest preserve source hashes, split identities, parameters, feature order, environment versions, session membership, and validation evidence hashes.

## Adaptation validation

| Metric | RF-v1 | RF-v2 |
|---|---:|---:|
| Accuracy | 0.003215 | 0.491265 |
| Macro precision | 0.001072 | 0.667274 |
| Macro recall | 0.333333 | 0.672352 |
| Macro F1 | 0.002136 | 0.532875 |
| Normal recall | 1.000000 | 0.652174 |
| DDoS recall | 0.000000 | 0.489882 |
| PortScan recall | 0.000000 | 0.875000 |

RF-v1 predicted every adaptation-validation row as Normal. Its confusion matrix, with rows and columns ordered Normal, DDoS, PortScan, was `[[23,0,0],[7116,0,0],[16,0,0]]`. RF-v2's matrix was `[[15,8,0],[3630,3486,0],[2,0,14]]`.

RF-v2 materially improves balanced recognition, but DDoS recall remains only 0.490 and 8 of 23 Normal flows are false positives. PortScan recall is based on only 16 rows and therefore has wide uncertainty. Acceptance is an internal gate result, not evidence of final external-test success or deployment readiness.

## CICIDS2017 internal control

| Metric | RF-v1 | RF-v2 |
|---|---:|---:|
| Accuracy | 0.9995767 | 0.9995789 |
| Macro F1 | 0.9981533 | 0.9981602 |
| Normal recall | 0.9995540 | 0.9995564 |
| DDoS recall | 0.9998828 | 0.9998828 |
| PortScan recall | 0.9996697 | 0.9996697 |

RF-v1's control confusion matrix was `[[419109,5,182],[3,25600,0],[6,0,18158]]`; RF-v2's was `[[419110,4,182],[3,25600,0],[6,0,18158]]`. Thus the adaptation candidate did not catastrophically degrade the pre-registered original-distribution control.

## Pre-registered decision

RF-v2 passed all four unchanged gates: DDoS recall was non-zero, PortScan recall was non-zero, Normal recall was at least 0.50, and adaptation macro F1 was no worse than RF-v1 on the identical rows. No post-result criteria, label, threshold, seed, split, or training-input changes were made.

## Leakage and scientific integrity

The D4 leakage audit is PASS. Adaptation validation and CICIDS2017 control were excluded from fit; training and validation sessions/captures do not overlap; D3 cross-source duplicate handling remains enforced; provenance was excluded from features; only 78 features reached the model; and preprocessing fit stayed inside the training pipeline.

The frozen baseline identity was `907ad890f4a7e830cc9ca4d38ee6b99075bab5a06ee6cdda0725db52cc0f7e70` both before and after D4. Consequently RF-v1, Experiment C, the adapter/crosswalk, and CICFlowMeter provenance remained unchanged. D2/D3 inputs were read-only. The final-test tree still contains no non-placeholder artifacts, and RF-v2 was not activated in the application.

## Evidence and D5 boundary

Metrics, labelled confusion matrices, row-level predictions with probabilities, the internal comparison, and the D4 leakage audit are stored under `reports/experiment_d/adaptation/` and `reports/experiment_d/audit/`. The candidate may proceed to a separately authorized, one-shot D5 final test. D4 does not authorize creating final-test traffic or activating this model.
