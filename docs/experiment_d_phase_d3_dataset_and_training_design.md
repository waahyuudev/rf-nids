# Experiment D Phase D3: Dataset and RF-v2 Training Design

## Scope and outcome

D3 is pre-training only. It revalidated D2, froze path-independent row membership, selected controlled adaptation candidates, and added a manifest-only RF-v2 dry run. No estimator was instantiated or fitted, no prediction was made, and no final-test data was inspected.

## D2 revalidation and adaptation audit

The nine valid source sessions contain 15,914 usable flows: Normal 44, PortScan 1,554, and DDoS 14,316. There are exactly three valid sessions per class. `expd-adapt-ddos-session-03` remains preserved but excluded; replacement session `expd-adapt-ddos-session-04` is valid. Every flow file matches its D2 SHA-256 identity and adapts to the same ordered 78-feature schema. The D2 leakage audit remains PASS.

`reports/experiment_d/adaptation/d3_adaptation_audit.json` records observed per-session counts, missing/non-finite values, duplicates, unique rows, scenario and endpoint metadata, pairwise cross-session exact-feature overlaps, and descriptive distributions for eight operationally important features. No model output or feature selection informed this audit.

The data contain substantial repeated feature vectors. D3 does not conceal them. Adaptation validation retains complete held-out captures as observations. From the adaptation training pool, a row is excluded if its feature signature occurs in adaptation validation, then later within-class copies are deterministically removed. This removes 3,601 validation-overlapping training observations and 366 additional within-class copies, leaving 4,792 leakage-clean unique training candidates. Two feature signatures also occur in CICIDS2017; every CICIDS2017 row carrying either signature is excluded from both its training and internal-control components.

## Whole-session adaptation split

The frozen training sessions are:

- Normal: `expd-adapt-normal-session-01`, `expd-adapt-normal-session-02`
- PortScan: `expd-adapt-portscan-session-01`, `expd-adapt-portscan-session-02`
- DDoS: `expd-adapt-ddos-session-01`, `expd-adapt-ddos-session-02`

The frozen validation sessions are:

- Normal: `expd-adapt-normal-session-03` (modest-concurrency scenario), 23 flows
- PortScan: `expd-adapt-portscan-session-03` (slow, selected-port scenario), 16 flows
- DDoS: `expd-adapt-ddos-session-04` (held-out concurrency 24 replacement scenario), 7,116 flows

The PortScan validation support is small, but it provides the clearest scenario separation and no exact cross-session feature overlap. Its recall must therefore be reported with its support and treated as a coarse 1/16-resolution estimate. Holding out the 513-flow moderate scan would create 365 exact-signature overlaps with the wide-fast training capture and would force extensive exclusions without improving scenario independence.

## Imbalance and candidate strategies

Raw adaptation data must not be appended silently. D3 registers four deterministic alternatives after leakage cleaning:

| Strategy | Normal | DDoS | PortScan | Rationale and risk |
|---|---:|---:|---:|---|
| D3-A | 13 | 3,606 | 1,173 | Uses every leakage-clean unique training vector; preserves evidence but remains attack- and DDoS-heavy. |
| D3-B | 13 | 1,173 | 1,173 | Caps each attack class at the smaller available attack pool; class-controlled, but can concentrate large sessions. |
| D3-C | 13 | 1,200 | 1,113 | Caps each session at 600 and retains all scarce Normal rows; best preservation of scenario provenance with limited domination. |
| D3-D | 13 | 13 | 13 | Fully class-balanced without synthesis; scientifically clean but discards too much attack variation for the first D4 test. |

D3-C is the recommended first D4 strategy. Ranking is SHA-256 based on the stable row identity and sampling seed 42, so it is independent of absolute filesystem paths. No rows are synthesized, and Normal rows are never duplicated.

## Normal limitation

Only 44 Normal lab observations exist; after holding out session 03 and excluding validation-overlapping/repeated training signatures, 13 remain available for adaptation training. This is weak lab coverage and limits claims about diverse benign environments. It does not require stopping before D4 because the unchanged CICIDS2017 base contributes 1,677,185 Normal training rows, the 13 lab rows are retained as-is, and an independent 23-row lab Normal session is preserved for validation. Additional diverse Normal capture is scientifically advisable before deployment or broad external-validity claims, but is not required for the controlled first RF-v2 comparison.

## CICIDS2017 integration and provenance

The original eight canonical CSVs are read in their recorded order and never modified. D3 preserves RF-v1 label mapping, ordered 78-feature schema, leakage-column policy, numeric conversion, infinity-to-NaN conversion, filtering, and exact feature-plus-label deduplication. The historical deterministic 80/20 stratified split is reconstructed with seed 42, checked against RF-v1 counts, and then frozen as compressed bitsets. After the two-signature cross-source exclusion, CICIDS2017 contributes:

- Training: Normal 1,677,185; DDoS 102,413; PortScan 72,655
- Internal control: Normal 419,296; DDoS 25,603; PortScan 18,164

For preferred D3-C, planned combined training is Normal 1,677,198; DDoS 103,613; PortScan 73,768 (1,854,579 rows total).

The split manifest records source family/file, capture, session, scenario, class, split role, original row position or reproducible membership basis, and stable row identity. These provenance fields are explicitly prohibited from classifier features.

## Preprocessing, classifier, and selection

The pipeline remains `SimpleImputer(strategy="median")` followed by the Random Forest. Only D4's combined training partition may fit the imputer. Adaptation validation, CICIDS2017 internal control, Experiment C, and final-test data may never fit preprocessing. No scaling or feature selection is introduced.

D4 should begin with fixed RF-v1 parameters: 200 estimators, Gini criterion, unlimited depth, minimum split 5, minimum leaf 4, `max_features="log2"`, balanced class weights, no bootstrap, seed 42, all jobs, and `ccp_alpha=0.0`. The first question is adaptation benefit under an unchanged classifier, so RandomizedSearchCV is not authorized for the initial run.

Primary selection evidence is adaptation-validation macro F1 plus DDoS, PortScan, and Normal recall. Per-class precision/F1, confusion matrix, Normal false-positive rate, and CICIDS2017 internal-control behavior are also reported. A candidate must have non-zero DDoS and PortScan recall, Normal recall of at least 0.50, and adaptation macro F1 no lower than RF-v1 on the identical held-out sessions. Passing candidates rank by adaptation macro F1, minimum per-class recall, Normal false-positive rate, then CICIDS2017 internal-control macro F1. These rules are fixed before any future final test.

## Artifacts and D4 readiness

The authoritative artifacts are `split_manifest.json`, `rf_v2_training_plan.json`, the detailed D3 audit, and the three distribution CSVs under `reports/experiment_d/adaptation/`. `scripts/train_rf_v2.py --dry-run` validates membership checksums, complete session separation, preprocessing, caps, prohibited-source flags, and the exact create-new output contract. D4 may eventually write only:

- `models/experiment_d/random_forest_rf_v2.joblib`
- `models/experiment_d/random_forest_rf_v2_metadata.json`
- `models/experiment_d/training_manifest.json`

RF-v1 destinations remain immutable. D3 deliberately leaves real training unavailable. Future final-test directories may contain only repository placeholders; no final-test PCAP, flow CSV, manifest, statistic, or prediction may exist or participate in D4.
