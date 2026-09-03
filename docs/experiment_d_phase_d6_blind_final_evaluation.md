# Experiment D Phase D6: Blind Final Evaluation

## Methodology and pre-inference integrity

This was a one-shot blind evaluation. The fail-closed gate verified RF-v1 and RF-v2 artifacts and metadata, the RF-v2 frozen manifest, all sealed PCAP and flow hashes, adapter and crosswalk identity, CICFlowMeter V3 provenance, leakage status, sealed counts, and unused output paths. Both frozen sklearn pipelines received one canonical 15,949-row, 78-feature matrix. No fitting, tuning, threshold selection, feature selection, resampling, or adaptation occurred. `predict(X)` and `predict_proba(X)` were called exactly once per model.

Sealed identity: `a60d79e66690dcb146e76a80dee5ff4e550abd298575a92d77be6db447881d18`. Ground-truth identity: `a5dec5d0197eee4601843f4832d51de1c86b52361e5f42f36fecebc157749e79`. Canonical row-order identity: `c89d2b8cf7bb848f8a5d397865870ba0c8823dd1073ea77a9142de152faf0fba`. Distribution: Normal 30, DDoS 15,482, PortScan 437.

## RF-v1 results

Accuracy 0.001943696; macro F1 0.002773791; weighted F1 0.000132177; Normal FPR 0.999937182; attack detection rate 0.000062818.

| Class | Support | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| Normal | 30 | 0.001881 | 1.000000 | 0.003755 |
| DDoS | 15482 | 0.000000 | 0.000000 | 0.000000 |
| PortScan | 437 | 1.000000 | 0.002288 | 0.004566 |

| Actual | Normal | DDoS | PortScan |
|---|---:|---:|---:|
| Normal | 30 | 0 | 0 |
| DDoS | 15482 | 0 | 0 |
| PortScan | 436 | 0 | 1 |

## RF-v2 results

Accuracy 0.102953163; macro F1 0.376822804; weighted F1 0.165626977; Normal FPR 0.898611722; attack detection rate 0.101388278.

| Class | Support | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| Normal | 30 | 0.001954 | 0.933333 | 0.003899 |
| DDoS | 15482 | 0.998324 | 0.076928 | 0.142849 |
| PortScan | 437 | 1.000000 | 0.967963 | 0.983721 |

| Actual | Normal | DDoS | PortScan |
|---|---:|---:|---:|
| Normal | 28 | 2 | 0 |
| DDoS | 14291 | 1191 | 0 |
| PortScan | 14 | 0 | 423 |

## Same-row comparison and sessions

RF-v2 minus RF-v1 macro F1 was +0.374049013. Recall deltas were Normal -0.066666667, DDoS +0.076928045, and PortScan +0.965675057. RF-v2 achieved non-zero DDoS recall: **True**; non-zero PortScan recall: **True**; Normal recall 0.933333333. Recall improved in 6 of nine independent sessions.

| Class | Session | Flows | RF-v1 recall | RF-v2 recall |
|---|---|---:|---:|---:|
| Normal | expd-final-normal-session-02 | 6 | 1.000000 | 0.666667 |
| Normal | expd-final-normal-session-03 | 12 | 1.000000 | 1.000000 |
| PortScan | expd-final-portscan-session-01 | 200 | 0.000000 | 1.000000 |
| PortScan | expd-final-portscan-session-02 | 221 | 0.000000 | 0.986425 |
| PortScan | expd-final-portscan-session-03 | 16 | 0.062500 | 0.312500 |
| DDoS | expd-final-ddos-session-01 | 1200 | 0.000000 | 0.000833 |
| DDoS | expd-final-ddos-session-02 | 2400 | 0.000000 | 0.495417 |
| DDoS | expd-final-ddos-session-03 | 11882 | 0.000000 | 0.000084 |
| Normal | expd-final-normal-session-04 | 12 | 1.000000 | 1.000000 |

## Context, limitations, and interpretation

Experiment C remains immutable historical evidence: RF-v1 recognized 61/61 Normal flows but 0/10,226 DDoS and 0/1,000 PortScan flows (accuracy 0.005404447594577833). It demonstrates RF-v1 failure on the earlier external laboratory set. Experiment D uses a new sealed set; the fair causal comparison is RF-v1 versus RF-v2 on identical D6 rows, not a direct comparison of Experiment C and D scores.

The set is extremely imbalanced and has only 30 Normal observations. Accuracy is secondary; macro F1, per-class recall, and session consistency are essential. No rows were rebalanced or resampled. D4 CICIDS2017 internal-control performance remains contextual evidence that adaptation did not materially destroy original-distribution performance; it was not recomputed or used to alter D6.

On this sealed set, RF-v2 demonstrates improved external generalization relative to RF-v1. This is limited to the preregistered captures and should not be generalized without further independently sealed evaluation.

## Scientific-integrity audit

Status: **PASS**. RF-v1, RF-v2, sealed inputs, ground truth, Experiment C, D2-D5 evidence, adapter, and crosswalk remained unchanged. RF-v2 remained `fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31`; RF-v2 was not activated; no training occurred. Metrics use `zero_division=0`.
