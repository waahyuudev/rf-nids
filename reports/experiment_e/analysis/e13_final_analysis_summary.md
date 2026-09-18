# E13 Final Scientific Analysis

All integrity and reconstruction gates passed. The locked adapter reconstructed E13-N-R1 (32×78), E13-D1-R1 (801×78), and E13-D2-R1 (1612×78); frozen RF-v2 and RF-v3 were evaluated offline on those same vectors.

- RF-v3 scoped Normal rate: 32/32.
- RF-v3 scoped controlled-DDoS-like detection: D1 2/801; D2 4/1612; E10 was 0/802. These are not universal DDoS recall.
- Median robust distance to frozen E4 DDoS: D1 0.6095; D2 1. D2 is not closer by this preregistered aggregate diagnostic.
- Case decision: **No preregistered case fully supported**.
- Runtime alert counts (0/2/4) are kept distinct from offline anomalous RF-v3 counts because E13 alert exports are unavailable.

No traffic, runtime DB write, model change, threshold change, retraining, or promotion occurred. Full results are in `e13_final_analysis.json`; feature and paired-model tables are adjacent.
