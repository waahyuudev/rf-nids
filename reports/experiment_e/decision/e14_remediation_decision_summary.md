# E14 Remediation Decision

Decision: **RFV4_EXPERIMENT_JUSTIFIED** — only as a future, separately preregistered three-class research experiment. No RF-v4 was created or authorized, and RF-v3 remains inactive.

- PortScan remediation: **SUPPORTED** in the tested E6/E7 scope (RF-v3 recall 0.999334/0.998336 vs RF-v2 0).
- Normal preservation: **SUPPORTED** within the tested E6/E7/E13 scope.
- Controlled DDoS-like runtime weakness: **SUPPORTED** in scope; this is not universal DDoS recall.
- RF-v2→RF-v3 DDoS regression signal: **PARTIALLY_SUPPORTED**; paired changed decisions are demonstrated, universal degradation is not.
- Runtime/training DDoS distribution shift: **SUPPORTED**; causal mechanism remains unresolved.
- Primary pipeline defect explanation: **NOT_SUPPORTED** by exact E12 reproduction and E13 contract/hash checks.

E10/E13 must not be directly relabeled as DDoS training data. The required next design uses new explicit ground truth and independent generator nodes in an isolated, bounded lab; see the future requirements document.
