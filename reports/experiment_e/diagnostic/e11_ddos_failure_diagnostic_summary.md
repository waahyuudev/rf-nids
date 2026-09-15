# E11 DDoS Failure Diagnostic

E11 gate: **PASS_WITH_DOCUMENTED_LIMITATION**. Exact Session 11 78-feature vectors are **not recoverable** from the frozen E10 export, so no feature dataset, offline RF-v3 reproduction, RF-v2 same-flow comparison, Session 11-vs-DDoS shift table, or top shifted features was fabricated.

The exact committed RF-v3 DDoS reference is the 3,081-row DDoS subset of the frozen E4 candidate training dataset. Its per-feature statistics and RF-v3 global feature importances are preserved in [the diagnostic JSON](e11_ddos_failure_diagnostic.json). The highest persisted P(DDoS) Session 11 rows are reported there from stored probabilities only; their feature values cannot be inspected.

No schema, extractor provenance, or model-loading/ordering error is established. E3-A1 records the runtime extractor as compatibility-qualified; actual Session 11 input ordering cannot be independently reproduced without the missing vectors.

Scientific decision: **ROOT_CAUSE_UNRESOLVED**. The only assigned category is **INSUFFICIENT_EVIDENCE**. This authorizes neither remediation nor promotion.

Evidence SHA-256: `364e709bd5411f2965bef2c667d7d32d03c723537ffc5845315733e0d11b75a0`
