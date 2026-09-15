# E10 Runtime Validation Analysis

Frozen-export checksum verification: PASS (six CSV inputs match `SHA256SUMS`).

- E10-N-R1 / Session 10: 18 Normal, 0 DDoS, 0 PortScan; scoped Normal classification rate: 18/18 = 100%.
- E10-D-R1 / Session 11: 802 Normal, 0 DDoS, 0 PortScan; scoped DDoS-like detection rate: 0/802 = 0%. This is not universal DDoS recall.
- Session 11 expected logical sources: 10.10.10.11/12/13/14 each contributed 200 predictions. Two additional frozen records are documented in the JSON; 800/802 have destination `10.10.20.2:8080`.
- Alert export: 0 alerts; severity distribution: empty.
- RF-v2 identical-flow comparison: unavailable because the frozen export has no exact 78-feature vectors or recoverable feature payloads.
- Scientific decision: **NOT_SUPPORTED** for this scoped controlled multi-source DDoS-like runtime workload. E8's `MORE_VALIDATION_REQUIRED` is reinforced; E9 promotion is not authorized.

The four logical sources originated from one ubuntu-traffic VM, so this is not evidence of a real distributed DDoS attack. Full probabilities, artifact hashes/provenance, target-scope exceptions, and integrity hashes are in [the JSON analysis](e10_runtime_validation_analysis.json).

Evidence SHA-256: `a0f85f3110df012359fef7203065e5f70c6b766ef1c8fab1a9397b7452d013ac`
