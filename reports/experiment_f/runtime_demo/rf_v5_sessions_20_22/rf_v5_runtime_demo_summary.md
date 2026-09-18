# RF-v5 Runtime Demo Evidence Freeze

Decision: `RF_V5_RUNTIME_DEMO_EVIDENCE_FROZEN`

## Scientific validation

Scientific status remains `RF_V5_VALIDATION_FAIL`; model status remains `CANDIDATE / NOT_ACTIVE`. These runtime sessions do not constitute scientific validation and do not modify the scientific freeze.

## Operational/runtime demonstration

- Session 20 — Normal HTTP: 58 predictions; Normal 46, PortScan 12; 12 MEDIUM alerts.
- Session 21 — controlled HTTP DDoS-like/load profile: 535 predictions; DDoS 453, Normal 82; 453 HIGH alerts.
- Session 22 — bounded PortScan: 1000 predictions; PortScan 1000; 1000 MEDIUM alerts.

Across these scoped operational scenarios, the runtime pipeline produced all three model classes. This does not claim general attack detection, real-world or genuine distributed DDoS validation, scientific PASS, production readiness, promotion, or activation.

## Provenance

Model: `rf-v5-candidate-01`; SHA256 `31d7d50fa79e3400e7d357cab05c780e038bc527b746d0be6ff894828c6b8d17`; selection mode `MANUAL / DEMO SELECTION`.
Extractor image identity: `sha256:b12b3a4a4218968aba2436685a4eb113473e5681de70705409e834e4613a879b`; CICFlowMeter source commit `a26aae27f21d165ff30b4b28e75124a5f9b4b2c4`; 78-feature crosswalk SHA256 `66e517cdcea217f19de4d0a2cd45302ede999388393f539fb8ca4a2c68b74cf4`.

## Session 22 discrepancy

Persisted `monitoring_sessions.target_ip` is `10.10.10.2`; the operator-bounded Nmap command targeted `10.10.20.2`. This configuration/provenance discrepancy is preserved exactly and is not normalized.

## Limitations

Exact generator evidence is not present in the exported database records. Runtime artifact references are preserved through the source export; raw artifacts were not copied into this freeze.
