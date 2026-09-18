# Experiment F Operator Plan

## F0 — complete

Design/preregistration only. Preserve all frozen inputs; do not generate traffic, train, or create RF-v4.

## Phases and stop gates

| Phase | Input | Action | Output | Pass gate | Stop condition |
|---|---|---|---|---|---|
| F1 | F0 manifests | Verify isolated topology, independent VMs, routes, ownership, capture visibility; no workload | preflight evidence | all identities/routes/interface checks pass | any public/corporate path, shared generator, route/capture failure |
| F2 | approved F1 | bounded collection only under separate operator authority | PCAP/logs/label manifests | complete safe windows | safety/target/generator/routing deviation |
| F3 | F2 artifacts | locked extraction and 84→78 validation | matrices/provenance | hashes/schema/row counts pass | extractor/checksum/matrix failure |
| F4 | F3 datasets | construct adaptation only; leakage audit | candidate dataset/lineage | session/capture separation | any duplicate/leak/final inclusion |
| F5 | F4 + approval | train initial frozen-settings candidate | candidate + metadata | preregistered reproducibility | unauthorized tuning/failure |
| F6 | frozen candidate | validation on identical flows vs RF-v2/v3 | validation report | all validation gates | mandatory class gate failure |
| F7 | independent sessions | unseen runtime validation | runtime evidence | replication gates | missing/invalid evidence |
| F8 | sealed final | freeze then evaluate once | final evidence | all final gates | any prior final access/leak |
| F9 | all results | comparison/scientific decision | decision record | evidence complete | unresolved mandatory gate |
| F10 | F9 positive decision | separate promotion consideration | authorization/decline | every required gate passed | otherwise no promotion |

## Protocol deviations

`ABORTED` stops on safety, target, routing, or generator failure. `INVALID` excludes evidence for checksum, extraction, row-count, source identity, empty/partial capture, leakage, or label failure. `PASS_WITH_DOCUMENTED_LIMITATION` is limited to non-label-affecting issues and cannot waive integrity, split, or ground-truth requirements. No silent correction is permitted.

Evidence preservation and all quantitative gates are binding in the adjacent F0 JSON artifacts.
