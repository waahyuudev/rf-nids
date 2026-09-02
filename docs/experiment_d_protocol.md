# Experiment D Protocol

Experiment D evaluates whether explicitly separated laboratory adaptation data can improve external performance while retaining a genuinely untouched final test. Experiment C remains frozen as evidence of the RF-v1 external generalization gap; none of its captures, flows, predictions, reports, or hashes may be reused as Experiment D data or changed.

## Roles and leakage policy

`adaptation` data may be used for fitting, tuning, preprocessing fit, feature selection, threshold selection, and model selection. `final_test` data may be used only after RF-v2 and all selection decisions are frozen. Reading final-test summaries or statistics during preparation is prohibited.

Every artifact records Experiment D, role, class, capture ID, session ID, hosts, capture interval, and scenario ID. Fields may be null while planning, but dataset preparation requires all of them. Whole captures and sessions are indivisible. Capture IDs, session IDs, and file hashes must be disjoint across roles; random flow-row splitting across roles is forbidden.

## Sealing and identity

Final-test files are hashed and checked against an unsealed manifest. Sealing creates a new manifest and never replaces the source. Later evaluation requires `sealed=true`. Scientific manifest identity hashes content SHA-256, size, logical role, logical Experiment D-relative path, class, capture ID, and session ID. Absolute machine paths never participate.

## Extraction and models

Extraction uses the existing pinned official CICFlowMeter V3 commit and image without changing feature behavior. The Experiment D wrapper accepts only PCAP and output paths inside the selected Experiment D role/class tree, runs without Docker networking, and writes a new role-local report. Experiment C and the global V3 extraction report are prohibited destinations.

RF-v2 is isolated below `models/experiment_d/`; RF-v1 artifacts and active-model metadata remain immutable. Median imputation must remain inside the fitted pipeline. D1 training, final evaluation, and comparison commands are guard-only dry runs and contain no fitting or inference implementation.

RF-v1 and RF-v2 final comparison must use the identical sealed manifest identity and exact evaluation rows. Experiment C metrics cannot substitute for Experiment D final metrics.

## Prohibited actions and limitations

Traffic generation, model fitting, inference, threshold tuning, final-test inspection, application/database/API/UI changes, and Experiment C/RF-v1 mutation are prohibited in D1. CICFlowMeter V3 is a pinned official reconstruction candidate; its exact identity with the historical CICIDS2017 generator remains unproven. Nine adapter fields intentionally reproduce historical dataset artifacts and remain documented by the validated crosswalk.
