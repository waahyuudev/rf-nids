# Experiment D Phase D1 Tooling

D1 adds an isolated configuration, Experiment D package, empty directory skeleton, guarded command entrypoints, documentation, and tests. It creates no capture, flow, model, prediction, or evaluation data.

The architecture centralizes paths in `src/experiment_d/paths.py`, validates the protocol in `config.py` and `protocol.py`, builds portable manifests in `manifest.py`, enforces capture/session/content separation in `split.py`, and protects frozen paths in `integrity.py`.

The extraction wrapper is create-new and constrained to role/class directories. The sealing command verifies every final-test file before creating a sealed manifest. Training, evaluation, and comparison entrypoints accept future arguments but terminate unless run as D1 dry-run validation; none imports or calls model fitting or inference.

`verify_experiment_d_frozen_baseline.py` checks the audited RF-v1, canonical Experiment C captures and flows, final Experiment C evidence, crosswalk, and pinned extractor provenance. Its sole output is `reports/experiment_d/audit/frozen_baseline_manifest.json` and it refuses overwrite.

Readiness for D2 requires the full test suite, successful baseline verification, successful dry-run boundaries, a clean `git diff --check`, and unchanged before/after scientific hashes. D2 must be separately authorized before adaptation traffic is captured.
