# Experiment F Amendment A4 — Normal remediation

Decision: `F4_A3_NORMAL_REMEDIATION_COLLECTION_AUTHORIZED`.

This prospective amendment authorizes only three new Normal adaptation captures: `F-A1-NORMAL-A2-01..03`. Each session generates exactly 100 sequential HTTP/1.1 GET requests to `http://10.10.20.2:8080/`, one at a time with a one-second inter-request delay, while `ubuntu-nids` captures `enp0s3` using `host 10.10.20.2 and tcp port 8080`.

All three sessions must pass collection and frozen CICFlowMeter/78-feature gates and yield more than 94 aggregate adapted Normal rows before a separately authorized training step may append them to the frozen RF-v4 training composition. No validation row may enter training.

At most one later model, `rf-v5-candidate-01 / NOT_ACTIVE`, may be trained with the exact RF-v4 parameters and preprocessing. Existing validation gates remain unchanged.
