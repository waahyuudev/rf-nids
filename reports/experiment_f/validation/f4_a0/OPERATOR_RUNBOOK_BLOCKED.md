# Experiment F4-A0 validation operator runbook — BLOCKED

Decision: `F4_A0_VALIDATION_PREREGISTRATION_BLOCKED`.

Do not start capture or traffic. Do not run validation inference. The exact Experiment F validation profiles for Normal and PortScan are not prospectively frozen. The DDoS-like validation profile is frozen, but partial collection is withheld to preserve a coherent nine-session protocol.

The missing amendment must select exact bounded parameters for all Normal validation repetitions and all PortScan validation repetitions. It must do so before any validation traffic or prediction inspection. Existing Experiment E commands are evidence of multiple approved methods, not authorization to select one silently for Experiment F.

After an amendment is approved, rerun F4-A0 to generate create-new, allowlisted session commands for exactly:

- `F-A1-NORMAL-V-01` through `F-A1-NORMAL-V-03`
- `F-A1-DDOSLIKE-V-01` through `F-A1-DDOSLIKE-V-03`
- `F-A1-PORTSCAN-V-01` through `F-A1-PORTSCAN-V-03`

Every future command must fix the target to `10.10.20.2` (HTTP `10.10.20.2:8080` where applicable), capture only on `ubuntu-nids:enp0s3`, reject arbitrary target arguments, and create new evidence without overwrite.

Exact first operator command: **NONE — blocked before execution.**
