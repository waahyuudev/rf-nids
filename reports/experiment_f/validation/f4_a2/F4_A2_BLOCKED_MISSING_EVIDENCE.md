# F4-A2 missing-evidence gate

Decision: `F4_A2_BLOCKED_MISSING_EVIDENCE`.

The repository has none of the nine required scientific validation PCAPs or their paired observer/generator evidence directories. F4-A2 therefore stopped before CICFlowMeter extraction, adaptation, dataset freezing, or inference.

## Missing scientific sessions

- Normal: `F-A1-NORMAL-V-01-R1`, `F-A1-NORMAL-V-02`, `F-A1-NORMAL-V-03`
- DDoS (controlled HTTP DDoS-like/load profile): `F-A1-DDOSLIKE-V-01`, `F-A1-DDOSLIKE-V-02`, `F-A1-DDOSLIKE-V-03`
- PortScan: `F-A1-PORTSCAN-V-01`, `F-A1-PORTSCAN-V-02`, `F-A1-PORTSCAN-V-03`

For each session, copy the whole observer directory (PCAP, capture timestamps, tcpdump status/log, and PCAP checksum) and the whole generator directory (generator timestamps/status and workload-specific logs). Whole-directory copying avoids silently omitting workload evidence.

The historical `F-A1-NORMAL-V-01` attempt was not found in the repository. If it remains on either VM, copy it separately for preservation only. It must remain `FAILED_PRE_TRAFFIC / EMPTY_CAPTURE` and must never enter the validation dataset.

## Safe copy commands (run on the Mac from the repository root)

These commands fail if a destination session directory already exists and do not delete or overwrite evidence.

```bash
set -euo pipefail
validation_root="$PWD/data/lab/experiment_f/validation/raw"
install -d -m 0750 "$validation_root/observer" "$validation_root/generator" "$validation_root/historical_failed/observer" "$validation_root/historical_failed/generator"

for session_id in \
  F-A1-NORMAL-V-01-R1 F-A1-NORMAL-V-02 F-A1-NORMAL-V-03 \
  F-A1-DDOSLIKE-V-01 F-A1-DDOSLIKE-V-02 F-A1-DDOSLIKE-V-03 \
  F-A1-PORTSCAN-V-01 F-A1-PORTSCAN-V-02 F-A1-PORTSCAN-V-03
do
  test ! -e "$validation_root/observer/$session_id"
  test ! -e "$validation_root/generator/$session_id"
  scp -rp "ubuntu-nids:/var/tmp/rf-nids-f-validation-observer/$session_id" "$validation_root/observer/"
  scp -rp "ubuntu-traffic:/var/tmp/rf-nids-f-validation-generator/$session_id" "$validation_root/generator/"
done
```

Preserve the failed original attempt if its directories exist:

```bash
set -euo pipefail
validation_root="$PWD/data/lab/experiment_f/validation/raw"
test ! -e "$validation_root/historical_failed/observer/F-A1-NORMAL-V-01"
test ! -e "$validation_root/historical_failed/generator/F-A1-NORMAL-V-01"
scp -rp ubuntu-nids:/var/tmp/rf-nids-f-validation-observer/F-A1-NORMAL-V-01 "$validation_root/historical_failed/observer/"
scp -rp ubuntu-traffic:/var/tmp/rf-nids-f-validation-generator/F-A1-NORMAL-V-01 "$validation_root/historical_failed/generator/"
```

If the failed pre-traffic attempt never created a generator directory, preserve the observer directory and any existing failure record; do not fabricate the absent generator evidence.

## Verified frozen inputs

- RF-v2 SHA256: `fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31`
- RF-v3 SHA256: `6b01c7b3923c1a6bd471862d011f8f5b88a31378e51d1dde082bd2e72bedef86`
- RF-v4 SHA256: `d5dccd339a5c67635e760d7d3760e1d006278362c6f70ea06bf20928ccdece13`
- Frozen crosswalk SHA256: `66e517cdcea217f19de4d0a2cd45302ede999388393f539fb8ca4a2c68b74cf4`

No model was loaded for inference and no acceptance gate is evaluable until the nine sessions pass the evidence and data gates.
