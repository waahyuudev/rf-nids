# Experiment F Amendment A3 validation collection runbook

Decision: `F0_AMENDMENT_A3_ACCEPTED`.

This runbook prepares collection only. It does not authorize extraction, inference, prediction inspection, retraining, activation, or promotion. Run one session at a time and do not overlap capture windows.

## Deployment

Copy `scripts/experiment_f_validation/` unchanged to both `ubuntu-nids` and `ubuntu-traffic`. On each VM, verify the copied file hashes against `f0_amendment_a3_SHA256SUMS` before use. Use an empty, dedicated evidence root on each VM; the scripts refuse to overwrite an existing session directory.

Suggested roots:

- Observer: `/var/tmp/rf-nids-f-validation-observer`
- Generator: `/var/tmp/rf-nids-f-validation-generator`

The roots may differ, but they must be dedicated to A3 validation evidence. A session directory must not already exist.

## Per-session workflow

1. Confirm both VMs are isolated and no other validation capture or intentionally generated background workload is running.
2. On `ubuntu-nids`, start the allowlisted capture command for the session. Wait until tcpdump reports that capture has started.
3. On `ubuntu-traffic`, run the matching fixed-profile generator command.
4. When generation finishes, stop tcpdump with Ctrl-C. Preserve both session directories and their failure evidence even if either command fails.
5. Do not retry under the same session ID. A failed registered session requires a separately documented prospective disposition.
6. Verify the capture and generator windows do not overlap any other validation session before proceeding to the next listed session.

## Exact commands

Set up the create-new roots once on the appropriate VM:

```bash
sudo install -d -m 0750 /var/tmp/rf-nids-f-validation-observer
sudo chown "$USER" /var/tmp/rf-nids-f-validation-observer
```

```bash
sudo install -d -m 0750 /var/tmp/rf-nids-f-validation-generator
sudo chown "$USER" /var/tmp/rf-nids-f-validation-generator
```

For each row below, start the observer command first, then run the generator command in the other VM, then stop the observer with Ctrl-C.

| Order | Session | Observer (`ubuntu-nids`) | Generator (`ubuntu-traffic`) |
|---:|---|---|---|
| 1 | F-A1-NORMAL-V-01 | `./capture_session.sh F-A1-NORMAL-V-01 /var/tmp/rf-nids-f-validation-observer` | `./generate_normal.sh F-A1-NORMAL-V-01 /var/tmp/rf-nids-f-validation-generator` |
| 2 | F-A1-NORMAL-V-02 | `./capture_session.sh F-A1-NORMAL-V-02 /var/tmp/rf-nids-f-validation-observer` | `./generate_normal.sh F-A1-NORMAL-V-02 /var/tmp/rf-nids-f-validation-generator` |
| 3 | F-A1-NORMAL-V-03 | `./capture_session.sh F-A1-NORMAL-V-03 /var/tmp/rf-nids-f-validation-observer` | `./generate_normal.sh F-A1-NORMAL-V-03 /var/tmp/rf-nids-f-validation-generator` |
| 4 | F-A1-DDOSLIKE-V-01 | `./capture_session.sh F-A1-DDOSLIKE-V-01 /var/tmp/rf-nids-f-validation-observer` | `./generate_ddoslike.sh F-A1-DDOSLIKE-V-01 /var/tmp/rf-nids-f-validation-generator` |
| 5 | F-A1-DDOSLIKE-V-02 | `./capture_session.sh F-A1-DDOSLIKE-V-02 /var/tmp/rf-nids-f-validation-observer` | `./generate_ddoslike.sh F-A1-DDOSLIKE-V-02 /var/tmp/rf-nids-f-validation-generator` |
| 6 | F-A1-DDOSLIKE-V-03 | `./capture_session.sh F-A1-DDOSLIKE-V-03 /var/tmp/rf-nids-f-validation-observer` | `./generate_ddoslike.sh F-A1-DDOSLIKE-V-03 /var/tmp/rf-nids-f-validation-generator` |
| 7 | F-A1-PORTSCAN-V-01 | `./capture_session.sh F-A1-PORTSCAN-V-01 /var/tmp/rf-nids-f-validation-observer` | `./generate_portscan.sh F-A1-PORTSCAN-V-01 /var/tmp/rf-nids-f-validation-generator` |
| 8 | F-A1-PORTSCAN-V-02 | `./capture_session.sh F-A1-PORTSCAN-V-02 /var/tmp/rf-nids-f-validation-observer` | `./generate_portscan.sh F-A1-PORTSCAN-V-02 /var/tmp/rf-nids-f-validation-generator` |
| 9 | F-A1-PORTSCAN-V-03 | `./capture_session.sh F-A1-PORTSCAN-V-03 /var/tmp/rf-nids-f-validation-observer` | `./generate_portscan.sh F-A1-PORTSCAN-V-03 /var/tmp/rf-nids-f-validation-generator` |

Exact first collection command, on `ubuntu-nids` after deployment and hash verification:

```bash
./capture_session.sh F-A1-NORMAL-V-01 /var/tmp/rf-nids-f-validation-observer
```

The exact first traffic-generation command, run only after that capture is visibly active, is:

```bash
./generate_normal.sh F-A1-NORMAL-V-01 /var/tmp/rf-nids-f-validation-generator
```

## Stop conditions

Abort and preserve evidence for target or route mismatch, missing `enp0s3`, unavailable required tool or HTTP service, out-of-scope traffic, any existing session output, or an operator safety stop. Never delete and silently repeat a failed registered session.

Stop after collection. Do not extract flows or run any model.
