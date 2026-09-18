# A4 shortest operator procedure

Use empty dedicated roots. Run one session at a time; do not overlap capture windows or retry an ID.

## 1. Deploy once from the Mac

```bash
scp -r scripts/experiment_f_normal_remediation ubuntu-nids:~/
scp -r scripts/experiment_f_normal_remediation ubuntu-traffic:~/
ssh ubuntu-nids 'chmod 0755 "$HOME"/experiment_f_normal_remediation/*.sh && "$HOME"/experiment_f_normal_remediation/test_operator_scripts.sh && sudo install -d -o "$USER" -g "$(id -gn)" -m 0750 /var/tmp/rf-nids-f-normal-a2-observer'
ssh ubuntu-traffic 'chmod 0755 "$HOME"/experiment_f_normal_remediation/*.sh && "$HOME"/experiment_f_normal_remediation/test_operator_scripts.sh && sudo install -d -o "$USER" -g "$(id -gn)" -m 0750 /var/tmp/rf-nids-f-normal-a2-generator'
```

Before proceeding, compare the deployed hashes with `f0_normal_remediation_amendment_a4_SHA256SUMS`.

## 2. Collect each session

For each ID below, start the observer command first, wait for `capturing on enp0s3`, run the generator command, then stop the observer with Ctrl-C immediately after generation ends.

| Session | On ubuntu-nids | On ubuntu-traffic |
|---|---|---|
| `F-A1-NORMAL-A2-01` | `cd ~/experiment_f_normal_remediation && ./capture_session.sh F-A1-NORMAL-A2-01 /var/tmp/rf-nids-f-normal-a2-observer` | `cd ~/experiment_f_normal_remediation && ./generate_normal.sh F-A1-NORMAL-A2-01 /var/tmp/rf-nids-f-normal-a2-generator` |
| `F-A1-NORMAL-A2-02` | `cd ~/experiment_f_normal_remediation && ./capture_session.sh F-A1-NORMAL-A2-02 /var/tmp/rf-nids-f-normal-a2-observer` | `cd ~/experiment_f_normal_remediation && ./generate_normal.sh F-A1-NORMAL-A2-02 /var/tmp/rf-nids-f-normal-a2-generator` |
| `F-A1-NORMAL-A2-03` | `cd ~/experiment_f_normal_remediation && ./capture_session.sh F-A1-NORMAL-A2-03 /var/tmp/rf-nids-f-normal-a2-observer` | `cd ~/experiment_f_normal_remediation && ./generate_normal.sh F-A1-NORMAL-A2-03 /var/tmp/rf-nids-f-normal-a2-generator` |

Stop after collection. Do not extract, train, or run validation inference under this authorization.
