# Experiment F A3 operator-script repair deployment

Decision: `F4_A0_OPERATOR_SCRIPT_REPAIR_PASS`.

The original A3 amendment and checksum manifest remain historical evidence. Deploy the repaired package before starting any validation session.

From the repository workstation:

```bash
ssh ubuntu-nids 'mkdir -p "$HOME/experiment_f_validation"'
scp scripts/experiment_f_validation/common.sh scripts/experiment_f_validation/capture_session.sh scripts/experiment_f_validation/test_operator_scripts.sh ubuntu-nids:experiment_f_validation/
ssh ubuntu-nids 'chmod 0755 "$HOME"/experiment_f_validation/*.sh && "$HOME/experiment_f_validation/test_operator_scripts.sh"'
```

```bash
ssh ubuntu-traffic 'mkdir -p "$HOME/experiment_f_validation"'
scp scripts/experiment_f_validation/common.sh scripts/experiment_f_validation/generate_normal.sh scripts/experiment_f_validation/generate_ddoslike.sh scripts/experiment_f_validation/generate_portscan.sh scripts/experiment_f_validation/locustfile_validation.py scripts/experiment_f_validation/test_operator_scripts.sh ubuntu-traffic:experiment_f_validation/
ssh ubuntu-traffic 'chmod 0755 "$HOME"/experiment_f_validation/*.sh && "$HOME/experiment_f_validation/test_operator_scripts.sh"'
```

Verify on both VMs that repaired `common.sh` has SHA256 `29c41d830f24626e28f27cb842e8d8a32953ed874bef5346a69477dea861de2c`.

Restart the first session by starting capture on `ubuntu-nids`:

```bash
cd "$HOME/experiment_f_validation"
./capture_session.sh F-A1-NORMAL-V-01 /var/tmp/rf-nids-f-validation-observer
```

Only after tcpdump is visibly active, run on `ubuntu-traffic`:

```bash
cd "$HOME/experiment_f_validation"
./generate_normal.sh F-A1-NORMAL-V-01 /var/tmp/rf-nids-f-validation-generator
```

Stop after collection. Do not extract or run inference.
