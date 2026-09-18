# Experiment F Normal V-01 replacement operator addendum

`F-A1-NORMAL-V-01` is preserved as `FAILED_PRE_TRAFFIC / EMPTY_CAPTURE`. Never delete, overwrite, reuse, or count its evidence.

The valid Normal validation set is now:

- `F-A1-NORMAL-V-01-R1`
- `F-A1-NORMAL-V-02`
- `F-A1-NORMAL-V-03`

Deploy the amended scripts from the repository workstation:

```bash
scp scripts/experiment_f_validation/common.sh scripts/experiment_f_validation/capture_session.sh scripts/experiment_f_validation/test_operator_scripts.sh ubuntu-nids:experiment_f_validation/
ssh ubuntu-nids 'chmod 0755 "$HOME"/experiment_f_validation/*.sh && "$HOME/experiment_f_validation/test_operator_scripts.sh"'
```

```bash
scp scripts/experiment_f_validation/common.sh scripts/experiment_f_validation/generate_normal.sh scripts/experiment_f_validation/test_operator_scripts.sh ubuntu-traffic:experiment_f_validation/
ssh ubuntu-traffic 'chmod 0755 "$HOME"/experiment_f_validation/*.sh && "$HOME/experiment_f_validation/test_operator_scripts.sh"'
```

Start the replacement capture on `ubuntu-nids`:

```bash
cd "$HOME/experiment_f_validation"
./capture_session.sh F-A1-NORMAL-V-01-R1 /var/tmp/rf-nids-f-validation-observer
```

Only after capture is visibly active, run on `ubuntu-traffic`:

```bash
cd "$HOME/experiment_f_validation"
./generate_normal.sh F-A1-NORMAL-V-01-R1 /var/tmp/rf-nids-f-validation-generator
```

This remains collection-only authorization. Stop before extraction or inference.
