# Experiment E RF-v3 demo-only runtime override

This is a temporary thesis demonstration only. It does not alter Experiment E's E8 decision (`MORE_VALIDATION_REQUIRED`), activate RF-v3 scientifically, execute E9, alter thresholds, or modify any model/evidence artifact.

## Safety design

Only `RF_NIDS_DEMO_MODEL=rf-v3.0-candidate` is accepted. It forcibly resolves the fixed candidate artifact and metadata paths; arbitrary names and paths are rejected. Startup verifies the candidate and metadata hashes, `CANDIDATE / NOT_ACTIVE` status, 78 ordered features, and fitted `n_features_in_ == 78` before inference. Without this environment variable, the original RF-v2 environment/path resolution is unchanged.

The backend registers RF-v3 only as an inactive database provenance record, while monitoring sessions created in demo mode point to that record. Thus persisted predictions honestly show `rf-v3.0-candidate`; RF-v2 remains the database/scientific active model. Alert rules are unchanged: Normal creates no alert, PortScan MEDIUM, DDoS HIGH.

## Enable and start

On the RF-NIDS host, export the same variable in the shell used for both backend and Streamlit:

```bash
export RF_NIDS_DEMO_MODEL=rf-v3.0-candidate
docker compose up -d postgres
docker compose run --rm migration
docker compose up -d api
streamlit run dashboard/app.py
```

Confirm backend loading after administrator login: the dashboard warning must state `DEMO MODEL: rf-v3.0-candidate`, `CANDIDATE / NOT ACTIVE`, and `Not scientifically promoted`. In Predictions, each new row's Model must be `rf-v3.0-candidate`. The Models history must still show RF-v2 as Active and RF-v3 as inactive.

## Run the manual isolated-lab demonstration

On the dashboard Monitoring page, start monitoring with target `10.10.20.2` and interface `enp0s3` on `ubuntu-nids`. Do not use `any`.

From `ubuntu-traffic`, manually generate the demonstration traffic; no application button generates attacks:

```bash
sudo nmap -n -Pn -sS -T4 --max-retries 1 --min-rate 100 -p 3001-3600 10.10.20.2
```

Wait for the monitoring window to extract and classify flows. Open Predictions to confirm `PortScan` rows with model `rf-v3.0-candidate`; open Alerts to confirm the resulting PortScan alerts have severity `MEDIUM`. Stop monitoring from the Monitoring page when complete.

## Disable and verify default restoration

Stop the demo processes, unset the variable, and restart the same services:

```bash
docker compose down
unset RF_NIDS_DEMO_MODEL
docker compose up -d postgres api
streamlit run dashboard/app.py
```

The demo warning must be absent and newly created inference/monitoring sessions must again resolve the configured RF-v2 default. Historical demo predictions retain their RF-v3 provenance; they are not relabeled.
