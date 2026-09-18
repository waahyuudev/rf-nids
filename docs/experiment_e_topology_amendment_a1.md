# Experiment E Topology Amendment A1

Status: APPROVED

Scope: documentation/configuration amendment only.

Experiment E traffic captured before amendment: NO

## Preregistered topology preserved

- Network: `172.30.50.0/24`
- Generator: `172.30.50.20`
- Target: `172.30.50.10:8080`
- Observer: `experiment-e-observer`, interface `eth0`

The original E1 preregistration remains preserved in
`data/lab/experiment_e/manifests/session_preregistration.json`.

## Amended topology for future live verification

- Architecture: routed 3-VM design
- Source segment: `10.10.10.0/24`
- Ubuntu NIDS: between source and target segments
- Target segment: `10.10.20.0/24`
- Expected generator: `10.10.10.2`, pending live verification
- Expected NIDS source-side address: `10.10.10.1`, documented established topology
- Expected NIDS target-side address: `10.10.20.1`, pending live verification
- Expected Ubuntu target: `10.10.20.2`, documented established topology pending live verification
- Expected capture interface: `enp0s3`, pending empirical verification
- HTTP service port: pending live verification

Pending values must not be treated as verified facts until a later explicitly
authorized live E2 preflight.

## Actions not authorized by A1

- Traffic capture
- CICFlowMeter extraction
- Inference
- Retraining
- Collection of `expe-normal-n-f1`
- Collection of `expe-portscan-p-f1`
- Experiment D modification
- RF-v2 modification
- 78-feature contract modification

## Stop state

No Experiment E traffic was captured before this amendment. Live preflight and
collection remain blocked until explicitly authorized after A1 review.
