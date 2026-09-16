# F1-A1 Operator Checklist — Three-VM Preflight Only

F1-A1 is **PENDING_OPERATOR_VALIDATION**. No Locust execution, collection, scanning, load testing, training, or RF-v4 work is authorized.

1. Record `ubuntu-traffic` hostname, machine identity, experiment-NIC MAC, `10.10.10.2/24`, and route to `10.10.20.0/24` via `10.10.10.1`.
2. Record `ubuntu-nids` identity, both experiment IPs, link state, IP-forwarding state, routes, and verify that target-side experiment traffic maps exactly to `enp0s3`.
3. Record `ubuntu-target` identity, `10.10.20.2/24`, return route to `10.10.10.0/24` via `10.10.20.1`, ownership/control, and HTTP service at `:8080`.
4. A bounded benign reachability check and at most one basic HTTP request to the owned target may be used only for connectivity. Do not start an F2 capture/session; do not use `any` as capture interface.
5. Verify the locked CICFlowMeter V3/crosswalk identity, 78-feature count/order, and frozen RF-v2/RF-v3 SHA-256 values in the amendment evidence. Record outputs in a new addendum.
6. Stop as INVALID/ABORTED for route/forwarding/return/capture/service/provenance mismatch. Do not authorize F2 without every amended gate passing.
