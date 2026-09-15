# F1 Operator Checklist — Preflight Only

Status remains **PENDING_OPERATOR_VALIDATION**. Do not run traffic generators, scanners, load tests, training, or model changes.

1. Inventory the six VMs. On each generator record hostname, `/etc/machine-id` (or VM UUID), experiment-NIC MAC, experiment IP, and `ip route`. Confirm all four identities and MACs are distinct.
2. Before assigning `.11`–`.14`, check the VM inventory and local lab address allocation for conflicts. Historical logical aliases do not clear these addresses.
3. On `ubuntu-nids`, verify `10.10.10.1`, `10.10.20.1`, forwarding state, routes, and the physical mapping of `enp0s3` to the target-side experiment network. Record link state.
4. On each generator, verify only the route to `10.10.20.0/24` through `10.10.10.1`. Use a bounded, low-count reachability check only if required.
5. On `ubuntu-target`, verify `10.10.20.2`, the return route for `10.10.10.0/24` through `10.10.20.1`, ownership/control, and the HTTP service at port 8080. At most one basic benign HTTP request per generator is permitted for connectivity; this is not F2 collection.
6. If a tiny benign connectivity check is performed, verify it is visible once on `ubuntu-nids:enp0s3`; do not use `any`, do not start a scientific capture session, and do not preserve it as F2 evidence.
7. Record Docker/API health only where needed for the locked extractor. Verify CICFlowMeter V3 identity, crosswalk SHA-256, RF-v2/RF-v3 hashes, metadata hash, 78-feature count/order SHA-256.
8. Attach command outputs/screenshots/logs to a new operator evidence addendum. Any source-identity conflict, shared VM identity, route/capture failure, checksum mismatch, or unowned target is `INVALID`/`ABORTED`; stop and do not authorize F2.
