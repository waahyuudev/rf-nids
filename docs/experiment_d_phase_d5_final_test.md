# Experiment D Phase D5: RF-v2 Freeze and Final-Test Capture

RF-v2 is frozen by `reports/experiment_d/audit/rf_v2_frozen_manifest.json`. The
freeze command hashes the model without deserializing it and refuses overwrite.

Final-test capture remains a physical lab operation. Create at least three fresh,
separately started/stopped sessions per class (Normal, PortScan, and controlled
single-source DDoS-like), with new scenario, capture, and session IDs. Before every
attack-class capture, record that both hosts are owned and isolated, routing is not
bridged/public, the destination is private, and the service/port is intended for
testing. Failed captures are preserved as invalid and replacements receive new IDs.

Only `scripts/run_experiment_d_cicflowmeter_v3.py --role final_test` may extract
accepted captures. Adapter checks are schema/finite-state checks only: exactly 84
raw columns, the unchanged ordered 78-feature mapping, no missing/duplicate required
headers, no imputation, and no prediction. Ground truth comes only from the scenario.

Before sealing, audit Experiment C and adaptation hashes plus capture/session IDs,
verify that no final-test artifact occurs in training inputs, and recheck the frozen
model hash. The final-test manifests and audits must contain no predictions or model
metrics. Any data, label, adapter, preprocessing, or RF-v2 change after sealing
invalidates this experiment revision.

## Executed D5 final-test capture

The verified D5a lab used Docker internal network `experiment-d-final-net`
(`172.30.50.0/24`), source `experiment-d-source` (`172.30.50.20`), target
`experiment-d-target` (`172.30.50.10:8080`), and observer capture interface
`target-netns:eth0`. Both endpoints had only the on-link subnet route and no
default route. All capture filters were limited to the two laboratory addresses.

| Class | Session | Scenario/command | Valid | Packets | Kernel drops | PCAP SHA-256 | Flows |
|---|---|---|---:|---:|---:|---|---:|
| Normal | `expd-final-normal-session-01` | five sequential GETs, 0.7 s idle | no | 60 | 0 | `44d80790a6869a10b4f2e640f90534118df7bf527639bb7932307dce5d18ba23` | — |
| Normal | `expd-final-normal-session-02` | mixed GET/small downloads | yes | 36 | 0 | `f37005e856cc79a20de922b53e8f59da1edc4b2a9e34a2acce95f7608165da40` | 6 |
| Normal | `expd-final-normal-session-03` | three modest concurrent pairs | yes | 72 | 0 | `889088c1bbc5d16995cc5650141214e311bd624f1bbe71aafa194633f1977c81` | 12 |
| Normal | `expd-final-normal-session-04` | replacement: six GETs, 0.6 s idle | yes | 72 | 0 | `c75b8e88f8eaac82680445228859fab339f1c93253e57c70f9bb1605e6cbabf9` | 12 |
| PortScan | `expd-final-portscan-session-01` | `nmap -n -Pn -sT -T3 -p 1-200 172.30.50.10` | yes | 400 | 0 | `5062e0a7c2dbfa31c014a0ac95e67fef0035584326b5e972a62c962a08e7d3d7` | 200 |
| PortScan | `expd-final-portscan-session-02` | `nmap -n -Pn -sT -T4 -p 300-520 172.30.50.10` | yes | 442 | 0 | `bc60c1c6885721c0620a41f60c0274530a6c327bd915e47de4f10ab512f6e71b` | 221 |
| PortScan | `expd-final-portscan-session-03` | selected ports, TCP connect T2 | yes | 34 | 0 | `94ee1b78b24ea0f8e0c0e8225b3d0452537cab9f6b58c2a36fabf243b119162f` | 16 |
| DDoS | `expd-final-ddos-session-01` | controlled single-source `ab -n 600 -c 4` | yes | 7,200 | 0 | `086cf39e90453d01a3b817a81f80223b6bf3894ec15a6164d1da7855a34665a4` | 1,200 |
| DDoS | `expd-final-ddos-session-02` | controlled single-source `ab -n 1200 -c 8` | yes | 14,402 | 0 | `9eba3f66d66b462eda27cb14bbf784fb3ea969dfefa51da2882ef21886c70541` | 2,400 |
| DDoS | `expd-final-ddos-session-03` | controlled single-source `ab -t 5 -c 12` | yes | 75,884 | 0 | `b9c73fce961260cd398ec510d6789c3aaf60d4819356e0732092e8690e6ba2b1` | 11,882 |

Session 01 was preserved as invalid because a capture-copy orchestration race
prevented authoritative start/end metadata from being committed. Its identity was
not reused; session 04 was preregistered and captured as its replacement.

All nine accepted PCAPs were extracted exclusively with the pinned Experiment D
wrapper and CICFlowMeter image digest
`sha256:0227c7280e586d54144b9bb11b2a6b5d4b1c4ba9bc7c44199fa312a6b829caab`.
Every CSV has exactly 84 columns and a nonzero row count. The unchanged adapter
produced exactly 78 ordered features, performed no imputation, and retained
crosswalk SHA-256 `66e517cdcea217f19de4d0a2cd45302ede999388393f539fb8ca4a2c68b74cf4`.

The model-blind dataset contains 30 Normal, 437 PortScan, and 15,482 DDoS flows
(15,949 total). The leakage audit is `PASS`; exact duplicate raw rows are zero.
The sealed final-test identity is
`a60d79e66690dcb146e76a80dee5ff4e550abd298575a92d77be6db447881d18`;
ground-truth identity is
`a5dec5d0197eee4601843f4832d51de1c86b52361e5f42f36fecebc157749e79`.
The blind evaluation preflight returned `DRY_RUN_VALID` and explicitly reported
`inference_performed: false`. D5 is ready for separately authorized D6 evaluation.
