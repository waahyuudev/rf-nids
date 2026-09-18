# Experiment F3-A1 dataset assembly

Decision: `F3_A1_DATASET_ASSEMBLY_PASS`.

Training-input readiness: `F3_A2_RF_V4_TRAINING_READY`. No model training or inference was performed.

The immutable candidate contains 6,698 rows and 78 ordered model features plus the separate `ground_truth_class` label: Normal 94, DDoS 4,023, and PortScan 2,581. It consists of the unchanged 5,756-row Experiment E candidate followed by all 942 A2-authorized F-ADAPTATION rows (A-01 311, A-02 311, A-03 320). The new DDoS contribution is limited to the controlled HTTP DDoS-like/load profile and is not genuine distributed-DDoS evidence.

NaN cells: 336. Inf cells: 0. Duplicate feature-vector rows beyond their first occurrence: 1987. Duplicates were retained. No cap, deduplication, resampling, reconstruction, train/test split, validation/final inspection, or model operation occurred.

Dataset SHA256: `a65c812494917b2e6d18153b784fd0505b84229f86b6a6916c59fa1187bd778d`. Lineage SHA256: `1ee2fdad6a9cb4321f6a85beb003e2eb2596518ddd9b54a7a9f151b1c65f4283`. Freeze-record SHA256: `1e89b78779c15d2c9f9cd21ea89fd39c88275a888fd28fd7d08b8d62d5cf4142`. Audit SHA256: `6dc316a4f27a39a4db81d3f0e787467236b2b4af42da87cacbb0524838464ee4`.
