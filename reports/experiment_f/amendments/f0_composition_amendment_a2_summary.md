# Experiment F Composition Amendment A2

Decision: `F0_AMENDMENT_A2_ACCEPTED`.

Dataset assembly is prospectively reauthorized as `F3_A1_DATASET_ASSEMBLY_REAUTHORIZED`, but was not performed here.

A2 freezes the exact 5,756-row Experiment E RF-v3 training candidate as the byte/logically unchanged historical baseline, including its existing deterministic caps and lineage. It prospectively authorizes appending every row from only F-A1-DDOSLIKE-A-01, A-02, and A-03: 311, 311, and 320 rows respectively. These 942 rows map to model class `DDoS` only within Amendment A1's controlled HTTP DDoS-like/load profile; they do not establish genuine distributed-DDoS representativeness.

The future independently verified combined expectation is 6,698 rows: Normal 94, DDoS 4,023, and PortScan 2,581. Any source hash, schema, or count mismatch must fail assembly rather than alter this amendment.

Historical rows remain unchanged. Duplicate F feature vectors remain included. Historical caps are not reapplied to the combined dataset, and the new F rows are not capped. Validation, runtime-validation, diagnostics, final data, future sessions, unapproved traffic, and reconstructed uncapped historical pools remain prohibited.

The first RF-v4 candidate must retain the frozen RF-v3 parameters and exact ordered 78-feature contract. No dataset assembly, training, traffic, prediction, inference, or validation/final inspection occurred while creating A2.
