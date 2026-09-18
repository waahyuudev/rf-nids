# F2-A1 Collection Evidence — F-A1-DDOSLIKE-A-01

Decision: `F2_A1_COLLECTION_EVIDENCE_FAIL`

The immutable pre-execution manifest was verified: its SHA256 is `05e7038204fcc0e52d6f7b2d772a0cef9ed87f8f721388fc8b0f1cbb8ff82749`.

The required PCAP is absent from `data/lab/experiment_f/adaptation/pcap/ddoslike/f-a1-ddoslike-a-01.pcap`. All four required Locust CSV evidence copies are also absent from `reports/experiment_f/collection/F-A1-DDOSLIKE-A-01/locust/`. Their hashes therefore cannot be confirmed, and the failures/exceptions files cannot be inspected. The reported final-stat failure count of zero is retained as an operator observation, not verified evidence.

The record preserves the 155 terminal-summary requests and 153 final-stats-CSV requests as separate, unreconciled observations. Workload provenance, F-ADAPTATION separation, DDoS class, and the controlled HTTP DDoS-like/load scope are recorded in `collection_evidence.json` and `lineage.json`.

`eligible_for_validation` and `eligible_for_final` are both `false`; training eligibility remains `PENDING_EXTRACTION_AND_DATA_GATES`.
