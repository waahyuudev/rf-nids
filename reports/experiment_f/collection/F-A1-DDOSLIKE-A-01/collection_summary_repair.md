# A-01 recovered-evidence repair

Decision: `F2_A1_A01_REPAIR_PASS`.

The recovered canonical PCAP and all four Locust CSV artifacts match their specified SHA256 values. `failures.csv` and `exceptions.csv` contain only headers. `stats.csv` has `GET /` and `Aggregated` rows, both with 153 requests and zero failures.

The terminal observation of 155 requests and the machine-readable CSV value of 153 requests are both retained without reconciliation. The path mapping addendum is administrative only and does not alter the scientific capture. No independent execution-log or exact start/end timestamp file was recovered; the persisted stats-history telemetry timestamps are recorded with their interpretation limit.

The session remains F-ADAPTATION only, ineligible for validation and final use, with training eligibility `PENDING_EXTRACTION_AND_DATA_GATES`.
