# E13 Controlled DDoS-like Runtime Validation — Preregistration

Gate: **PASS — preregistration only**. E13 defines one bounded Normal control and two bounded controlled multi-source DDoS-like HTTP profiles. All traffic is restricted to `10.10.20.2:8080` across the two private lab networks and capture is restricted to `ubuntu-nids:enp0s3`.

E13-D1-R1 is capped at 400 requests / 8 concurrent requests; E13-D2-R1 is capped at 800 requests / 32 concurrent requests. Both use at most four logical source identities on one VM, finite 10-second request timeouts, and a 300-second maximum duration. They are not real distributed DDoS attacks.

Every later session must preserve the PCAP, raw 84-column CSV, exact ordered 78-feature matrix, exports, provenance, and SHA256SUMS before cleanup. Frozen RF-v2 and RF-v3 will be compared on the same vectors. Decision rules and normalized distribution diagnostics against frozen E4 DDoS and E10 Session 11 are specified before observation.

No traffic, monitoring, database write, model modification, threshold change, promotion, or E1–E12 change occurred. The next gate is separate operator authorization plus preflight verification.
