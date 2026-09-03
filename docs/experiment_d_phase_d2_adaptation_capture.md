# Experiment D Phase D2 — Adaptation Capture

## Result and boundary

D2 acquired new adaptation-only traffic on 2026-09-03. It did not generate or inspect final-test traffic, train a model, run inference, or modify Experiment C, RF-v1, CICFlowMeter V3, or the validated adapter/crosswalk. The accepted dataset contains three valid independent sessions for each of Normal, PortScan, and controlled single-source DDoS-like traffic.

## Isolated lab topology

The run used Docker internal network `experiment-d-d2-internal` (`172.29.0.0/24`) with no external gateway or default route. `experiment-d-source` was fixed at `172.29.0.20`; the owned `experiment-d-target` was fixed at `172.29.0.10` and exposed a Python static HTTP server only on port 8080. Capture ran on `eth0` in the target network namespace. Before capture, ICMP and local HTTP reachability passed and the source route table contained only the internal subnet route.

The tooling image was prepared before isolation. Every recorded scenario then ran solely between these two private lab containers. PCAPs are class-separated and no capture contains adaptation and final-test traffic.

## Protocol and sessions

Each session used a fresh capture container and PCAP. The authoritative timestamps, hashes, sizes, exact commands, quality results, and notes are in `data/lab/experiment_d/adaptation/manifests/capture_manifest.json`.

| Class | Session ID | Capture ID | Scenario | Generator/config | Valid |
|---|---|---|---|---|---|
| Normal | `expd-adapt-normal-session-01` | `expd-adapt-normal-capture-01` | HTTP, API, 64 KiB download, limited ping, idle intervals | curl/ping sequence | yes |
| Normal | `expd-adapt-normal-session-02` | `expd-adapt-normal-capture-02` | repeated pages, API, download, idle intervals | repeated curl sequence | yes |
| Normal | `expd-adapt-normal-session-03` | `expd-adapt-normal-capture-03` | modest concurrent API/download requests and limited ping | curl via `xargs -P 3`/`-P 2` | yes |
| PortScan | `expd-adapt-portscan-session-01` | `expd-adapt-portscan-capture-01` | moderate SYN range | `nmap -n -Pn -sS -T3 -p 1-512 172.29.0.10` | yes |
| PortScan | `expd-adapt-portscan-session-02` | `expd-adapt-portscan-capture-02` | wider/faster SYN range | `nmap -n -Pn -sS -T4 -p 1-1024 172.29.0.10` | yes |
| PortScan | `expd-adapt-portscan-session-03` | `expd-adapt-portscan-capture-03` | slower selected-port SYN profile | `nmap -n -Pn -sS -T2 -p 20-25,53,80,110,139,143,443,445,8080,8443 172.29.0.10` | yes |
| DDoS | `expd-adapt-ddos-session-01` | `expd-adapt-ddos-capture-01` | controlled HTTP, concurrency 8 | `ab -q -n 1200 -c 8 http://172.29.0.10:8080/` | yes |
| DDoS | `expd-adapt-ddos-session-02` | `expd-adapt-ddos-capture-02` | controlled API-like HTTP, concurrency 16 | `ab -q -n 2400 -c 16 http://172.29.0.10:8080/api/status.json` | yes |
| DDoS | `expd-adapt-ddos-session-03` | `expd-adapt-ddos-capture-03` | large-response trial, concurrency 24 | `ab -q -t 8 -c 24 http://172.29.0.10:8080/files/sample-64k.bin` | no |
| DDoS | `expd-adapt-ddos-session-04` | `expd-adapt-ddos-capture-04` | bounded replacement, concurrency 24 | `ab -q -n 3600 -c 24 http://172.29.0.10:8080/` | yes |

The DDoS ground-truth/model label is `DDoS`, but the scientific description remains controlled single-source high-rate DoS-like/DDoS-like traffic; this run is not evidence of distributed sources.

## Failure and replacement

The original DDoS-like session 03 was preserved but rejected because tcpdump reported 183,044 kernel packet drops. It was not extracted or included in usable-flow counts. Session 04 replaced it without overwriting any artifact; tcpdump reported 43,315 captured, 43,315 received, and zero dropped packets. The target remained responsive after both trials.

## Quality, extraction, adaptation, and labeling

All nine valid PCAPs were non-empty, parseable by tcpdump, contained both expected IPs, and matched their declared scenario/class. Each passed through `scripts/run_experiment_d_cicflowmeter_v3.py` with role `adaptation`, the pinned commit `a26aae27f21d165ff30b4b28e75124a5f9b4b2c4`, image digest `sha256:0227c7280e586d54144b9bb11b2a6b5d4b1c4ba9bc7c44199fa312a6b829caab`, and Docker networking disabled. All nine raw CSVs have 84 columns and non-zero rows.

The unchanged adapter `CICFLOWMETER_V3_CICIDS2017_MODEL_ADAPTER` version `1.0.0` produced exactly 78 features in the frozen model order for every file. No imputation was performed during validation. Labels were assigned from the controlled session ground truth, never from predictions.

Actual valid flow counts are:

| Class | Valid PCAPs | Flows |
|---|---:|---:|
| Normal | 3 | 44 |
| PortScan | 3 | 1,554 |
| DDoS | 3 | 14,316 |
| **Total** | **9** | **15,914** |

## Audit and integrity

`dataset_audit.json` records row duplication, content-hash duplication, missing/non-finite values, exact feature order, and actual label distribution. `adaptation_leakage_audit.json` reports no Experiment C hash overlap, no reused capture/session identity, adaptation-only roles, no final-test paths/data, and no cross-role collision. Its recheck of every frozen-baseline entry passed against baseline scientific identity `907ad890f4a7e830cc9ca4d38ee6b99075bab5a06ee6cdda0725db52cc0f7e70`.

The D2 artifact inventory is `reports/experiment_d/audit/d2_artifact_inventory.json`. The capture manifest, labeled-flow manifest, dataset audit, class distribution, leakage audit, and per-file extraction reports are all create-new artifacts.

## Remaining gate before D3

D2 supplies adaptation data only. RF-v2 training must not begin until separately approved. D3 must consume only the valid entries of the adaptation manifests, retain session-level provenance, keep preprocessing inside its fitted pipeline, and continue to leave final-test data untouched.
