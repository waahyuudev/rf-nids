# Experiment E — E7 unseen runtime validation procedure

Status: preregistered, not executed. This procedure creates two new evidence sessions only: `E7-N-R1` / `expe-e7-normal-r1` and `E7-P-R1` / `expe-e7-portscan-r1`. Never substitute an earlier Experiment E session, `N-F1`, or `P-F1`.

## 1. Capture each session on ubuntu-nids

Run one block per session on `ubuntu-nids`. Do not use `-i any`. Record the UTC timestamps, terminal output, PID, tcpdump summary, SHA-256, and offline packet count in the matching new session manifest.

```bash
mkdir -p /tmp/experiment-e-e7
tcpdump -i enp0s3 -nn -s 0 -U -w /tmp/experiment-e-e7/expe-e7-normal-r1.pcap 'host 10.10.20.2' &
CAP_PID=$!
sleep 3
# Run the E7-N-R1 traffic command below on ubuntu-traffic.
kill -INT "$CAP_PID"
wait "$CAP_PID"
sha256sum /tmp/experiment-e-e7/expe-e7-normal-r1.pcap
tcpdump -nn -r /tmp/experiment-e-e7/expe-e7-normal-r1.pcap 2>/dev/null | wc -l
```

For `E7-P-R1`, use the identical block with `expe-e7-portscan-r1.pcap`, then run the PortScan command below. Do not combine the two scenarios in one PCAP.

## 2. Generate preregistered traffic on ubuntu-traffic

E7-N-R1 — exactly twelve sequential HTTP GET requests. The final zero delay is intentional and preserves the fixed twelve-request pattern.

```bash
for delay in 0.2 0.5 0.3 0.7 0.4 0.6 0.2 0.8 0.3 0.5 0.4 0; do
  curl --http1.1 --max-time 5 -sS -o /dev/null -A 'Experiment-E7-N-R1/1.0' http://10.10.20.2:8080/
  sleep "$delay"
done
```

E7-P-R1 — only the isolated target is allowed. This is a new 600-port range (`3001-3600`), unlike every E2/E6 PortScan range/pattern.

```bash
sudo nmap -n -Pn -sS -T4 --max-retries 1 --min-rate 100 -p 3001-3600 10.10.20.2
```

## 3. Return immutable capture evidence to this workspace

From the workspace host, after recording the remote hashes, transfer each PCAP using the configured SSH alias for the NIDS VM. Then verify the local hash equals the recorded remote hash before extraction.

```bash
mkdir -p data/lab/experiment_e/runtime_validation/pcap/normal data/lab/experiment_e/runtime_validation/pcap/portscan
scp ubuntu-nids:/tmp/experiment-e-e7/expe-e7-normal-r1.pcap data/lab/experiment_e/runtime_validation/pcap/normal/
scp ubuntu-nids:/tmp/experiment-e-e7/expe-e7-portscan-r1.pcap data/lab/experiment_e/runtime_validation/pcap/portscan/
sha256sum data/lab/experiment_e/runtime_validation/pcap/normal/expe-e7-normal-r1.pcap
sha256sum data/lab/experiment_e/runtime_validation/pcap/portscan/expe-e7-portscan-r1.pcap
```

Also return the tcpdump start/stop transcript, packet-count output, Nmap output, and the two session manifests to `data/lab/experiment_e/runtime_validation/manifests/`. Do not return, inspect, or reference final-test data.

## 4. Approved extraction and fixed inference contract

Before extraction, confirm the approved E3-A1 replacement image identity:

```bash
docker image inspect rf-nids-cicflowmeter-v3:a26aae27 --format '{{.Id}}'
```

It must equal `sha256:b12b3a4a4218968aba2436685a4eb113473e5681de70705409e834e4613a879b`. Extract each new PCAP with that image, no network, and a create-new output directory:

```bash
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only \
  --tmpfs /work:rw,noexec,nosuid,size=64m,uid=10001,gid=10001 \
  --mount type=bind,src="$PWD/data/lab/experiment_e/runtime_validation/pcap/normal",dst=/input,readonly \
  --mount type=bind,src="$PWD/data/lab/experiment_e/runtime_validation/flows/normal",dst=/output \
  rf-nids-cicflowmeter-v3:a26aae27 /input/expe-e7-normal-r1.pcap /output
```

Repeat for PortScan with the corresponding `pcap/portscan` and `flows/portscan` directories. Verify exactly 84 raw columns, then adapt only through `CICFlowMeterV3ModelAdapter` to the pinned ordered 78 features. Run `predict` and `predict_proba` on the identical adapted rows for frozen RF-v2 and inactive RF-v3; do not fit, tune, resample, modify thresholds, or promote either model.

## 5. Required E7 outputs after execution

Create new files only: `reports/experiment_e/runtime_validation/e7_runtime_validation.json`, `reports/experiment_e/analysis/e7_rf_v2_vs_rf_v3_comparison.json`, and session/capture/extraction manifests under `data/lab/experiment_e/runtime_validation/manifests/`. Report per-session flow count, predicted distribution, correct/incorrect counts, Normal/PortScan recall, PortScan false negatives, Normal-to-PortScan false positives, class-probability summaries, and RF-v2/RF-v3 deltas. DDoS recall is explicitly out of scope.

`N-F1`, `P-F1`, and Experiment D final-test remain sealed and unread.
