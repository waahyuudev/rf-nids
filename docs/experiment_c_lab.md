# Experiment C Phase 1 — Controlled Virtual Laboratory

## Purpose and boundary

Experiment C is **flow-level external validation** of the RF-NIDS near-real-time detection
prototype on traffic produced outside CICIDS2017. It remains methodologically separate from
Experiment A (stratified split) and Experiment B (ordered scenario blocks); their metrics must
never be combined.

Phase 1 establishes infrastructure and benign connectivity only. It does not perform attack
testing, install vulnerable applications, weaken a VM, enumerate networks, or calculate model
metrics. It is not production validation or real-world production accuracy.

## Topology and IP plan

```text
                            macOS host (arm64)
                         RF-NIDS + packet capture
                                   |
                      private host-side interface
                                   |
              isolated network: 192.168.56.0/24
                    /                              \
 Ubuntu Server LTS /                                \ Kali Linux
 target 192.168.56.10  <--- benign ICMP/HTTP only ---> attacker 192.168.56.20
                    \                              /
                     +---- no experiment egress --+

 capture -> CICFlowMeter -> feature adapter -> FastAPI -> Random Forest
         -> PostgreSQL -> Streamlit
```

The addresses are the intended plan, not evidence that the VMs currently exist. If the chosen
hypervisor assigns a different host address or private subnet, update
`config/experiment_c.yaml` and this document. The model must not contain hardcoded lab IPs.

## Host and virtualization

The recorded host is macOS 26.0 on `arm64` (Apple Silicon), detected with `uname -m`. Use an
Apple-Silicon-compatible ARM guest configuration:

- UTM is a practical choice for ARM64 Ubuntu and Kali guests and supports shared/private
  virtual networking.
- VMware Fusion for Apple Silicon is suitable if its private/custom network can be observed
  from the host.
- VirtualBox may be considered only after confirming that its current macOS/Apple Silicon
  release supports both required ARM guests and a usable host-only network. Do not assume it.

No hypervisor is installed automatically by this project. Suggested allocation per VM:

| VM | CPU | RAM | Disk |
|---|---:|---:|---:|
| Ubuntu Server LTS target | 2 vCPU | 2 GB | 20 GB |
| Kali attacker | 2 vCPU | 2–4 GB | 20–30 GB |

## Isolation strategy

Give each VM a private/host-only adapter on `192.168.56.0/24`. If installation needs internet,
attach a separate NAT adapter temporarily and use it only for packages. Before any later
scenario work, disconnect or disable NAT and confirm the experiment route uses only the
isolated adapter. Never use bridged networking for experiment traffic.

On Ubuntu assign `192.168.56.10/24`; on Kali assign `192.168.56.20/24`. A default gateway is
not required on the isolated adapter. Inspect the IP address and routes locally on each VM.
Phase 1 does not use network enumeration.

## Benign connectivity validation

After both private addresses are confirmed, the permitted checks are:

```bash
# Kali to Ubuntu
ping -c 4 192.168.56.10

# Ubuntu to Kali
ping -c 4 192.168.56.20
```

An optional temporary service on Ubuntu can validate TCP/HTTP without weakening the VM:

```bash
python3 -m http.server 8080 --bind 192.168.56.10
```

Then request only that explicit address from Kali:

```bash
curl --fail http://192.168.56.10:8080/
```

Stop the server after validation. Ensure it is bound only to the isolated address.

## Capture strategy

The RF-NIDS remains on macOS. Discover interfaces instead of assuming `en0`:

```bash
python3 scripts/list_capture_interfaces.py
# Equivalent existing discovery:
python3 scripts/run_live_capture.py --list-interfaces
```

Names such as `bridge*`, `vmnet*`, `vboxnet*`, `utun*`, or `tap*` are candidates, not proof.
Generate only the benign ping or HTTP request while observing interface counters or a tightly
filtered capture. Record the interface only after traffic between the two lab IPs is visible.
Then reuse the existing pipeline:

```bash
sudo -v
python3 scripts/run_live_capture.py \
  --interface <verified-private-lab-interface> \
  --segment-seconds 15 \
  --max-segments 1 \
  --output-dir data/lab/experiment_c/normal
```

The operator must verify the resulting flows belong to the benign test window and endpoints
before setting `traffic_observed` to true in the Phase 1 report. PCAP and extracted CSV files
under `data/lab/experiment_c/` are ignored by Git.

## Safety restrictions

`config/experiment_c.yaml` is fail-closed: future tooling must accept literal IP addresses
only, require private targets, reject public IPv4 and IPv6, reject loopback unless explicitly
enabled, reject addresses outside the configured subnet, and require an explicit allowlist
entry. The sole current target is `192.168.56.10`. The configuration contains no traffic or
attack commands.

Phase 1 must not run port scans, Nmap, hping3, SYN floods, packet floods, DDoS-like traffic,
network enumeration, or any test against public, office, or Accurate.id infrastructure.

## Ground truth and manifest

`reports/experiment_c/experiment_manifest.json` is a JSON Schema, not a fabricated run. The
runtime model in `src/experiment_c/manifest.py` records experiment ID, scenario, expected
class, start/end time, source/target IP, capture session ID, and status.

The unit of analysis is a **flow**. One future scenario can create many flows, and one command
is not one prediction. Ground truth must be assigned by the controlled scenario time window
plus source/target metadata, independently of model predictions. Allowed class labels are
`Normal`, `DDoS`, and `PortScan`.

## Future scenarios and metrics (design only)

Future Phase 2 may define controlled Normal, DDoS, and PortScan scenarios, but none are
implemented or executed here. Experiment C will eventually report per-class precision,
recall, and F1; macro precision, recall, and F1; a confusion matrix; candidate false-positive
rate on normal traffic; attack detection rate; successful and failed flow counts; and
prediction latency. There is no Experiment C dataset yet, so no such metrics are calculated.

## Phase 1 report, pass gate, and limitations

`reports/metrics/experiment_c_lab_setup.json` contains only verified host facts and marks all
unverified infrastructure checks false. Change a field to true only with direct operator
evidence. Phase 1 passes only after the isolated network, both VMs and private IPs, bidirectional
reachability, benign HTTP request, host capture interface, and RF-NIDS benign traffic
observation are all verified while `attack_testing_performed` remains false.

Current limitation: the repository can prepare and validate configuration, but cannot prove
that external VMs or a hypervisor exist. Therefore the current gate is:

```text
EXPERIMENT C LAB SETUP: INCOMPLETE
```
