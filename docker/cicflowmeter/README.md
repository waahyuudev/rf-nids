# RF-NIDS flow extractor container

This image pins `hieulw/cicflowmeter` 0.4.2 on Python 3.12. It is a maintained,
Scapy-based compatible implementation, not the original Java CICFlowMeter used to
produce CICIDS2017. The original relies on Java 8-era jNetPcap and bundled Linux
x86_64 native libraries, which makes a reproducible modern arm64 build difficult.

Scapy uses the distribution's `libpcap` runtime and `tcpdump` binary to compile and
apply its offline packet filter.
This is installed from Debian for the image's native architecture, so the image builds
natively on both Apple Silicon (`linux/arm64`) and Intel Mac (`linux/amd64`). No
`platform: linux/amd64` emulation is imposed.

From the repository root:

```bash
docker compose --profile tools run --rm cicflowmeter \
  /input/sample.pcap /output/sample.csv
```

Only `/input` (read-only) and `/output` are accepted by the entrypoint. The container
exits after offline extraction.
