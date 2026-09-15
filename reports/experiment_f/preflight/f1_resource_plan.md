# F1 Resource Plan — Apple Silicon Host (16 GB RAM)

This is a lightweight headless topology plan. It intentionally leaves substantial host RAM for macOS, the hypervisor, and capture tooling.

| VM | vCPU | RAM | Disk | NICs | Notes |
|---|---:|---:|---:|---:|---|
| ubuntu-traffic-1..4 | 1 each | 768 MB each | 8 GB each | 2 | Headless; experiment NIC plus optional separate management NIC. |
| ubuntu-nids | 2 | 3 GB | 24 GB | 3 | Source experiment NIC, target experiment NIC (`enp0s3` capture), optional management NIC. |
| ubuntu-target | 1 | 1.5 GB | 16 GB | 2 | Target experiment NIC plus optional separate management NIC. |

Provisioned guest RAM is 7.5 GB and 7 vCPU total. Do not use a management interface for scientific traffic or capture. If a hypervisor uses different interface names, resolve and document which target-side NIC is `enp0s3` before F2; changing F0's capture interface is not allowed.
