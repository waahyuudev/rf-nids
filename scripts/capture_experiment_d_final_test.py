#!/usr/bin/env python3
"""Capture the nine preregistered Experiment D final-test lab sessions (no inference)."""

from __future__ import annotations

import base64
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from src.common.config import PROJECT_ROOT
from src.experiment_d.d5 import canonical_identity
from src.experiment_d.integrity import require_create_new, sha256_file


ROOT = PROJECT_ROOT
DATA = ROOT / "data/lab/experiment_d/final_test"
PREREG = DATA / "manifests/session_preregistration.json"
MANIFEST = DATA / "manifests/capture_manifest.json"
SOURCE, TARGET, OBSERVER = "experiment-d-source", "experiment-d-target", "experiment-d-observer"


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {args}: {result.stderr[-2000:]}")
    return result


def docker_exec(container: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run("docker", "exec", container, *args, check=check)


def traffic(session_id: str) -> list[str]:
    commands = {
        "expd-final-normal-session-01": ["sh", "-lc", "for i in 1 2 3 4 5; do curl -fsS -o /dev/null http://172.30.50.10:8080/; sleep 0.7; done"],
        "expd-final-normal-session-02": ["sh", "-lc", "curl -fsS -o /dev/null http://172.30.50.10:8080/; sleep 0.4; curl -fsS -o /dev/null http://172.30.50.10:8080/etc/os-release; sleep 1; curl -fsS -o /dev/null http://172.30.50.10:8080/proc/version"],
        "expd-final-normal-session-03": ["sh", "-lc", "for i in 1 2 3; do curl -fsS -o /dev/null http://172.30.50.10:8080/ & curl -fsS -o /dev/null http://172.30.50.10:8080/ & wait; sleep 1; done"],
        "expd-final-portscan-session-01": ["nmap", "-n", "-Pn", "-sT", "-T3", "-p", "1-200", "172.30.50.10"],
        "expd-final-portscan-session-02": ["nmap", "-n", "-Pn", "-sT", "-T4", "-p", "300-520", "172.30.50.10"],
        "expd-final-portscan-session-03": ["nmap", "-n", "-Pn", "-sT", "-T2", "-p", "21-25,53,80,110,143,443,445,3306,5432,6379,8080,8443", "172.30.50.10"],
        "expd-final-ddos-session-01": ["ab", "-q", "-n", "600", "-c", "4", "http://172.30.50.10:8080/"],
        "expd-final-ddos-session-02": ["ab", "-q", "-n", "1200", "-c", "8", "http://172.30.50.10:8080/etc/os-release"],
        "expd-final-ddos-session-03": ["ab", "-q", "-t", "5", "-c", "12", "http://172.30.50.10:8080/"],
        "expd-final-normal-session-04": ["sh", "-lc", "for i in 1 2 3 4 5 6; do curl -fsS -o /dev/null http://172.30.50.10:8080/; sleep 0.6; done"],
    }
    return commands[session_id]


def capture_one(spec: dict) -> dict:
    class_dir = {"Normal": "normal", "PortScan": "portscan", "DDoS": "ddos"}[spec["class"]]
    short = spec["session_id"].removeprefix("expd-final-").replace("-session-", "-s")
    path = DATA / "pcap" / class_dir / f"{short}.pcap"
    require_create_new(path)
    remote = f"/tmp/{short}.pcap"
    log = f"/tmp/{short}.tcpdump.log"
    pid = f"/tmp/{short}.tcpdump.pid"
    done = f"/tmp/{short}.tcpdump.done"
    start = datetime.now(timezone.utc)
    launch = f"tcpdump -i eth0 -n -s 0 -U -w {remote} 'host 172.30.50.20 and host 172.30.50.10' >{log} 2>&1 & echo $! >{pid}"
    docker_exec(OBSERVER, "sh", "-lc", launch)
    time.sleep(1)
    generator = docker_exec(SOURCE, *traffic(spec["session_id"]), check=False)
    time.sleep(1)
    docker_exec(OBSERVER, "sh", "-lc", f"kill -2 $(cat {pid}); while kill -0 $(cat {pid}) 2>/dev/null; do sleep 0.1; done; echo done >{done}")
    end = datetime.now(timezone.utc)
    tcpdump_log = docker_exec(OBSERVER, "cat", log).stdout
    if generator.returncode:
        validity, reason = False, f"generator failed: {generator.stderr[-500:]}"
    else:
        validity, reason = True, None
    parse = docker_exec(OBSERVER, "tcpdump", "-nn", "-r", remote, check=False)
    text = parse.stdout
    if parse.returncode or "172.30.50.20" not in text or "172.30.50.10" not in text:
        validity, reason = False, "PCAP parse/endpoints validation failed"
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = docker_exec(OBSERVER, "base64", remote).stdout
    path.write_bytes(base64.b64decode(encoded))
    if not path.is_file() or path.stat().st_size == 0:
        validity, reason = False, "PCAP empty"
    def stat(pattern: str) -> int | None:
        found = re.search(rf"(\d+) {pattern}", tcpdump_log)
        return int(found.group(1)) if found else None
    captured = stat("packets captured")
    received = stat("packets received by filter")
    dropped = stat("packets dropped by kernel")
    if captured in (None, 0):
        validity, reason = False, "no packets captured"
    return {
        **spec, "experiment_code": "EXPERIMENT_D", "role": "final_test",
        "source_host": SOURCE, "source_ip": "172.30.50.20",
        "target_host": TARGET, "target_ip": "172.30.50.10", "interface": "target-netns:eth0",
        "started_at": start.isoformat(), "ended_at": end.isoformat(),
        "duration_seconds": (end - start).total_seconds(),
        "logical_path": str(path.relative_to(DATA)), "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path), "packet_count": captured,
        "packets_received_by_filter": received, "packets_dropped_by_kernel": dropped,
        "valid": validity, "rejection_reason": reason,
        "generator_exit_code": generator.returncode,
        "notes": "controlled single-source DDoS-like / DoS-like traffic" if spec["class"] == "DDoS" else "fresh class-separated final-test capture",
    }


def main() -> int:
    require_create_new(MANIFEST)
    prereg = json.loads(PREREG.read_text())
    if not prereg.get("model_blind") or len(prereg["sessions"]) != 10:
        raise ValueError("invalid final-test preregistration")
    first, *remaining = prereg["sessions"]
    first_path = DATA / "pcap/normal/normal-s01.pcap"
    if not first_path.is_file():
        raise ValueError("preserved invalid session 01 PCAP is missing")
    invalid_first = {
        **first, "experiment_code": "EXPERIMENT_D", "role": "final_test",
        "source_host": SOURCE, "source_ip": "172.30.50.20", "target_host": TARGET,
        "target_ip": "172.30.50.10", "interface": "target-netns:eth0",
        "started_at": None, "ended_at": None, "duration_seconds": None,
        "logical_path": "pcap/normal/normal-s01.pcap", "size_bytes": first_path.stat().st_size,
        "sha256": sha256_file(first_path), "packet_count": 60,
        "packets_received_by_filter": 60, "packets_dropped_by_kernel": 0,
        "valid": False,
        "rejection_reason": "capture orchestration copy race prevented authoritative start/end metadata preservation",
        "generator_exit_code": 0, "notes": "preserved invalid capture; identity will never be reused",
    }
    results = [invalid_first, *[capture_one(spec) for spec in remaining]]
    payload = {
        "schema": "experiment_d_final_test_capture_manifest", "schema_version": 1,
        "experiment_code": "EXPERIMENT_D", "role": "final_test",
        "isolated_network": {"name": "experiment-d-final-net", "subnet": "172.30.50.0/24", "internal": True},
        "sessions": results,
    }
    payload["scientific_identity"] = canonical_identity(results)
    MANIFEST.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": "CAPTURED", "valid": sum(x["valid"] for x in results), "identity": payload["scientific_identity"]}))
    return 0 if all(x["valid"] for x in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
