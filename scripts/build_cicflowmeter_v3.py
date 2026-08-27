#!/usr/bin/env python3
"""Build and document the isolated pinned official CICFlowMeter V3 image."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTEXT = ROOT / "docker" / "cicflowmeter-v3"
REPORT = ROOT / "reports" / "metrics" / "cicflowmeter_v3_build.json"
IMAGE = "rf-nids-cicflowmeter-v3:a26aae27"
PLATFORM = "linux/amd64"
SOURCE_URL = "https://github.com/ahlashkari/CICFlowMeter"
SOURCE_COMMIT = "a26aae27f21d165ff30b4b28e75124a5f9b4b2c4"
COMMIT_DATE = "2018-04-03T09:30:33-03:00"
SOURCE_SHA256 = "78f13b2d474e5a669a367aef610d597cf86bc338088ffdd72228671bdca364c7"
BUILD_BASE = "eclipse-temurin:8-jdk-jammy@sha256:e0e0243c25c8985bb786948c2e23d267597ad9751c0311f43c113211a25392f5"
RUNTIME_BASE = "eclipse-temurin:8-jre-jammy@sha256:8d8ffe619c1b4aebfa670426ea6b938cccf76faa491ca8483dee520c48b30441"


def run(command: list[str], *, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)


def probe(image: str, command: list[str]) -> dict[str, object]:
    result = run([
        "docker", "run", "--rm", "--platform", PLATFORM,
        "--entrypoint", command[0], image, *command[1:],
    ])
    return {
        "exit_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=IMAGE)
    args = parser.parse_args()
    if REPORT.exists():
        raise SystemExit(f"refusing to overwrite existing report: {REPORT}")

    started = time.monotonic()
    build = run([
        "docker", "build", "--platform", PLATFORM, "--pull",
        "--tag", args.image, str(CONTEXT),
    ])
    image_data: dict[str, object] = {}
    if build.returncode == 0:
        inspected = run(["docker", "image", "inspect", args.image])
        if inspected.returncode == 0:
            image_data = json.loads(inspected.stdout)[0]

    probes: dict[str, dict[str, object]] = {}
    if build.returncode == 0:
        probes = {
            "java": probe(args.image, ["java", "-version"]),
            "toolchain": probe(args.image, ["cat", "/opt/CICFlowMeter/BUILD_TOOLCHAIN.txt"]),
            "source_hashes": probe(args.image, ["cat", "/opt/CICFlowMeter/SOURCE_HASHES.txt"]),
            "jni_linkage": probe(args.image, ["sh", "-c", "ldd /opt/CICFlowMeter/lib/native/libjnetpcap.so"]),
            "libpcap": probe(args.image, ["sh", "-c", "dpkg-query -W -f='${Version}' libpcap-dev"]),
            "cli_class": probe(args.image, ["sh", "-c", "jar tf /opt/CICFlowMeter/lib/CICFlowMeter-3.0.jar | grep '^cic/cs/unb/ca/ifm/CICFlowMeter.class$'"]),
        }

    jni_text = " ".join(str(probes.get("jni_linkage", {}).get(k, "")) for k in ("stdout", "stderr"))
    jni_linked = (
        probes.get("jni_linkage", {}).get("exit_code") == 0
        and "libpcap" in jni_text
        and "not found" not in jni_text
    )
    cli_success = probes.get("cli_class", {}).get("exit_code") == 0
    report = {
        "source_repository": SOURCE_URL,
        "commit": SOURCE_COMMIT,
        "commit_date": COMMIT_DATE,
        "source_archive_sha256": SOURCE_SHA256,
        "platform": PLATFORM,
        "host": {"system": platform.system(), "machine": platform.machine()},
        "java_version": probes.get("java"),
        "gradle_version": "4.2 (pinned upstream wrapper; exact probe in toolchain)",
        "maven_version": "exact probe in toolchain",
        "jnetpcap_version": "1.4.1 / bundled r1425 native library",
        "libpcap_version": probes.get("libpcap"),
        "docker_base_images": {"builder": BUILD_BASE, "runtime": RUNTIME_BASE},
        "docker_image": {
            "tag": args.image,
            "id": image_data.get("Id"),
            "repo_digests": image_data.get("RepoDigests", []),
        },
        "build_success": build.returncode == 0,
        "jni_load_success": None,
        "jni_link_success": jni_linked,
        "cli_success": cli_success,
        "offline_pcap_reading_success": None,
        "source_hashes": probes.get("source_hashes"),
        "toolchain": probes.get("toolchain"),
        "build": {
            "exit_code": build.returncode,
            "runtime_seconds": round(time.monotonic() - started, 3),
            "stdout_tail": build.stdout[-12000:],
            "stderr_tail": build.stderr[-12000:],
        },
        "provenance_notes": [
            "The downloaded archive is checksum-pinned to the exact official commit.",
            "build.gradle and pom.xml identify V3; README names CICFlowMeterV3.zip.",
            "Cmd.java is absent at V3. The image includes the commit's dormant cic.cs.unb.ca.ifm.CICFlowMeter CLI by removing only its Gradle exclusion; the Java source bytes are unchanged and its SHA256 is recorded.",
            "Successful build or extraction does not establish 78-feature compatibility and does not authorize model inference.",
        ],
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "inference_run": False,
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return build.returncode


if __name__ == "__main__":
    raise SystemExit(main())
