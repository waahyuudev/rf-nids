#!/usr/bin/env python3
"""Build and document the isolated historical Java CICFlowMeter image."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTEXT = ROOT / "docker" / "historical-cicflowmeter"
REPORT = ROOT / "reports" / "metrics" / "historical_cicflowmeter_build.json"
IMAGE = "rf-nids-historical-cicflowmeter:98a5ebad"
PLATFORM = "linux/amd64"
SOURCE_URL = "https://github.com/ahlashkari/CICFlowMeter"
SOURCE_COMMIT = "98a5ebad0df579cc8b43eedd3421b3ae87699901"
SOURCE_SHA256 = "fcaf387d0a7ce6a7a0cf88545163e96173569121f16af81d483f8f775de39a22"


def run(command: list[str], *, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=IMAGE)
    args = parser.parse_args()
    started = time.monotonic()
    built_at = datetime.now(timezone.utc).isoformat()

    build = run(
        [
            "docker",
            "build",
            "--platform",
            PLATFORM,
            "--pull",
            "--tag",
            args.image,
            str(CONTEXT),
        ]
    )

    inspect = run(["docker", "image", "inspect", args.image]) if build.returncode == 0 else None
    image_data = {}
    if inspect and inspect.returncode == 0:
        image_data = json.loads(inspect.stdout)[0]

    probes: dict[str, dict[str, object]] = {}
    if build.returncode == 0:
        commands = {
            "java": ["java", "-version"],
            "build_toolchain": ["cat", "/opt/CICFlowMeter/BUILD_TOOLCHAIN.txt"],
            "jni": ["sh", "-c", "ldd /opt/CICFlowMeter/lib/native/libjnetpcap.so"],
            "libpcap": ["sh", "-c", "dpkg-query -W -f='${Version}' libpcap-dev"],
        }
        for name, command in commands.items():
            result = run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--platform",
                    PLATFORM,
                    "--entrypoint",
                    command[0],
                    args.image,
                    *command[1:],
                ]
            )
            probes[name] = {
                "exit_code": result.returncode,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }

    jni_text = " ".join(
        str(probes.get("jni", {}).get(key, "")) for key in ("stdout", "stderr")
    )
    jni_link_success = (
        probes.get("jni", {}).get("exit_code") == 0
        and "libpcap" in jni_text
        and "not found" not in jni_text
    )
    report = {
        "status": "success" if build.returncode == 0 else "failure",
        "generated_at_utc": built_at,
        "source": {
            "repository_url": SOURCE_URL,
            "commit_sha": SOURCE_COMMIT,
            "archive_sha256": SOURCE_SHA256,
        },
        "platform": PLATFORM,
        "host": {"system": platform.system(), "machine": platform.machine()},
        "image": {
            "tag": args.image,
            "id": image_data.get("Id"),
            "repo_digests": image_data.get("RepoDigests", []),
            "base_build_image": "eclipse-temurin:8-jdk-jammy@sha256:e0e0243c25c8985bb786948c2e23d267597ad9751c0311f43c113211a25392f5",
            "base_runtime_image": "eclipse-temurin:8-jre-jammy@sha256:8d8ffe619c1b4aebfa670426ea6b938cccf76faa491ca8483dee520c48b30441",
            "base_digest_note": "linux/amd64 manifest digests are pinned in the Dockerfile.",
        },
        "versions": {
            "java": probes.get("java"),
            "gradle": "4.2 (upstream wrapper)",
            "maven": "exact version recorded in build_toolchain_probe",
            "build_toolchain_probe": probes.get("build_toolchain"),
            "jnetpcap": "1.4.1/r1425 (bundled upstream)",
            "libpcap": probes.get("libpcap"),
        },
        "build": {
            "success": build.returncode == 0,
            "exit_code": build.returncode,
            "runtime_seconds": round(time.monotonic() - started, 3),
            "stdout_tail": build.stdout[-12000:],
            "stderr_tail": build.stderr[-12000:],
        },
        "jni": {
            "link_dependencies_resolved": jni_link_success,
            "offline_load_success": None,
            "note": "ldd verifies native linkage. Actual JNI/offline load is established only by a successful extraction and is copied into the extraction report.",
            "probe": probes.get("jni"),
        },
        "known_provenance_caveat": "The pinned public repository identifies this source as CICFlowMeter V4. It is not yet proven to be the exact V3 generator used for CICIDS2017; successful build/extraction is not semantic compatibility.",
        "safety": {
            "offline_only": True,
            "model_inference_run": False,
            "feature_values_transformed": False,
            "existing_python_extractor_modified": False,
        },
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    java_summary = probes.get("java", {}).get("stderr", "not available").splitlines()
    print("Historical CICFlowMeter Docker Build")
    print("------------------------------------")
    print(f"Platform: {PLATFORM}")
    print(f"Java: {java_summary[0] if java_summary else 'not available'}")
    print(f"Source commit: {SOURCE_COMMIT}")
    print(f"Image: {image_data.get('Id', args.image)}")
    print(f"JNI: {'linked' if jni_link_success else 'not verified'}")
    print(f"Build: {'SUCCESS' if build.returncode == 0 else 'FAILURE'}")
    return build.returncode


if __name__ == "__main__":
    raise SystemExit(main())
