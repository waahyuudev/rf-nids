#!/usr/bin/env python3
"""Create the deterministic Experiment D frozen-baseline integrity manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from src.common.config import PROJECT_ROOT
from src.experiment_d.config import load_experiment_d_config
from src.experiment_d.integrity import require_create_new, sha256_file
from src.ingestion.cicflowmeter_v3_adapter import (
    ADAPTER_IDENTITY,
    ADAPTER_VERSION,
    CICFLOWMETER_V3_COMMIT,
    CICFLOWMETER_V3_IMAGE_DIGEST,
    CROSSWALK_SHA256,
)


OUTPUT = PROJECT_ROOT / "reports/experiment_d/audit/frozen_baseline_manifest.json"
EXPECTED = {
    "models/random_forest_active.joblib": "73d86cb98f35c228d6e619e0f746a2b659d94deabe86d57e801c58bcf935f647",
    "models/random_forest_tuned.joblib": "73d86cb98f35c228d6e619e0f746a2b659d94deabe86d57e801c58bcf935f647",
    "models/random_forest_baseline.joblib": "0ac3031724bb1168553ba81aeb48dafc80036ec942af8181dd84dea49228190c",
    "models/model_metadata.json": "c632b16d30efb8f5a642070520c43cc1caaf36cbead33bddf9b5359b0fb531f2",
    "data/lab/pcap/normal-http-test.pcap": "04fe7f461feb9974557341dd2620da5d9ad476b52604f691472984be8fe9e9b4",
    "data/lab/pcap/ddos-test.pcap": "cac5ec5fcaeef11eb1e055933329b30fe431acf6a5a69b615d99c2def25860cd",
    "data/lab/pcap/portscan-test.pcap": "653dc8e8f7593aa811958374b0d95414f42e799b845c8bcaeb262e4baf01f102",
    "data/lab/flows/cicflowmeter-v3/normal-http-test.pcap_ISCX.csv": "5fced18068b91e1955206a3f07833f5533d68f706b45c36eca9e6d6e3eec477a",
    "data/lab/flows/cicflowmeter-v3/ddos-test.pcap_ISCX.csv": "77376a3e6c6707435e709adef437610c3f0434f9ec8361dfdd3031ea5f1cf045",
    "data/lab/flows/cicflowmeter-v3/portscan-test.pcap_ISCX.csv": "e10519fe09819247eecd45260740380f5bb037f5e320432634e7905e9f4c43c8",
    "reports/metrics/experiment_c_v3_final.json": "6e091fdc1f0113fd34403d60dafdea83e6aa6ee957bf4a77632da31c6478f02b",
    "reports/tables/experiment_c_final_confusion_matrix.csv": "7e269d96d4fd266d6937f69d2b7e9c70e1c000d1ad9f255acf9645bbcbeb2a31",
    "reports/tables/experiment_c_final_class_metrics.csv": "1f5d67a772258ed2120033c706ad0aeba989dd656eac56cfe50f2756e30aad8e",
    "reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv": "66e517cdcea217f19de4d0a2cd45302ede999388393f539fb8ca4a2c68b74cf4",
}


def build_manifest() -> dict[str, object]:
    config = load_experiment_d_config(PROJECT_ROOT / "config/experiment_d.yaml")
    entries = []
    failures = []
    for logical_path, expected in sorted(EXPECTED.items()):
        path = PROJECT_ROOT / logical_path
        actual = sha256_file(path) if path.is_file() else None
        matches = actual == expected
        entries.append({"logical_path": logical_path, "size_bytes": path.stat().st_size if path.is_file() else None,
                        "sha256": actual, "expected_sha256": expected, "matches": matches})
        if not matches:
            failures.append(logical_path)
    encoded = json.dumps(
        [{"logical_path": x["logical_path"], "size_bytes": x["size_bytes"], "sha256": x["sha256"]} for x in entries],
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    provenance_ok = (
        config.cicflowmeter_v3.source_archive_sha256 == "78f13b2d474e5a669a367aef610d597cf86bc338088ffdd72228671bdca364c7"
        and config.cicflowmeter_v3.image_digest == "sha256:0227c7280e586d54144b9bb11b2a6b5d4b1c4ba9bc7c44199fa312a6b829caab"
        and config.cicflowmeter_v3.commit == CICFLOWMETER_V3_COMMIT
        and config.cicflowmeter_v3.image_digest == CICFLOWMETER_V3_IMAGE_DIGEST
        and config.adapter.identity == ADAPTER_IDENTITY
        and config.adapter.version == ADAPTER_VERSION
        and config.adapter.crosswalk_sha256 == CROSSWALK_SHA256
    )
    if failures or not provenance_ok:
        raise ValueError(f"frozen baseline verification failed: {failures}")
    return {"experiment_code": "EXPERIMENT_D", "status": "PASS", "identity_algorithm": "sha256",
            "path_independent_scientific_identity": hashlib.sha256(encoded).hexdigest(),
            "entries": entries, "cicflowmeter_v3": config.cicflowmeter_v3.model_dump(),
            "adapter": config.adapter.model_dump()}


def main() -> int:
    require_create_new(OUTPUT)
    manifest = build_manifest()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "PASS", "output": str(OUTPUT)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
