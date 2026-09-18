"""Read-only Experiment E E1 scaffold validation."""

from pathlib import Path

from src.common.config import PROJECT_ROOT
from src.experiment_d.integrity import sha256_file
from src.experiment_e.config import load_experiment_e_config
from src.experiment_e.integrity import (
    load_preregistration,
    ordered_feature_identity,
    validate_feature_contract,
    validate_provenance,
)
from src.experiment_e.paths import CLASS_DIRS, ROLES, ExperimentEPaths
from src.ingestion.cicflowmeter_v3_adapter import (
    CICFLOWMETER_V3_COMMIT,
    CICFLOWMETER_V3_IMAGE_DIGEST,
    MODEL_FEATURES,
)


def validate_e1(root: Path = PROJECT_ROOT) -> dict:
    config = load_experiment_e_config(root / "config/experiment_e.yaml")
    paths = ExperimentEPaths(root)
    paths.assert_isolated_from_experiment_d()
    preregistration = load_preregistration(
        paths.data_root / "manifests/session_preregistration.json"
    )
    baseline = config.baseline_rf_v2
    identities = {
        baseline.artifact: baseline.artifact_sha256,
        baseline.scientific_metadata: baseline.scientific_metadata_sha256,
        baseline.runtime_metadata: baseline.runtime_metadata_sha256,
        config.adapter.crosswalk: config.adapter.crosswalk_sha256,
    }
    for logical_path, expected in identities.items():
        artifact = root / logical_path
        if not artifact.is_file() or sha256_file(artifact) != expected:
            raise ValueError(f"scientific artifact identity mismatch: {logical_path}")
    validate_feature_contract(MODEL_FEATURES)
    if (
        ordered_feature_identity(MODEL_FEATURES)
        != config.feature_contract.ordered_names_sha256
    ):
        raise ValueError("configured ordered feature identity mismatch")
    validate_provenance(
        config.cicflowmeter_v3.model_dump(),
        {
            "commit": CICFLOWMETER_V3_COMMIT,
            "source_archive_sha256": (
                "78f13b2d474e5a669a367aef610d597cf86bc338088ffdd72228671bdca364c7"
            ),
            "image_digest": CICFLOWMETER_V3_IMAGE_DIGEST,
        },
    )
    required = [paths.data_root / "manifests"]
    for role in ROLES:
        required.append(paths.manifest_root(role))
        for class_dir in CLASS_DIRS:
            required.extend((paths.pcap_root(role, class_dir), paths.flow_root(role, class_dir)))
    required.extend(
        [paths.model_root]
        + [paths.report_root / name for name in (
            "baseline", "adaptation", "validation", "final_test", "audit", "comparison"
        )]
    )
    missing = [str(path.relative_to(root)) for path in required if not path.is_dir()]
    if missing:
        raise ValueError(f"Experiment E scaffold directories missing: {missing}")
    return {
        "status": "PASS", "phase": config.phase,
        "sessions": len(preregistration["sessions"]),
        "traffic_collected": False, "model_trained": False,
        "baseline_identities": identities, "feature_count": len(MODEL_FEATURES),
    }
