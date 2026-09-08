#!/usr/bin/env python3
"""Validate RF-v2 through the real application using a disposable database."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from src.api.auth import hash_password
from src.api.main import create_app
from src.api.models import ModelRecord, Prediction, User
from src.api.service import register_inactive_model, sync_active_model
from src.common.config import PROJECT_ROOT, Settings
from src.common.hashing import sha256_file
from src.inference import InferenceEngine


ROOT = PROJECT_ROOT
RF1 = ROOT / "models/random_forest_active.joblib"
RF1_META = ROOT / "models/model_metadata.json"
RF2 = ROOT / "models/experiment_d/random_forest_rf_v2.joblib"
RF2_META = ROOT / "models/experiment_d/random_forest_rf_v2_runtime_metadata.json"
FIXTURES = ROOT / "tests/fixtures/rf_v2_integration/functional_vectors.json"
DEFAULT_OUTPUT = ROOT / "reports/application/rf_v2_activation_validation.json"


def scientific_snapshot() -> dict:
    roots = [ROOT / "data/lab/experiment_d", ROOT / "reports/experiment_d"]
    paths = [
        RF1, ROOT / "models/random_forest_tuned.joblib",
        ROOT / "models/random_forest_baseline.joblib", RF1_META, RF2,
        ROOT / "models/experiment_d/random_forest_rf_v2_metadata.json",
        ROOT / "reports/metrics/experiment_c_v3_final.json",
        ROOT / "reports/tables/experiment_c_final_confusion_matrix.csv",
        ROOT / "reports/tables/experiment_c_final_class_metrics.csv",
        ROOT / "reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv",
    ]
    paths.extend(path for base in roots for path in base.rglob("*") if path.is_file())
    records = [{"path": str(path.relative_to(ROOT)), "sha256": sha256_file(path)}
               for path in sorted(set(paths))]
    identity = hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"identity": identity, "file_count": len(records), "records": records}


def expanded_vectors() -> dict[str, dict[str, float]]:
    runtime = json.loads(RF2_META.read_text())
    fixture = json.loads(FIXTURES.read_text())
    return {
        label: {name: float(overrides.get(name, 0.0)) for name in runtime["feature_names"]}
        for label, overrides in fixture["vectors"].items()
    }


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_validation(output: Path | None = None) -> dict:
    before = scientific_snapshot()
    rf1_hash, rf2_hash = sha256_file(RF1), sha256_file(RF2)
    vectors = expanded_vectors()
    cases = []
    with tempfile.TemporaryDirectory(prefix="rf-nids-rf-v2-integration-") as directory:
        temporary_root = Path(directory)
        database_path = temporary_root / "integration.db"

        rf1_runtime_metadata = json.loads(RF1_META.read_text(encoding="utf-8"))
        rf1_runtime_metadata["model_path"] = "models/random_forest_active.joblib"
        rf1_runtime_metadata_path = temporary_root / "rf1_runtime_metadata.json"
        rf1_runtime_metadata_path.write_text(
            json.dumps(rf1_runtime_metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        settings = Settings(
            app_env="integration-test", log_level="WARNING",
            leakage_columns_config=ROOT / "config/leakage_columns.json",
            database_url=f"sqlite:///{database_path}", model_path=RF2,
            model_metadata_path=RF2_META, max_batch_size=10, max_page_size=100,
        )
        app = create_app(settings, create_tables=True)
        with TestClient(app) as client:
            with app.state.session_factory() as db:
                register_inactive_model(db, json.loads(RF1_META.read_text()))
                db.add(User(name="RF-v2 Integration Admin", email="rfv2@example.test",
                    password_hash=hash_password("rfv2-integration-password"), role="ADMIN", is_active=True))
                db.commit()
            login = client.post("/api/auth/login", json={"email":"rfv2@example.test","password":"rfv2-integration-password"})
            _assert(login.status_code == 200, "administrator login failed")
            client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

            active = client.get("/api/models/active").json()
            history = client.get("/api/models").json()
            _assert(active["model_version"] == "rf-v2.0" and active["artifact_sha256"] == rf2_hash, "RF-v2 is not active")
            _assert({row["model_version"] for row in history} == {"rf-v1.0", "rf-v2.0"}, "model history incomplete")
            cases.append({"test_id":"RFV2-01","status":"PASS","actual":"RF-v2 active; RF-v1 retained as previous/rollback"})

            outputs = {}
            metadata = {
                "capture_session_id":"rf-v2-integration-controlled-20260903",
                "capture_interface":"synthetic-functional-fixture",
                "pcap_segment":"not-a-pcap-functional-vector",
                "capture_time":"2026-09-03T09:00:00Z",
                "source_ip":"192.0.2.10", "destination_ip":"198.51.100.20",
                "source_port":49152, "destination_port":80, "protocol":"TCP",
            }
            for label in ("Normal", "PortScan", "DDoS"):
                response = client.post("/api/predict", json={"features":vectors[label],"metadata":metadata})
                _assert(response.status_code == 201, f"{label} inference failed")
                result = response.json(); outputs[label] = result
                _assert(result["prediction"] == label and result["model_version"] == "rf-v2.0", f"{label} branch mismatch")
                _assert(set(result["probabilities"]) == {"Normal","DDoS","PortScan"}, "probabilities missing")

            alerts = client.get("/api/alerts").json()
            by_label = {row["predicted_label"]: row for row in alerts}
            _assert("Normal" not in by_label, "Normal created an alert")
            _assert(by_label["PortScan"]["severity"] == "MEDIUM", "PortScan alert mismatch")
            _assert(by_label["DDoS"]["severity"] == "HIGH", "DDoS alert mismatch")
            cases.extend([
                {"test_id":"RFV2-02","status":"PASS","actual":"Normal persisted under RF-v2 with no alert"},
                {"test_id":"RFV2-03","status":"PASS","actual":"PortScan persisted and created MEDIUM alert"},
                {"test_id":"RFV2-04","status":"PASS","actual":"DDoS persisted and created HIGH alert"},
            ])

            normal_detail = client.get(f"/api/predictions/{outputs['Normal']['prediction_id']}").json()
            _assert(normal_detail["model_version"] == "rf-v2.0" and len(normal_detail["class_probabilities"]) == 3, "prediction detail provenance failure")
            cases.append({"test_id":"RFV2-05","status":"PASS","actual":"detail exposed RF-v2 and genuine three-class probabilities"})
            summary = client.get("/api/dashboard/summary").json()
            _assert(summary["total_flows"] == 3 and client.get("/api/models/active").json()["model_version"] == "rf-v2.0", "dashboard/model status mismatch")
            cases.append({"test_id":"RFV2-06","status":"PASS","actual":"dashboard counted three RF-v2 runtime records and active model endpoint showed RF-v2"})
            monitoring = client.get("/api/traffic-flows").json()
            _assert(len(monitoring) == 3, "monitoring did not expose all rows")
            prediction_export = client.get("/api/export/predictions", params={"format":"json"}).json()
            _assert(len(prediction_export["predictions"]) == 3 and all(row["model_version"] == "rf-v2.0" for row in prediction_export["predictions"]), "prediction export provenance failure")
            cases.append({"test_id":"RFV2-07","status":"PASS","actual":"prediction export contained all RF-v2 records and model version"})

            alert_id = by_label["DDoS"]["id"]
            acknowledged = client.patch(f"/api/alerts/{alert_id}/acknowledge").json()
            _assert(acknowledged["status"] == "ACKNOWLEDGED" and acknowledged["model_version"] == "rf-v2.0", "alert acknowledgment failure")

            with app.state.session_factory() as db:
                rf1_engine = InferenceEngine(RF1, rf1_runtime_metadata_path)
                rollback = sync_active_model(db, rf1_engine.metadata)
                _assert(rollback.model_version == "rf-v1.0", "rollback activation failed")
                _assert(db.scalar(select(ModelRecord).where(ModelRecord.model_version=="rf-v2.0")) is not None, "rollback deleted RF-v2")
                restore = sync_active_model(db, app.state.inference.metadata)
                _assert(restore.model_version == "rf-v2.0", "RF-v2 restore failed")
                stored = db.scalars(select(Prediction).order_by(Prediction.id)).all()
                _assert(len(stored)==3 and all(row.model.model_version=="rf-v2.0" for row in stored), "historical prediction model linkage changed")
            cases.append({"test_id":"RFV2-08","status":"PASS","actual":"RF-v1 rollback and RF-v2 restoration preserved both records and historical predictions"})

            final_active = client.get("/api/models/active").json()
            alert_export = client.get("/api/export/alerts", params={"format":"json"}).json()
            result = {
                "schema":"rf_v2_application_activation_validation","schema_version":1,
                "status":"PASS","functional_only":True,
                "performance_claim":False,
                "executed_at":datetime.now(timezone.utc).isoformat(),
                "database":"disposable SQLite integration database",
                "rf_v1":{"version":"rf-v1.0","artifact_sha256":rf1_hash,"preserved":True},
                "rf_v2":{"version":"rf-v2.0","artifact_sha256":rf2_hash,"active_after_validation":final_active["model_version"]=="rf-v2.0"},
                "runtime_metadata":{"path":str(RF2_META.relative_to(ROOT)),"sha256":sha256_file(RF2_META)},
                "predictions":outputs,"alert_count":len(alerts),"alert_export_count":len(alert_export["alerts"]),
                "monitoring_count":len(monitoring),"dashboard":summary,
                "black_box_cases":cases,"black_box_passed":sum(row["status"]=="PASS" for row in cases),
                "rollback_verified":True,"schema_migration":False,
            }
    after = scientific_snapshot()
    _assert(before["identity"] == after["identity"], "scientific evidence changed")
    result["scientific_integrity"]={"status":"PASS","file_count":before["file_count"],"identity_before":before["identity"],"identity_after":after["identity"],"no_retraining":True}
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True); stream.write("\n")
    return result


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,default=DEFAULT_OUTPUT)
    args=parser.parse_args(); result=run_validation(args.output)
    print(json.dumps({"status":result["status"],"black_box_passed":result["black_box_passed"],"runtime_metadata_sha256":result["runtime_metadata"]["sha256"]},sort_keys=True)); return 0


if __name__ == "__main__": raise SystemExit(main())
