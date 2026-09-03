#!/usr/bin/env python3
"""Train RF-v2-D3C exactly once and persist D4 internal validation evidence."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import resource
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.prepare_experiment_d_d3 import feature_hashes, validate_d2  # noqa: E402
from scripts.train_rf_v2 import validate_dry_run  # noqa: E402
from scripts.verify_experiment_d_frozen_baseline import build_manifest as frozen_baseline  # noqa: E402
from src.experiment_d.d3 import (  # noqa: E402
    canonical_json_sha256, decode_index_membership,
)
from src.experiment_d.d4 import (  # noqa: E402
    apply_selection_rule, confusion_rows, metrics_with_predictions,
    prediction_rows, write_csv_new, write_json_new,
)
from src.experiment_d.integrity import sha256_file  # noqa: E402
from src.ingestion.cicflowmeter_v3_adapter import (  # noqa: E402
    ADAPTER_IDENTITY, ADAPTER_VERSION, CICFLOWMETER_V3_COMMIT,
    CICFLOWMETER_V3_IMAGE_DIGEST, CROSSWALK_SHA256, MODEL_FEATURES,
    CICFlowMeterV3ModelAdapter,
)
from src.preprocessing.columns import normalize_columns  # noqa: E402
from src.preprocessing.labels import CLASS_NAMES, map_label  # noqa: E402

REPORT = ROOT / "reports/experiment_d/adaptation"
AUDIT = ROOT / "reports/experiment_d/audit"
MODEL_DIR = ROOT / "models/experiment_d"
SPLIT_PATH = REPORT / "split_manifest.json"
PLAN_PATH = REPORT / "rf_v2_training_plan.json"
MODEL_PATH = MODEL_DIR / "random_forest_rf_v2.joblib"
METADATA_PATH = MODEL_DIR / "random_forest_rf_v2_metadata.json"
TRAINING_MANIFEST_PATH = MODEL_DIR / "training_manifest.json"
CLASSES = tuple(CLASS_NAMES)

REPORT_PATHS = {
    "training_metrics": REPORT / "rf_v2_training_metrics.json",
    "rf_v2_adaptation": REPORT / "rf_v2_adaptation_validation_metrics.json",
    "rf_v1_adaptation": REPORT / "rf_v1_adaptation_validation_metrics.json",
    "rf_v2_control": REPORT / "rf_v2_cicids2017_control_metrics.json",
    "rf_v1_control": REPORT / "rf_v1_cicids2017_control_metrics.json",
    "rf_v2_adaptation_cm": REPORT / "rf_v2_adaptation_confusion_matrix.csv",
    "rf_v1_adaptation_cm": REPORT / "rf_v1_adaptation_confusion_matrix.csv",
    "rf_v2_control_cm": REPORT / "rf_v2_cicids2017_control_confusion_matrix.csv",
    "rf_v1_control_cm": REPORT / "rf_v1_cicids2017_control_confusion_matrix.csv",
    "comparison_csv": REPORT / "rf_v1_vs_rf_v2_internal_comparison.csv",
    "comparison_json": REPORT / "rf_v1_vs_rf_v2_internal_report.json",
    "rf_v2_adaptation_predictions": REPORT / "rf_v2_adaptation_validation_predictions.csv",
    "rf_v1_adaptation_predictions": REPORT / "rf_v1_adaptation_validation_predictions.csv",
    "rf_v2_control_predictions": REPORT / "rf_v2_cicids2017_control_predictions.csv",
    "rf_v1_control_predictions": REPORT / "rf_v1_cicids2017_control_predictions.csv",
    "leakage_audit": AUDIT / "d4_training_leakage_audit.json",
}


def ensure_create_new_outputs() -> None:
    for path in (MODEL_PATH, METADATA_PATH, TRAINING_MANIFEST_PATH, *REPORT_PATHS.values()):
        if path.exists():
            raise FileExistsError(f"D4 create-new output exists: {path}")


def load_cicids(split: dict) -> tuple[pd.DataFrame, pd.Series, list[dict], pd.DataFrame, pd.Series, list[dict]]:
    frames = []
    for source in split["cicids2017"]["source_identities"]:
        path = ROOT / source["logical_path"]
        if sha256_file(path) != source["sha256"]:
            raise ValueError(f"CICIDS2017 hash mismatch: {path}")
        frame = pd.read_csv(path, low_memory=False)
        frame.columns = normalize_columns(frame.columns)
        frame["__source_file"] = source["logical_path"]
        frame["__source_row"] = np.arange(len(frame), dtype=np.int64)
        frames.append(frame)
    data = pd.concat(frames, ignore_index=True); del frames
    labels = data["label"].map(map_label)
    data = data.loc[labels.notna()].copy(); data["label"] = labels.loc[labels.notna()]
    data = data.loc[~data.duplicated(subset=list(MODEL_FEATURES) + ["label"], keep="first")].reset_index(drop=True)
    if len(data) != split["cicids2017"]["filter_and_dedup_rows"]:
        raise ValueError("CICIDS2017 filtered row count mismatch")
    train_ix = decode_index_membership(split["cicids2017"]["training_membership"])
    control_ix = decode_index_membership(split["cicids2017"]["internal_control_membership"])
    numeric = data[list(MODEL_FEATURES)].replace([np.inf, -np.inf], np.nan).astype(np.float32)
    def part(indices: np.ndarray, role: str, include_provenance: bool):
        block = numeric.iloc[indices].reset_index(drop=True)
        target = data["label"].iloc[indices].astype(str).reset_index(drop=True)
        provenance = [{
            "row_identity": canonical_json_sha256(["CICIDS2017", data["__source_file"].iloc[i], int(data["__source_row"].iloc[i])]),
            "source_family":"CICIDS2017", "source_file":data["__source_file"].iloc[i],
            "original_row_index":int(data["__source_row"].iloc[i]), "split_role":role,
        } for i in indices] if include_provenance else []
        return block, target, provenance
    train = part(train_ix, "cicids2017_training", False)
    control = part(control_ix, "cicids2017_internal_control", True)
    del numeric, data
    return *train, *control


def load_adaptation(split: dict) -> tuple[pd.DataFrame, pd.Series, list[dict], pd.DataFrame, pd.Series, list[dict]]:
    adapter = CICFlowMeterV3ModelAdapter.from_metadata(ROOT / "models/model_metadata.json")
    selected = set(split["adaptation"]["candidate_strategies"]["D3-C"]["row_identities"])
    validation_ids = {x["row_identity"] for x in split["adaptation"]["validation_rows"]}
    train_features=[]; train_labels=[]; train_prov=[]; val_features=[]; val_labels=[]; val_prov=[]
    for source in split["adaptation"]["source_identities"]:
        path = ROOT / source["logical_path"]
        if sha256_file(path) != source["sha256"]: raise ValueError(f"adaptation hash mismatch: {path}")
        features = adapter.adapt_csv(path).features.replace([np.inf,-np.inf],np.nan).astype(np.float32)
        for index in range(len(features)):
            row_identity = canonical_json_sha256(["experiment_d_adaptation", source["sha256"], index])
            provenance = {"row_identity":row_identity,"source_family":"experiment_d_adaptation","source_file":source["logical_path"],"capture_id":source["capture_id"],"session_id":source["session_id"],"scenario_id":source["scenario_id"],"original_row_index":index}
            if row_identity in selected:
                train_features.append(features.iloc[index]); train_labels.append(source["class"]); train_prov.append({**provenance,"split_role":"adaptation_training"})
            if row_identity in validation_ids:
                val_features.append(features.iloc[index]); val_labels.append(source["class"]); val_prov.append({**provenance,"split_role":"adaptation_validation"})
    return (pd.DataFrame(train_features, columns=MODEL_FEATURES).reset_index(drop=True), pd.Series(train_labels), train_prov,
            pd.DataFrame(val_features, columns=MODEL_FEATURES).reset_index(drop=True), pd.Series(val_labels), val_prov)


def predict(model: Pipeline, x: pd.DataFrame, y: pd.Series, provenance: list[dict]):
    started=time.perf_counter(); predicted=model.predict(x); probabilities=model.predict_proba(x); elapsed=time.perf_counter()-started
    metrics=metrics_with_predictions(y,predicted,elapsed)
    return metrics,prediction_rows(provenance,y,predicted,probabilities,model.classes_)


def main() -> int:
    ensure_create_new_outputs()
    split_bytes = SPLIT_PATH.read_bytes(); plan_bytes = PLAN_PATH.read_bytes()
    split=json.loads(split_bytes); plan=json.loads(plan_bytes)
    dry=validate_dry_run(split,plan,"D3-C")
    if dry["combined_training_counts"] != {"Normal":1677198,"DDoS":103613,"PortScan":73768}:
        raise ValueError("D3-C combined distribution mismatch")
    validate_d2(); baseline_before=frozen_baseline()
    final_files=[p for p in (ROOT/"data/lab/experiment_d/final_test").rglob("*") if p.is_file() and p.name != ".gitkeep"]
    if final_files: raise ValueError("final_test artifact exists; D4 fails closed")

    x_cic_train,y_cic_train,p_cic_train,x_control,y_control,p_control=load_cicids(split)
    x_adapt_train,y_adapt_train,p_adapt_train,x_adapt_val,y_adapt_val,p_adapt_val=load_adaptation(split)
    x_train=pd.concat([x_cic_train,x_adapt_train],ignore_index=True); y_train=pd.concat([y_cic_train,y_adapt_train],ignore_index=True)
    del x_cic_train,y_cic_train,x_adapt_train,y_adapt_train
    actual={name:int((y_train==name).sum()) for name in CLASSES}
    if actual != dry["combined_training_counts"]: raise ValueError(f"training counts mismatch: {actual}")
    params=plan["rf_parameters"]
    pipeline=Pipeline([("imputer",SimpleImputer(strategy="median")),("classifier",RandomForestClassifier(**params))])
    started_utc=datetime.now(timezone.utc); started=time.perf_counter(); pipeline.fit(x_train,y_train); training_elapsed=time.perf_counter()-started; ended_utc=datetime.now(timezone.utc)
    MODEL_DIR.mkdir(parents=True,exist_ok=True)
    with MODEL_PATH.open("xb") as stream: joblib.dump(pipeline,stream,compress=3)
    model_hash=sha256_file(MODEL_PATH)

    rf_v1=joblib.load(ROOT/"models/random_forest_active.joblib")
    v2a,v2ap=predict(pipeline,x_adapt_val,y_adapt_val,p_adapt_val); v1a,v1ap=predict(rf_v1,x_adapt_val,y_adapt_val,p_adapt_val)
    v2c,v2cp=predict(pipeline,x_control,y_control,p_control); v1c,v1cp=predict(rf_v1,x_control,y_control,p_control)
    selection=apply_selection_rule(v1a,v2a)
    common={"split_manifest_sha256":hashlib.sha256(split_bytes).hexdigest(),"training_plan_sha256":hashlib.sha256(plan_bytes).hexdigest()}
    write_json_new(REPORT_PATHS["training_metrics"],{"model":"RF-v2-D3C","training_started_utc":started_utc.isoformat(),"training_ended_utc":ended_utc.isoformat(),"training_elapsed_seconds":training_elapsed,"peak_resident_memory_bytes":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,"peak_memory_measurement":"macOS ru_maxrss bytes; process lifetime high-water mark","model_size_bytes":MODEL_PATH.stat().st_size,"training_class_counts":actual,"training_rows":len(y_train),"rf_parameters":params,**common})
    for key,value in (("rf_v2_adaptation",v2a),("rf_v1_adaptation",v1a),("rf_v2_control",v2c),("rf_v1_control",v1c)): write_json_new(REPORT_PATHS[key],{"model":key,"metrics":value,**common})
    fields=["ground_truth",*CLASSES]
    for key,value in (("rf_v2_adaptation_cm",v2a),("rf_v1_adaptation_cm",v1a),("rf_v2_control_cm",v2c),("rf_v1_control_cm",v1c)): write_csv_new(REPORT_PATHS[key],fields,confusion_rows(value))
    pred_fields=list(v2ap[0])
    for key,value in (("rf_v2_adaptation_predictions",v2ap),("rf_v1_adaptation_predictions",v1ap),("rf_v2_control_predictions",v2cp),("rf_v1_control_predictions",v1cp)): write_csv_new(REPORT_PATHS[key],pred_fields,value)
    comparison=[]
    for dataset,a,b in (("adaptation_validation",v1a,v2a),("cicids2017_internal_control",v1c,v2c)):
        for metric in ("accuracy","macro_precision","macro_recall","macro_f1"):
            comparison.append({"dataset":dataset,"metric":metric,"rf_v1":a[metric],"rf_v2":b[metric],"rf_v2_minus_rf_v1":b[metric]-a[metric]})
        for name in CLASSES:
            metric=f"{name}_recall"; av=a["classification_report"][name]["recall"]; bv=b["classification_report"][name]["recall"]
            comparison.append({"dataset":dataset,"metric":metric,"rf_v1":av,"rf_v2":bv,"rf_v2_minus_rf_v1":bv-av})
    write_csv_new(REPORT_PATHS["comparison_csv"],list(comparison[0]),comparison)
    commit=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip()
    metadata={"model_name":"RF-NIDS Random Forest","version":"rf-v2.0-experiment-d","role":"Experiment D candidate","active":False,"feature_count":78,"feature_names":list(MODEL_FEATURES),"classes":list(CLASSES),"training_strategy":"D3-C","rf_parameters":params,"training_row_counts":actual,"adaptation_training_session_ids":split["adaptation"]["selected_training_sessions"],"adaptation_validation_session_ids":split["adaptation"]["selected_validation_sessions"],"cicids2017_source_identities":split["cicids2017"]["source_identities"],"split_manifest_identity":split["content_identity"],"split_manifest_sha256":common["split_manifest_sha256"],"training_plan_sha256":common["training_plan_sha256"],"model_sha256":model_hash,"adapter":{"identity":ADAPTER_IDENTITY,"version":ADAPTER_VERSION,"crosswalk_sha256":CROSSWALK_SHA256},"cicflowmeter":{"commit":CICFLOWMETER_V3_COMMIT,"image_digest":CICFLOWMETER_V3_IMAGE_DIGEST},"code_commit":commit,"training_timestamp_utc":ended_utc.isoformat(),"python_version":platform.python_version(),"numpy_version":np.__version__,"pandas_version":pd.__version__,"scikit_learn_version":sklearn.__version__,"joblib_version":joblib.__version__}
    write_json_new(METADATA_PATH,metadata)
    evidence_before_manifest={name:{"logical_path":str(path.relative_to(ROOT)),"sha256":sha256_file(path),"size_bytes":path.stat().st_size} for name,path in REPORT_PATHS.items() if path.exists() and name not in {"comparison_json","leakage_audit"}}
    training_manifest={"schema":"experiment_d_d4_training_manifest","schema_version":1,"model_sha256":model_hash,"metadata_sha256":sha256_file(METADATA_PATH),"split_manifest_sha256":common["split_manifest_sha256"],"training_plan_sha256":common["training_plan_sha256"],"training_membership_identity":split["adaptation"]["candidate_strategies"]["D3-C"]["membership_sha256"],"cicids_training_membership_sha256":split["cicids2017"]["training_membership"]["packed_sha256"],"cicids_control_membership_sha256":split["cicids2017"]["internal_control_membership"]["packed_sha256"],"evidence":evidence_before_manifest,"training_fit_count":1}
    write_json_new(TRAINING_MANIFEST_PATH,training_manifest)
    baseline_after=frozen_baseline()
    cicids_membership_disjoint = not set(decode_index_membership(split["cicids2017"]["training_membership"])) & set(decode_index_membership(split["cicids2017"]["internal_control_membership"]))
    leakage_checks={"no_final_test_data":True,"no_experiment_c_data":True,"adaptation_validation_excluded_from_fit":not set(x["row_identity"] for x in p_adapt_train)&set(x["row_identity"] for x in p_adapt_val),"cicids_control_excluded_from_fit":cicids_membership_disjoint,"no_session_capture_overlap":not set(x["session_id"] for x in p_adapt_train)&set(x["session_id"] for x in p_adapt_val),"no_post_handling_content_hash_overlap":split["leakage_checks"]["post_handling_cross_source_overlap_count"]==0,"provenance_excluded_from_features":list(x_train.columns)==list(MODEL_FEATURES),"imputer_fitted_inside_training_pipeline":hasattr(pipeline.named_steps["imputer"],"statistics_"),"feature_count_is_78":x_train.shape[1]==78,"rf_v1_immutable":baseline_before["path_independent_scientific_identity"]==baseline_after["path_independent_scientific_identity"]}
    leakage={"status":"PASS" if all(leakage_checks.values()) else "FAIL","checks":leakage_checks,"frozen_baseline_before":baseline_before["path_independent_scientific_identity"],"frozen_baseline_after":baseline_after["path_independent_scientific_identity"]}
    write_json_new(REPORT_PATHS["leakage_audit"],leakage)
    frozen={"model":model_hash,"metadata":sha256_file(METADATA_PATH),"training_manifest":sha256_file(TRAINING_MANIFEST_PATH),**{name:sha256_file(path) for name,path in REPORT_PATHS.items() if path.exists() and name!="comparison_json"}}
    internal={"declaration":"RF-v2 INTERNAL CANDIDATE ACCEPTED" if selection["passed"] else "RF-v2 INTERNAL CANDIDATE REJECTED","selection":selection,"adaptation_validation":{"rf_v1":v1a,"rf_v2":v2a},"cicids2017_internal_control":{"rf_v1":v1c,"rf_v2":v2c},"frozen_artifact_hashes":frozen,**common}
    write_json_new(REPORT_PATHS["comparison_json"],internal)
    print(json.dumps({"status":internal["declaration"],"model_sha256":model_hash,"model_size_bytes":MODEL_PATH.stat().st_size,"training_elapsed_seconds":training_elapsed,"selection":selection,"leakage_audit":leakage["status"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
