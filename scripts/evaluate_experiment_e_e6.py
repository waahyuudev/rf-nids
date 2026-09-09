#!/usr/bin/env python3
"""Experiment E E6: sealed offline validation and RF-v2/RF-v3 comparison."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_experiment_d_frozen_baseline import build_manifest as frozen_baseline
from src.experiment_d.integrity import sha256_file
from src.experiment_e.e1 import validate_e1
from src.experiment_e.integrity import ordered_feature_identity, validate_feature_contract
from src.ingestion.cicflowmeter_v3_adapter import CICFlowMeterV3ModelAdapter, MODEL_FEATURES

CANDIDATE = ROOT / "models/experiment_e/random_forest_rf_v3_candidate.joblib"
CANDIDATE_META = ROOT / "models/experiment_e/random_forest_rf_v3_candidate_metadata.json"
BASELINE = ROOT / "models/experiment_d/random_forest_rf_v2.joblib"
SOURCES = (("N-V1", "Normal", ROOT / "data/lab/experiment_e/validation/flows/cicflowmeter-v3/normal/expe-normal-n-v1.pcap_ISCX.csv", "1120b5efb9700d4c2173b1d7cf0c9ccd3beee3f09959ec3397181fc824190a76", 17),
           ("P-V1", "PortScan", ROOT / "data/lab/experiment_e/validation/flows/cicflowmeter-v3/portscan/expe-portscan-p-v1.pcap_ISCX.csv", "1664c6ab044daced69d198ee967a7deba452ecad68da46d99bff9faffd8820dc", 1501))
OUT = ROOT / "reports/experiment_e/evaluation/e6_offline_validation.json"
COMPARE = ROOT / "reports/experiment_e/analysis/e6_rf_v2_vs_rf_v3_comparison.json"
CLASSES = ["Normal", "DDoS", "PortScan"]

def write_new(path: Path, data: dict) -> None:
    if path.exists(): raise FileExistsError(f"E6 create-new output exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(data, indent=2, sort_keys=True)+"\n", encoding="utf-8")

def probability_summary(proba: np.ndarray, classes: list[str], mask: np.ndarray) -> dict:
    q = (0, .25, .5, .75, 1)
    return {name: dict(zip(("min","q1","median","q3","max"), map(float, np.quantile(proba[mask, i], q)))) | {"mean": float(proba[mask, i].mean())} for i, name in enumerate(classes)}

def evaluate(model, x: pd.DataFrame, y: np.ndarray, sessions: np.ndarray) -> dict:
    pred, proba = model.predict(x), model.predict_proba(x)
    model_classes = list(model.classes_)
    observed = ["Normal", "PortScan"]
    pr, re, f1, support = precision_recall_fscore_support(y, pred, labels=observed, zero_division=0)
    metrics = {c: {"precision":float(pr[i]), "recall":float(re[i]), "f1":float(f1[i]), "support":int(support[i])} for i,c in enumerate(observed)}
    cm = confusion_matrix(y, pred, labels=CLASSES).astype(int).tolist()
    predicted = pd.Series(pred).value_counts().reindex(CLASSES, fill_value=0).astype(int).to_dict()
    details = {"accuracy":float(accuracy_score(y,pred)), "observed_class_metrics":metrics, "confusion_matrix_labels":CLASSES, "confusion_matrix":cm, "predicted_class_counts":predicted,
               "normal_false_positive_as_portscan_count":int(((y=="Normal")&(pred=="PortScan")).sum()), "normal_false_positive_as_portscan_rate":float(((y=="Normal")&(pred=="PortScan")).mean() / (y=="Normal").mean()),
               "portscan_false_negative_count":int(((y=="PortScan")&(pred!="PortScan")).sum()), "portscan_to_normal_count":int(((y=="PortScan")&(pred=="Normal")).sum()), "portscan_to_ddos_count":int(((y=="PortScan")&(pred=="DDoS")).sum()),
               "ddos_ground_truth_evaluated":False, "ddos_predictions_on_observed_validation":int((pred=="DDoS").sum())}
    by_session={}
    for session, truth in (("N-V1","Normal"),("P-V1","PortScan")):
        mask=sessions==session; count=int(mask.sum()); correct=int((pred[mask]==truth).sum())
        by_session[session]={"ground_truth_class":truth,"row_count":count,"correct_count":correct,"incorrect_count":count-correct,"recall_for_ground_truth_class":correct/count,"predicted_distribution":pd.Series(pred[mask]).value_counts().reindex(CLASSES,fill_value=0).astype(int).to_dict(),"probability_summary":probability_summary(proba,model_classes,mask)}
    details["session_results"]=by_session
    return details

def main() -> int:
    for p in (OUT,COMPARE):
        if p.exists(): raise FileExistsError(f"E6 create-new output exists: {p}")
    if sha256_file(CANDIDATE)!="6b01c7b3923c1a6bd471862d011f8f5b88a31378e51d1dde082bd2e72bedef86" or sha256_file(CANDIDATE_META)!="30b6bdf2a6cb2d60e2be36d4db1e124d71504393081b229e6d94da7e70322cbc": raise ValueError("candidate integrity mismatch")
    candidate_meta=json.loads(CANDIDATE_META.read_text()); e5=json.loads((ROOT/"reports/experiment_e/audit/e5_training_audit.json").read_text())
    if candidate_meta["status"]!="CANDIDATE / NOT_ACTIVE" or e5["verdict"]!="PASS": raise ValueError("E5 candidate not authorized")
    baseline_integrity=frozen_baseline()
    if not all(e["matches"] for e in baseline_integrity["entries"]): raise ValueError("RF-v2 frozen integrity mismatch")
    adapter=CICFlowMeterV3ModelAdapter.from_metadata(ROOT/"models/experiment_d/random_forest_rf_v2_runtime_metadata.json")
    frames=[]; labels=[]; sessions=[]; source_audit=[]
    for session,label,path,expected,rows in SOURCES:
        if not path.is_file() or sha256_file(path)!=expected: raise ValueError(f"validation source hash mismatch: {session}")
        raw=pd.read_csv(path)
        if len(raw)!=rows or raw.shape[1]!=84: raise ValueError(f"validation source schema/count mismatch: {session}")
        adapted=adapter.adapt(raw,raw_input_path=path,raw_input_sha256=expected)
        if list(adapted.features.columns)!=list(MODEL_FEATURES) or adapted.features.shape!=(rows,78): raise ValueError(f"adapter mismatch: {session}")
        frames.append(adapted.features); labels.extend([label]*rows); sessions.extend([session]*rows)
        source_audit.append({"session":session,"ground_truth_class":label,"path":str(path.relative_to(ROOT)),"sha256":expected,"raw_rows":rows,"raw_columns":84,"adapter_provenance":adapted.provenance})
    x=pd.concat(frames,ignore_index=True); y=np.asarray(labels); session_arr=np.asarray(sessions)
    if len(x)!=1518 or list(x.columns)!=list(MODEL_FEATURES): raise ValueError("combined validation identity mismatch")
    validate_feature_contract(MODEL_FEATURES)
    baseline=joblib.load(BASELINE); candidate=joblib.load(CANDIDATE)
    for m in (baseline,candidate):
        if m.n_features_in_!=78 or set(m.classes_)!=set(CLASSES): raise ValueError("model feature/class mismatch")
    r2,r3=evaluate(baseline,x,y,session_arr),evaluate(candidate,x,y,session_arr)
    delta={"overall_accuracy":r3["accuracy"]-r2["accuracy"],"portscan_recall":r3["observed_class_metrics"]["PortScan"]["recall"]-r2["observed_class_metrics"]["PortScan"]["recall"],"portscan_f1":r3["observed_class_metrics"]["PortScan"]["f1"]-r2["observed_class_metrics"]["PortScan"]["f1"],"normal_recall":r3["observed_class_metrics"]["Normal"]["recall"]-r2["observed_class_metrics"]["Normal"]["recall"],"normal_f1":r3["observed_class_metrics"]["Normal"]["f1"]-r2["observed_class_metrics"]["Normal"]["f1"],"normal_false_positive_as_portscan_change":r3["normal_false_positive_as_portscan_count"]-r2["normal_false_positive_as_portscan_count"],"portscan_false_negative_reduction":r2["portscan_false_negative_count"]-r3["portscan_false_negative_count"]}
    # Interpretation is a comparison to the frozen baseline, not an optimized post-hoc threshold.
    useful=delta["portscan_recall"]>0 and delta["normal_recall"]>=0
    verdict="PASS_WITH_DOCUMENTED_LIMITATION" if useful else "FAIL"
    seal=json.loads((ROOT/"reports/experiment_d/audit/final_test_leakage_audit.json").read_text())
    regression={"e1":validate_e1()["status"]=="PASS","e3":json.loads((ROOT/"reports/experiment_e/audit/e3_extraction_validation_final.json").read_text())["session_isolation"]["final_test_sessions_absent_and_unread"],"e4":json.loads((ROOT/"reports/experiment_e/audit/e4_dataset_construction_audit.json").read_text())["status"]=="PASS_WITH_DOCUMENTED_LIMITATION","e5":e5["verdict"]=="PASS","rf_v2_frozen":all(e["matches"] for e in baseline_integrity["entries"]),"candidate_hashes":True,"feature_contract_78":ordered_feature_identity(MODEL_FEATURES)==candidate_meta["feature_order_sha256"],"final_test_seal":seal["status"]=="PASS"}
    if not all(regression.values()): raise ValueError(f"post-evaluation integrity regression: {regression}")
    payload={"schema":"experiment_e_e6_offline_validation","status":verdict,"evaluated_at_utc":datetime.now(timezone.utc).isoformat(),"scope":"N-V1/P-V1 only; no final-test data read; no retraining, tuning, threshold change, or promotion.","integrity_gate":{"candidate_model_sha256":sha256_file(CANDIDATE),"candidate_metadata_sha256":sha256_file(CANDIDATE_META),"rf_v2_frozen_identity":baseline_integrity["path_independent_scientific_identity"],"sources":source_audit,"combined_rows":1518,"feature_order_exact":True},"labels":{"N-V1":"Normal","P-V1":"PortScan"},"rf_v2":r2,"rf_v3_candidate":r3,"deltas_rf_v3_minus_rf_v2":delta,"interpretation":{"scientific_question":"Runtime-like PortScan detection versus preserved Normal behavior","portscan_materially_better_than_baseline":delta["portscan_recall"]>0,"normal_recall_not_degraded":delta["normal_recall"]>=0,"e7_scientifically_authorized":useful},"limitations":["E6 does NOT validate DDoS recall: no new DDoS validation session exists.","DDoS predictions are counted for observed Normal/PortScan rows but are not DDoS performance evidence.","N-V1 has 17 rows; Normal conclusions have limited session/row coverage.","N-F1/P-F1 and Experiment D final-test remain sealed and unread."],"post_evaluation_regression":regression}
    comparison={"schema":"experiment_e_e6_rf_v2_vs_rf_v3_comparison","status":verdict,"rf_v2":r2,"rf_v3_candidate":r3,"deltas_rf_v3_minus_rf_v2":delta,"e7_scientifically_authorized":useful,"limitations":payload["limitations"]}
    write_new(OUT,payload); write_new(COMPARE,comparison)
    print(json.dumps({"verdict":verdict,"e7_authorized":useful,"deltas":delta}))
if __name__=="__main__": main()
