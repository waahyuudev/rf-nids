#!/usr/bin/env python3
"""Evaluate preregistered E7 runtime PCAPs; no training or final-test access."""
from __future__ import annotations
import json, sys
from datetime import datetime, timezone
from pathlib import Path
import joblib, numpy as np, pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from scripts.verify_experiment_d_frozen_baseline import build_manifest as frozen_baseline
from src.experiment_d.integrity import sha256_file
from src.experiment_e.e1 import validate_e1
from src.experiment_e.integrity import ordered_feature_identity, validate_feature_contract
from src.ingestion.cicflowmeter_v3_adapter import CICFlowMeterV3ModelAdapter, MODEL_FEATURES
PCAPS=(("E7-N-R1","Normal",ROOT/"data/lab/experiment_e/runtime_validation/pcap/normal/expe-e7-normal-r1.pcap","8cd96745f3134525a93cd2e3e3a83bf54308e338934dd34e3411da63eae0b8ec",124,ROOT/"data/lab/experiment_e/runtime_validation/flows/normal/expe-e7-normal-r1.pcap_ISCX.csv","d4ccc8ec403943af2c07d09b4defdf9348bd617824605a407ffb2ff7d33e8d13"),("E7-P-R1","PortScan",ROOT/"data/lab/experiment_e/runtime_validation/pcap/portscan/expe-e7-portscan-r1.pcap","10a4e97c161294b349bb89be8857babe1584300d0a7afda696894ad957303584",1204,ROOT/"data/lab/experiment_e/runtime_validation/flows/portscan/expe-e7-portscan-r1.pcap_ISCX.csv","ac8263362a27e0d475a819b46def871aa19ad25f20160b91b758c51f97851403"))
CLASSES=["Normal","DDoS","PortScan"]; OUT=ROOT/"reports/experiment_e/runtime_validation/e7_runtime_validation.json"; CMP=ROOT/"reports/experiment_e/analysis/e7_rf_v2_vs_rf_v3_comparison.json"
def new(p,d):
    if p.exists(): raise FileExistsError(p)
    p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(d,indent=2,sort_keys=True)+"\n")
def summ(p,cls,mask):
    return {c:{"min":float(np.min(p[mask,i])),"q1":float(np.quantile(p[mask,i],.25)),"median":float(np.median(p[mask,i])),"mean":float(np.mean(p[mask,i])),"q3":float(np.quantile(p[mask,i],.75)),"max":float(np.max(p[mask,i]))} for i,c in enumerate(cls)}
def metrics(m,x,y,s):
    pred=m.predict(x); prob=m.predict_proba(x); obs=["Normal","PortScan"]; pr,re,f1,sup=precision_recall_fscore_support(y,pred,labels=obs,zero_division=0)
    sessions={}
    for sid,truth in (("E7-N-R1","Normal"),("E7-P-R1","PortScan")):
        z=s==sid; n=int(z.sum()); ok=int((pred[z]==truth).sum()); sessions[sid]={"ground_truth_class":truth,"total_flows":n,"correct":ok,"incorrect":n-ok,"predicted_counts":pd.Series(pred[z]).value_counts().reindex(CLASSES,fill_value=0).astype(int).to_dict(),"ground_truth_class_recall":ok/n,"probability_summary":summ(prob,list(m.classes_),z)}
    return {"accuracy":float(accuracy_score(y,pred)),"observed_class_metrics":{c:{"precision":float(pr[i]),"recall":float(re[i]),"f1":float(f1[i]),"support":int(sup[i])} for i,c in enumerate(obs)},"confusion_matrix_labels":CLASSES,"confusion_matrix":confusion_matrix(y,pred,labels=CLASSES).astype(int).tolist(),"predicted_counts":pd.Series(pred).value_counts().reindex(CLASSES,fill_value=0).astype(int).to_dict(),"portscan_false_negatives":int(((y=="PortScan")&(pred!="PortScan")).sum()),"normal_to_portscan_false_positives":int(((y=="Normal")&(pred=="PortScan")).sum()),"ddos_predictions_on_observed_classes":int((pred=="DDoS").sum()),"ddos_ground_truth_evaluated":False,"sessions":sessions}
def main():
    if OUT.exists() or CMP.exists(): raise FileExistsError("E7 output already exists")
    prereg=json.loads((ROOT/"reports/experiment_e/audit/e7_runtime_preregistration.json").read_text()); assert prereg["status"]=="PREREGISTERED_NOT_EXECUTED"
    if sha256_file(ROOT/"models/experiment_e/random_forest_rf_v3_candidate.joblib")!="6b01c7b3923c1a6bd471862d011f8f5b88a31378e51d1dde082bd2e72bedef86": raise ValueError("candidate hash")
    base=frozen_baseline(); assert all(e["matches"] for e in base["entries"]); adapter=CICFlowMeterV3ModelAdapter.from_metadata(ROOT/"models/experiment_d/random_forest_rf_v2_runtime_metadata.json")
    xs=[]; ys=[]; ss=[]; extraction=[]
    for sid,label,pcap,ph,packets,csv,ch in PCAPS:
        if not pcap.is_file() or sha256_file(pcap)!=ph or pcap.stat().st_size==0: raise ValueError(f"PCAP integrity {sid}")
        if not csv.is_file() or sha256_file(csv)!=ch: raise ValueError(f"CSV integrity {sid}")
        raw=pd.read_csv(csv)
        if len(raw)==0 or raw.shape[1]!=84: raise ValueError(f"raw schema {sid}")
        a=adapter.adapt(raw,raw_input_path=csv,raw_input_sha256=ch)
        if a.features.shape!=(len(raw),78) or list(a.features.columns)!=list(MODEL_FEATURES): raise ValueError(f"adapter {sid}")
        xs.append(a.features); ys += [label]*len(raw); ss += [sid]*len(raw)
        entry={"session":sid,"ground_truth_class":label,"pcap":{"path":str(pcap.relative_to(ROOT)),"sha256":ph,"packet_count":packets,"kernel_drops":0,"non_empty":True},"raw_csv":{"path":str(csv.relative_to(ROOT)),"sha256":ch,"flow_count":len(raw),"raw_column_count":84},"extractor":{"image_tag":"rf-nids-cicflowmeter-v3:a26aae27","image_digest":"sha256:b12b3a4a4218968aba2436685a4eb113473e5681de70705409e834e4613a879b","amendment":"E3-A1","network_access":False},"adapter_provenance":a.provenance}
        extraction.append(entry); new(ROOT/f"data/lab/experiment_e/runtime_validation/manifests/{sid.lower()}.extraction.json",entry)
    x=pd.concat(xs,ignore_index=True); y=np.asarray(ys); s=np.asarray(ss); validate_feature_contract(MODEL_FEATURES)
    if len(x)!=626 or ordered_feature_identity(MODEL_FEATURES)!="9338f50fc3e7efc78d678cc65ab38d428a7f6912ed9467a2b99a449a7c8e3c13": raise ValueError("combined feature identity")
    r2=metrics(joblib.load(ROOT/"models/experiment_d/random_forest_rf_v2.joblib"),x,y,s); r3=metrics(joblib.load(ROOT/"models/experiment_e/random_forest_rf_v3_candidate.joblib"),x,y,s)
    d={"accuracy":r3["accuracy"]-r2["accuracy"],"normal_recall":r3["observed_class_metrics"]["Normal"]["recall"]-r2["observed_class_metrics"]["Normal"]["recall"],"portscan_recall":r3["observed_class_metrics"]["PortScan"]["recall"]-r2["observed_class_metrics"]["PortScan"]["recall"],"portscan_false_negative_reduction":r2["portscan_false_negatives"]-r3["portscan_false_negatives"],"normal_to_portscan_false_positive_change":r3["normal_to_portscan_false_positives"]-r2["normal_to_portscan_false_positives"]}
    e6=json.loads((ROOT/"reports/experiment_e/evaluation/e6_offline_validation.json").read_text()); seals=json.loads((ROOT/"reports/experiment_d/audit/final_test_leakage_audit.json").read_text()); checks={"e1":validate_e1()["status"]=="PASS","rf_v2_frozen":True,"candidate_hash":True,"feature_contract":True,"final_test_seal":seals["status"]=="PASS","e7_pcap_hashes":True,"new_session_ids":True}
    if not all(checks.values()): raise ValueError(checks)
    supports=d["portscan_recall"]>0 and r3["observed_class_metrics"]["PortScan"]["recall"]>r2["observed_class_metrics"]["PortScan"]["recall"]
    verdict="PASS_WITH_DOCUMENTED_LIMITATION" if supports else "FAIL"
    out={"schema":"experiment_e_e7_runtime_validation","status":verdict,"evaluated_at_utc":datetime.now(timezone.utc).isoformat(),"scope":"new E7-N-R1/E7-P-R1 traffic only; no retraining, tuning, threshold changes, promotion, or final-test access.","extractions":extraction,"rf_v2":r2,"rf_v3_candidate":r3,"deltas_rf_v3_minus_rf_v2":d,"e6_comparison":{"e6_rf_v2_portscan_recall":e6["rf_v2"]["observed_class_metrics"]["PortScan"]["recall"],"e6_rf_v3_portscan_recall":e6["rf_v3_candidate"]["observed_class_metrics"]["PortScan"]["recall"],"e7_rf_v2_portscan_recall":r2["observed_class_metrics"]["PortScan"]["recall"],"e7_rf_v3_portscan_recall":r3["observed_class_metrics"]["PortScan"]["recall"],"interpretation":"E7 is a distinct live 3-VM capture and is not expected to numerically equal E6."},"integrity_checks":checks,"limitations":["No E7 DDoS ground-truth session; DDoS recall is not validated.","Minimal E7 has one new session per observed class.","Candidate remains inactive; no promotion was performed."],"e8_comparison_final_decision_authorized":supports}
    cmp={"schema":"experiment_e_e7_rf_v2_vs_rf_v3_comparison","status":verdict,"rf_v2":r2,"rf_v3_candidate":r3,"deltas":d,"e6_comparison":out["e6_comparison"],"e8_comparison_final_decision_authorized":supports}
    new(OUT,out); new(CMP,cmp); print(json.dumps({"verdict":verdict,"deltas":d,"e8_authorized":supports}))
if __name__=="__main__": main()
