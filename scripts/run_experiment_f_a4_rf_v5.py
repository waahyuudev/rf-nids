#!/usr/bin/env python3
"""Run fail-closed A4 adaptation, sole RF-v5 candidate training, and validation."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.ingestion.cicflowmeter_v3_adapter import CICFlowMeterV3ModelAdapter, CROSSWALK_SHA256, MODEL_FEATURES  # noqa: E402

SESSIONS = ["F-A1-NORMAL-A2-01", "F-A1-NORMAL-A2-02", "F-A1-NORMAL-A2-03"]
LABELS = ["Normal", "DDoS", "PortScan"]
FEATURE_SHA = "9338f50fc3e7efc78d678cc65ab38d428a7f6912ed9467a2b99a449a7c8e3c13"
IMAGE_SHA = "sha256:b12b3a4a4218968aba2436685a4eb113473e5681de70705409e834e4613a879b"
COMMIT = "a26aae27f21d165ff30b4b28e75124a5f9b4b2c4"
RAW = ROOT / "data/lab/experiment_f/normal_remediation_a2/raw"
DERIVED = ROOT / "data/lab/experiment_f/normal_remediation_a2/derived/a4_run_01"
CFM = DERIVED / "raw_cicflowmeter"
ADAPTED = DERIVED / "adapted_78"
FROZEN = DERIVED / "frozen"
REPORT = ROOT / "reports/experiment_f/normal_remediation_a2/a4_run_01"
V4_DATA = ROOT / "data/lab/experiment_f/datasets/rf_v4_candidate_01_training.csv"
V4_LINEAGE = ROOT / "data/lab/experiment_f/datasets/rf_v4_candidate_01_training_lineage.csv"
VALIDATION = ROOT / "data/lab/experiment_f/validation/derived/f4_a2_run_03/frozen/f_validation_78_features_ground_truth.csv"
VALIDATION_LINEAGE = ROOT / "data/lab/experiment_f/validation/derived/f4_a2_run_03/frozen/f_validation_lineage.csv"
TRAINING = FROZEN / "rf_v5_candidate_01_training.csv"
TRAINING_LINEAGE = FROZEN / "rf_v5_candidate_01_training_lineage.csv"
MODEL = ROOT / "models/experiment_f/random_forest_rf_v5_candidate_01.joblib"
META = ROOT / "models/experiment_f/random_forest_rf_v5_candidate_01_metadata.json"
MODELS = {
    "RF-v3": (ROOT / "models/experiment_e/random_forest_rf_v3_candidate.joblib", "6b01c7b3923c1a6bd471862d011f8f5b88a31378e51d1dde082bd2e72bedef86"),
    "RF-v4": (ROOT / "models/experiment_f/random_forest_rf_v4_candidate_01.joblib", "d5dccd339a5c67635e760d7d3760e1d006278362c6f70ea06bf20928ccdece13"),
}
EXPECTED = {
    "v4_data": "a65c812494917b2e6d18153b784fd0505b84229f86b6a6916c59fa1187bd778d",
    "v4_lineage": "1ee2fdad6a9cb4321f6a85beb003e2eb2596518ddd9b54a7a9f151b1c65f4283",
    "validation": "d5dbc3e6a6de373526c46bb7220092c14e81779ec91ebfe5ef855db7f7d53d0e",
    "validation_lineage": "8c2697841de6df5d66e22836eee100cf53de08935f1832f265130a9a2419c909",
    "v4_meta": "9f8bb215740943b326b6ec6f76e55caef4d094290ac43ed30cb7e32884a47a1a",
    "amendment": "1ea33436455fb15c8a377be3db618626c252a7e1340239b33c6c796984f68d6c",
}

def sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""): h.update(b)
    return h.hexdigest()

def rel(p: Path) -> str: return str(p.relative_to(ROOT))
def text(p: Path) -> str: return p.read_text(encoding="utf-8").strip()
def dt(v: str) -> datetime: return datetime.fromisoformat(v.replace("Z", "+00:00"))
def require(ok: bool, message: str) -> None:
    if not ok: raise RuntimeError(f"A4_BLOCKED: {message}")
def write_new(p: Path, value: str) -> None:
    if p.exists(): raise FileExistsError(f"refusing to overwrite {rel(p)}")
    p.parent.mkdir(parents=True, exist_ok=True); p.write_text(value, encoding="utf-8")
def json_new(p: Path, value: object) -> None: write_new(p, json.dumps(value, indent=2, sort_keys=True) + "\n")
def csv_new(p: Path, frame: pd.DataFrame) -> None:
    if p.exists(): raise FileExistsError(f"refusing to overwrite {rel(p)}")
    p.parent.mkdir(parents=True, exist_ok=True); frame.to_csv(p, index=False)
def feature_sha() -> str:
    return hashlib.sha256(json.dumps(list(MODEL_FEATURES), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def metrics(y: np.ndarray, pred: np.ndarray) -> dict:
    p, r, f, s = precision_recall_fscore_support(y, pred, labels=LABELS, zero_division=0)
    macro = precision_recall_fscore_support(y, pred, labels=LABELS, average="macro", zero_division=0)
    cm = confusion_matrix(y, pred, labels=LABELS)
    return {"accuracy": float(accuracy_score(y, pred)), "macro_precision": float(macro[0]), "macro_recall": float(macro[1]), "macro_f1": float(macro[2]),
            "per_class": {c: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]), "support": int(s[i]), "correct": int(cm[i,i]), "total": int(s[i])} for i,c in enumerate(LABELS)},
            "confusion_matrix": {"labels": LABELS, "rows": cm.tolist()}}

def main() -> int:
    require(not any(p.exists() for p in (ADAPTED, FROZEN, REPORT, MODEL, META)), "create-new output already exists")
    bindings = [(V4_DATA,"v4_data"),(V4_LINEAGE,"v4_lineage"),(VALIDATION,"validation"),(VALIDATION_LINEAGE,"validation_lineage"),
                (ROOT/"models/experiment_f/random_forest_rf_v4_candidate_01_metadata.json","v4_meta"),
                (ROOT/"reports/experiment_f/amendments/f0_normal_remediation_amendment_a4.json","amendment")]
    for p,k in bindings: require(sha(p) == EXPECTED[k], f"frozen binding mismatch: {rel(p)}")
    require(sha(ROOT/"reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv") == CROSSWALK_SHA256, "crosswalk mismatch")
    require(feature_sha() == FEATURE_SHA, "feature identity mismatch")
    for name,(p,h) in MODELS.items(): require(sha(p)==h, f"{name} hash mismatch")
    for side in ("observer","generator"):
        require({p.name for p in (RAW/side).iterdir() if p.is_dir()} == set(SESSIONS), f"{side} session set mismatch")

    evidence=[]; intervals=[]; pcap_hashes=[]; adapted=[]; new_lineage=[]
    adapter=CICFlowMeterV3ModelAdapter()
    for session in SESSIONS:
        o=RAW/"observer"/session; g=RAW/"generator"/session; pcap=o/f"{session}.pcap"
        required_o=[pcap,o/"PCAP_SHA256SUM",o/"capture_started_utc.txt",o/"capture_ended_utc.txt",o/"tcpdump_exit_status.txt",o/"tcpdump.stderr.log",o/"capture_interface.txt",o/"capture_filter.txt"]
        require(all(p.is_file() for p in required_o), f"{session} observer evidence incomplete")
        ph=sha(pcap); require(ph==text(o/"PCAP_SHA256SUM").split()[0], f"{session} PCAP hash mismatch")
        log=text(o/"tcpdump.stderr.log"); nums=[]
        for pat in (r"(\d+) packets captured",r"(\d+) packets received by filter",r"(\d+) packets dropped by kernel"):
            m=re.search(pat,log); require(m is not None,f"{session} packet counters incomplete"); nums.append(int(m.group(1)))
        cs,ce=text(o/"capture_started_utc.txt"),text(o/"capture_ended_utc.txt")
        require(text(o/"tcpdump_exit_status.txt")=="0" and text(o/"capture_interface.txt")=="enp0s3" and text(o/"capture_filter.txt")=="host 10.10.20.2 and tcp port 8080",f"{session} capture identity/status mismatch")
        require(nums[0]>0 and nums[0]==nums[1] and nums[2]==0,f"{session} packet/drop gate failed")
        required_g=[g/"generator_started_utc.txt",g/"generator_ended_utc.txt",g/"generator_exit_status.txt",g/"profile_id.txt",g/"target_url.txt",g/"requests.csv"]
        require(all(p.is_file() for p in required_g),f"{session} generator evidence incomplete")
        gs,ge=text(g/"generator_started_utc.txt"),text(g/"generator_ended_utc.txt")
        require(text(g/"generator_exit_status.txt")=="0" and text(g/"profile_id.txt")=="F-A1-NORMAL-A2-PROFILE-01" and text(g/"target_url.txt")=="http://10.10.20.2:8080/",f"{session} generator identity/status mismatch")
        rows=list(csv.reader((g/"requests.csv").open(encoding="utf-8")))
        require(len(rows)==100 and [int(r[0]) for r in rows]==list(range(1,101)) and all(int(r[2])==0 for r in rows),f"{session} request log mismatch")
        for n in range(1,101):
            require((g/f"request_{n}.stderr").is_file() and (g/f"request_{n}.stderr").stat().st_size==0 and text(g/f"request_{n}.result").split(",",1)[0]=="200",f"{session} request {n} failed")
        require(dt(cs)<=dt(gs)<=dt(ge)<=dt(ce),f"{session} generator window outside capture")
        intervals.append((session,dt(cs),dt(ce))); pcap_hashes.append(ph)
        raw=CFM/session/f"{session}.pcap_ISCX.csv"; require(raw.is_file(),f"{session} extraction missing")
        frame=pd.read_csv(raw); require(frame.shape[0]>0 and frame.shape[1]==84,f"{session} raw extraction schema failed")
        result=adapter.adapt(frame,raw_input_path=Path(rel(raw)),raw_input_sha256=sha(raw)); ap=ADAPTED/f"{session}_model_input_78.csv"; csv_new(ap,result.features)
        arr=result.features.to_numpy(dtype=float); require(np.isinf(arr).sum()==0,f"{session} adapted Inf")
        evidence.append({"session_id":session,"decision":"PASS","capture":{"start_utc":cs,"end_utc":ce,"interface":"enp0s3","filter":"host 10.10.20.2 and tcp port 8080","exit_status":0,"packets_captured":nums[0],"packets_received":nums[1],"kernel_drops":nums[2],"pcap":rel(pcap),"pcap_sha256":ph},
            "generator":{"start_utc":gs,"end_utc":ge,"exit_status":0,"profile_id":"F-A1-NORMAL-A2-PROFILE-01","requests":100,"http_200":100},
            "raw":{"path":rel(raw),"sha256":sha(raw),"rows":len(frame),"columns":len(frame.columns)},
            "adapted":{"path":rel(ap),"sha256":sha(ap),"rows":len(result.features),"columns":78,"nan_count":int(np.isnan(arr).sum()),"inf_count":0,"duplicate_feature_vectors":int(result.features.duplicated().sum()),"feature_order_sha256":feature_sha(),"provenance":result.provenance}})
        labeled=result.features.copy(); labeled["ground_truth_class"]="Normal"; adapted.append(labeled)
        flow=frame["Flow ID"].astype(str) if "Flow ID" in frame else pd.Series([None]*len(frame))
        for idx,fid in enumerate(flow): new_lineage.append({"ground_truth_class":"Normal","origin_group":"EXPERIMENT_F_A4_NORMAL_REMEDIATION","source_experiment":"EXPERIMENT_F","source_role":"F-ADAPTATION-NORMAL-A2","source_session_id":session,"source_capture_id":session,"source_row_index":idx,"source_row_identity":fid,"adapted_artifact":rel(ap),"adapted_artifact_sha256":sha(ap),"historical_source_csv":"NOT_APPLICABLE","historical_source_csv_sha256":"NOT_APPLICABLE","raw_extraction":rel(raw),"raw_extraction_sha256":sha(raw),"pcap":rel(pcap),"pcap_sha256":ph,"transformation":"approved CICFlowMeter V3 -> frozen ordered 78-feature adapter; no imputation"})
    require(len(set(pcap_hashes))==3,"PCAP hash reuse")
    for i,(a,astart,aend) in enumerate(intervals):
        for b,bstart,bend in intervals[i+1:]: require(max(astart,bstart)>min(aend,bend),f"capture overlap {a}/{b}")

    new_data=pd.concat(adapted,ignore_index=True); require(len(new_data)>94,"aggregate adapted Normal rows not >94")
    remediation=FROZEN/"a4_normal_remediation_adaptation.csv"; remediation_lineage=FROZEN/"a4_normal_remediation_lineage.csv"
    csv_new(remediation,new_data); nl=pd.DataFrame(new_lineage); nl.insert(0,"candidate_row_index",np.arange(6698,6698+len(nl))); csv_new(remediation_lineage,nl)
    gate={"schema":"experiment_f_a4_extraction_data_gate","evidence_gate":"PASS","extraction_gate":"PASS","data_gate":"PASS","sessions":evidence,"aggregate_adapted_normal_rows":len(new_data),"required":">94","extractor":{"commit":COMMIT,"image_digest":IMAGE_SHA,"network_access":False},"feature_contract":{"count":78,"feature_order_sha256":feature_sha(),"crosswalk_sha256":CROSSWALK_SHA256},"deduplication_performed":False,"rows_dropped":0}
    json_new(REPORT/"evidence_extraction_data_gate.json",gate)

    base=pd.read_csv(V4_DATA,low_memory=False); base_lin=pd.read_csv(V4_LINEAGE,low_memory=False)
    require(base.shape==(6698,79) and list(base.columns)==[*MODEL_FEATURES,"ground_truth_class"],"RF-v4 base dataset mismatch")
    combined=pd.concat([base,new_data],ignore_index=True); require(len(combined)==6698+len(new_data),"training append cardinality mismatch")
    lineage=pd.concat([base_lin,nl[base_lin.columns]],ignore_index=True); require(len(lineage)==len(combined),"training lineage cardinality mismatch")
    csv_new(TRAINING,combined); csv_new(TRAINING_LINEAGE,lineage)
    counts=combined.ground_truth_class.value_counts().to_dict(); require(counts=={"DDoS":4023,"PortScan":2581,"Normal":94+len(new_data)},"training class counts mismatch")
    freeze={"schema":"experiment_f_a4_rf_v5_training_freeze","decision":"RF_V5_TRAINING_INPUT_FROZEN","base":{"path":rel(V4_DATA),"sha256":sha(V4_DATA),"rows":6698},"appended":{"path":rel(remediation),"sha256":sha(remediation),"rows":len(new_data),"class":"Normal","sessions":SESSIONS},"training":{"path":rel(TRAINING),"sha256":sha(TRAINING),"rows":len(combined),"columns":79,"class_counts":counts},"lineage":{"path":rel(TRAINING_LINEAGE),"sha256":sha(TRAINING_LINEAGE),"rows":len(lineage)},"validation_rows_used":False,"deduplication_performed":False,"other_rows_added_or_removed":False}
    json_new(REPORT/"rf_v5_training_input_freeze.json",freeze)

    v4meta=json.loads((ROOT/"models/experiment_f/random_forest_rf_v4_candidate_01_metadata.json").read_text()); params=v4meta["rf_parameters"]
    require(params["random_state"]==42 and params["n_estimators"]==200 and params["class_weight"]=="balanced", "RF-v4 params mismatch")
    X=combined.loc[:,list(MODEL_FEATURES)].replace([np.inf,-np.inf],np.nan).astype(np.float32); y=combined.ground_truth_class.astype(str)
    candidate=RandomForestClassifier(**params); candidate.fit(X,y)
    repeat=RandomForestClassifier(**params); repeat.fit(X,y)
    probe=X.iloc[np.arange(0,len(X),97,dtype=int)]
    require(np.array_equal(candidate.predict(probe),repeat.predict(probe)) and np.allclose(candidate.predict_proba(probe),repeat.predict_proba(probe),rtol=0,atol=1e-15),"repeat-fit reproducibility failed")
    MODEL.parent.mkdir(parents=True,exist_ok=True)
    with MODEL.open("xb") as f: joblib.dump(candidate,f,compress=3)
    reloaded=joblib.load(MODEL); require(np.array_equal(candidate.predict(probe),reloaded.predict(probe)),"reload mismatch")
    meta={"schema":"experiment_f_rf_v5_candidate_metadata","version":"rf-v5-candidate-01","model_id":"rf-v5-candidate-01","status":"CANDIDATE / NOT_ACTIVE","active":False,"parent_model":"rf-v4.0-candidate-01","model_path":rel(MODEL),"model_sha256":sha(MODEL),"training_dataset":freeze["training"],"training_lineage":freeze["lineage"],"feature_count":78,"feature_names":list(MODEL_FEATURES),"feature_order_sha256":feature_sha(),"crosswalk_sha256":CROSSWALK_SHA256,"estimator_classes":list(candidate.classes_),"rf_parameters":params,"preprocessing":v4meta["preprocessing"],"training":{"candidate_count":1,"repeat_fit_diagnostic_persisted":False,"hyperparameter_tuning":False,"threshold_change":False,"validation_data_used":False},"scientific_scope":"Normal remediation under prospective Experiment F Amendment A4; no activation or promotion."}
    json_new(META,meta)
    training_audit={"schema":"experiment_f_a4_rf_v5_training_audit","decision":"RF_V5_CANDIDATE_TRAINING_PASS","candidate":{"path":rel(MODEL),"sha256":sha(MODEL),"metadata":rel(META),"metadata_sha256":sha(META),"status":"CANDIDATE / NOT_ACTIVE"},"training_dataset":freeze["training"],"class_counts":counts,"same_rf_v4_parameters":True,"same_preprocessing":True,"candidate_count":1,"validation_data_used":False,"activation":False,"promotion":False}
    json_new(REPORT/"rf_v5_training_audit.json",training_audit)

    val=pd.read_csv(VALIDATION); vlin=pd.read_csv(VALIDATION_LINEAGE); require(val.shape==(5999,79) and len(vlin)==5999,"validation shape mismatch")
    VX=val.loc[:,list(MODEL_FEATURES)]; vy=val.ground_truth_class.to_numpy(); results={}; predictions={}
    compare={**MODELS,"RF-v5":(MODEL,sha(MODEL))}
    for name,(path,expected) in compare.items():
        require(sha(path)==expected,f"{name} pre-inference hash mismatch"); model=joblib.load(path); classes=[str(c) for c in model.classes_]
        pred=np.asarray(model.predict(VX)); prob=model.predict_proba(VX); predictions[name]=pred
        out=pd.DataFrame({"row_id":np.arange(len(vy)),"session_id":vlin.session_id,"ground_truth_class":vy,"predicted_class":pred,"model_id":name})
        for c in LABELS: out[f"probability_{c}"]=prob[:,classes.index(c)]
        pp=REPORT/f"predictions_{name.lower().replace('-','_')}.csv"; csv_new(pp,out); results[name]=metrics(vy,pred); results[name]["model_sha256"]=expected; results[name]["predictions_sha256"]=sha(pp)
    trans={}
    for left,right in (("RF-v3","RF-v4"),("RF-v4","RF-v5"),("RF-v3","RF-v5")):
        c=Counter(zip(predictions[left],predictions[right])); trans[f"{left}->{right}"]={f"{a}->{b}":int(c[(a,b)]) for a in LABELS for b in LABELS}
    comp={"schema":"experiment_f_a4_rf_v5_comparative_metrics","validation":{"path":rel(VALIDATION),"sha256":sha(VALIDATION),"lineage_sha256":sha(VALIDATION_LINEAGE),"rows":5999,"unchanged":True},"models":results,"transitions":trans}
    json_new(REPORT/"comparative_metrics.json",comp)
    cm=pd.DataFrame(results["RF-v5"]["confusion_matrix"]["rows"],index=[f"true_{x}" for x in LABELS],columns=[f"pred_{x}" for x in LABELS]); cm.index.name="ground_truth"; cm_path=REPORT/"confusion_matrix_rf_v5.csv"; cm_path.parent.mkdir(parents=True,exist_ok=True); cm.to_csv(cm_path)

    v3,v5=results["RF-v3"],results["RF-v5"]; total=v5["per_class"]["Normal"]["total"]
    fp=lambda x,j:x["confusion_matrix"]["rows"][0][j]/total
    gates={
      "normal_recall_absolute":{"status":"PASS" if v5["per_class"]["Normal"]["recall"]>=.98 else "FAIL","actual":v5["per_class"]["Normal"]["recall"],"threshold":">=0.98"},
      "normal_recall_vs_rf_v3":{"status":"PASS" if v5["per_class"]["Normal"]["recall"]>=v3["per_class"]["Normal"]["recall"]-.02 else "FAIL","delta":v5["per_class"]["Normal"]["recall"]-v3["per_class"]["Normal"]["recall"],"threshold":">=-0.02"},
      "portscan_recall_absolute":{"status":"PASS" if v5["per_class"]["PortScan"]["recall"]>=.995 else "FAIL","actual":v5["per_class"]["PortScan"]["recall"],"threshold":">=0.995"},
      "portscan_recall_vs_rf_v3":{"status":"PASS" if v5["per_class"]["PortScan"]["recall"]>=v3["per_class"]["PortScan"]["recall"]-.005 else "FAIL","delta":v5["per_class"]["PortScan"]["recall"]-v3["per_class"]["PortScan"]["recall"],"threshold":">=-0.005"},
      "ddos_recall_absolute":{"status":"PASS" if v5["per_class"]["DDoS"]["recall"]>=.20 else "FAIL","actual":v5["per_class"]["DDoS"]["recall"],"threshold":">=0.20"},
      "ddos_recall_vs_rf_v3":{"status":"PASS" if v5["per_class"]["DDoS"]["recall"]>=v3["per_class"]["DDoS"]["recall"]+.10 else "FAIL","delta":v5["per_class"]["DDoS"]["recall"]-v3["per_class"]["DDoS"]["recall"],"threshold":">=+0.10"},
      "ddos_f1_vs_rf_v3":{"status":"PASS" if v5["per_class"]["DDoS"]["f1"]>=v3["per_class"]["DDoS"]["f1"]+.10 else "FAIL","delta":v5["per_class"]["DDoS"]["f1"]-v3["per_class"]["DDoS"]["f1"],"threshold":">=+0.10"},
      "normal_f1_preservation":{"status":"PASS" if v5["per_class"]["Normal"]["f1"]>=.98*v3["per_class"]["Normal"]["f1"] else "FAIL","ratio":v5["per_class"]["Normal"]["f1"]/v3["per_class"]["Normal"]["f1"],"threshold":">=0.98 of RF-v3"},
      "portscan_f1_preservation":{"status":"PASS" if v5["per_class"]["PortScan"]["f1"]>=.98*v3["per_class"]["PortScan"]["f1"] else "FAIL","ratio":v5["per_class"]["PortScan"]["f1"]/v3["per_class"]["PortScan"]["f1"],"threshold":">=0.98 of RF-v3"},
      "normal_to_ddos_false_positive":{"status":"PASS" if fp(v5,1)-fp(v3,1)<=.02 else "FAIL","rf_v3":fp(v3,1),"rf_v5":fp(v5,1),"delta":fp(v5,1)-fp(v3,1),"threshold":"increase <=0.02"},
      "normal_to_portscan_false_positive":{"status":"PASS" if fp(v5,2)-fp(v3,2)<=.02 else "FAIL","rf_v3":fp(v3,2),"rf_v5":fp(v5,2),"delta":fp(v5,2)-fp(v3,2),"threshold":"increase <=0.02"},
      "macro_f1":{"status":"PASS" if v5["macro_f1"]>=v3["macro_f1"]-.02 else "FAIL","actual":v5["macro_f1"],"rf_v3":v3["macro_f1"],"delta":v5["macro_f1"]-v3["macro_f1"],"threshold":">=RF-v3-0.02"},
      "three_sessions_per_class_and_reporting":{"status":"PASS","basis":"Frozen F4-A2 validation has three sessions per class and aggregate/session evidence remains frozen."},
      "unseen_validation_and_sealed_final_evaluation":{"status":"NOT_EVALUABLE","reason":"Later Experiment F stages."}}
    passed=all(v["status"]=="PASS" for k,v in gates.items() if k!="unseen_validation_and_sealed_final_evaluation")
    decision={"schema":"experiment_f_a4_rf_v5_acceptance","gates":gates,"validation_decision":"PASS" if passed else "FAIL","final_evaluation_authorized":passed,"candidate_status":"CANDIDATE / NOT_ACTIVE","activation_or_promotion_authorized":False}
    json_new(REPORT/"acceptance_gate_evaluation.json",decision)
    summary={"schema":"experiment_f_a4_rf_v5_summary","phase_decision":"RF_V5_VALIDATION_PASS_FINAL_EVALUATION_AUTHORIZED" if passed else "RF_V5_VALIDATION_FAIL","evidence_gate":"PASS","extraction_data_gate":"PASS","new_normal_rows":len(new_data),"training_rows":len(combined),"training_class_counts":counts,"model_sha256":sha(MODEL),"metadata_sha256":sha(META),"metrics":{k:{"accuracy":v["accuracy"],"macro_f1":v["macro_f1"],"per_class":v["per_class"]} for k,v in results.items()},"validation_decision":decision["validation_decision"],"final_evaluation_authorized":passed,"status":"CANDIDATE / NOT_ACTIVE","no_rf_v6_created":True}
    json_new(REPORT/"scientific_summary.json",summary)
    files=sorted([p for p in REPORT.rglob("*") if p.is_file()]+[p for p in ADAPTED.rglob("*") if p.is_file()]+[p for p in FROZEN.rglob("*") if p.is_file()]+[MODEL,META])
    write_new(REPORT/"SHA256SUMS","".join(f"{sha(p)}  {rel(p)}\n" for p in files))
    print(json.dumps(summary,indent=2)); return 0

if __name__ == "__main__": raise SystemExit(main())
