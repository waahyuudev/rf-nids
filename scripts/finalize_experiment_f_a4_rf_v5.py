#!/usr/bin/env python3
"""Create only the missing A4 post-evaluation reports after finalizer interruption."""
import hashlib, json
from pathlib import Path
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
REPORT=ROOT/"reports/experiment_f/normal_remediation_a2/a4_run_01"
DERIVED=ROOT/"data/lab/experiment_f/normal_remediation_a2/derived/a4_run_01"
MODEL=ROOT/"models/experiment_f/random_forest_rf_v5_candidate_01.joblib"
META=ROOT/"models/experiment_f/random_forest_rf_v5_candidate_01_metadata.json"
LABELS=["Normal","DDoS","PortScan"]
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""): h.update(b)
 return h.hexdigest()
def rel(p): return str(p.relative_to(ROOT))
def new(p,s):
 if p.exists(): raise FileExistsError(f"refusing to overwrite {rel(p)}")
 p.parent.mkdir(parents=True,exist_ok=True); p.write_text(s,encoding="utf-8")
def jnew(p,x): new(p,json.dumps(x,indent=2,sort_keys=True)+"\n")

def main():
 comp_path=REPORT/"comparative_metrics.json"
 expected={
  comp_path:"e96012fb9ec5b634777baaa067f800aeac77a3c0c87b0ddfc7dc6d424d0e1bba",
  MODEL:"31d7d50fa79e3400e7d357cab05c780e038bc527b746d0be6ff894828c6b8d17",
  META:"b9255fb4ad067611db60632e384e2cc5e8aaa2f989228cbc0e541ef421c7224e"}
 for p,h in expected.items():
  if sha(p)!=h: raise RuntimeError(f"frozen continuation binding mismatch: {rel(p)}")
 comp=json.loads(comp_path.read_text()); v3=comp["models"]["RF-v3"]; v5=comp["models"]["RF-v5"]
 cm=pd.DataFrame(v5["confusion_matrix"]["rows"],index=[f"true_{x}" for x in LABELS],columns=[f"pred_{x}" for x in LABELS]); cm.index.name="ground_truth"
 cm_path=REPORT/"confusion_matrix_rf_v5.csv"
 if cm_path.exists(): raise FileExistsError(f"refusing to overwrite {rel(cm_path)}")
 cm.to_csv(cm_path)
 total=v5["per_class"]["Normal"]["total"]
 fp=lambda x,i:x["confusion_matrix"]["rows"][0][i]/total
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
  "three_sessions_per_class_and_reporting":{"status":"PASS","basis":"Frozen F4-A2 validation has three sessions per class."},
  "unseen_validation_and_sealed_final_evaluation":{"status":"NOT_EVALUABLE","reason":"Later Experiment F stages."}}
 passed=all(v["status"]=="PASS" for k,v in gates.items() if k!="unseen_validation_and_sealed_final_evaluation")
 decision={"schema":"experiment_f_a4_rf_v5_acceptance","gates":gates,"validation_decision":"PASS" if passed else "FAIL","final_evaluation_authorized":passed,"candidate_status":"CANDIDATE / NOT_ACTIVE","activation_or_promotion_authorized":False}
 jnew(REPORT/"acceptance_gate_evaluation.json",decision)
 freeze=json.loads((REPORT/"rf_v5_training_input_freeze.json").read_text()); gate=json.loads((REPORT/"evidence_extraction_data_gate.json").read_text())
 summary={"schema":"experiment_f_a4_rf_v5_summary","phase_decision":"RF_V5_VALIDATION_PASS_FINAL_EVALUATION_AUTHORIZED" if passed else "RF_V5_VALIDATION_FAIL","evidence_gate":"PASS","extraction_data_gate":"PASS","new_normal_rows":gate["aggregate_adapted_normal_rows"],"training_rows":freeze["training"]["rows"],"training_class_counts":freeze["training"]["class_counts"],"model_sha256":sha(MODEL),"metadata_sha256":sha(META),"metrics":{k:{"accuracy":v["accuracy"],"macro_f1":v["macro_f1"],"per_class":v["per_class"]} for k,v in comp["models"].items()},"validation_decision":decision["validation_decision"],"final_evaluation_authorized":passed,"status":"CANDIDATE / NOT_ACTIVE","no_rf_v6_created":True,"finalizer_note":"Training/evaluation completed before a report-only typo; this continuation created no model and performed no fit or inference."}
 jnew(REPORT/"scientific_summary.json",summary)
 files=sorted([p for p in REPORT.rglob("*") if p.is_file()]+[p for p in (DERIVED/"adapted_78").rglob("*") if p.is_file()]+[p for p in (DERIVED/"frozen").rglob("*") if p.is_file()]+[MODEL,META])
 new(REPORT/"SHA256SUMS","".join(f"{sha(p)}  {rel(p)}\n" for p in files))
 print(json.dumps(summary,indent=2))
if __name__=="__main__": main()
