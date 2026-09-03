#!/usr/bin/env python3
"""Run the fail-closed, one-shot Experiment D D6 blind final evaluation."""

from __future__ import annotations

import argparse, csv, json, platform, subprocess, sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

from scripts.verify_experiment_d_frozen_baseline import build_manifest as verify_rf_v1_baseline
from src.common.config import PROJECT_ROOT
from src.experiment_d.d5 import canonical_identity, verify_frozen_manifest
from src.experiment_d.integrity import sha256_file
from src.experiment_d.manifest import load_manifest, verify_manifest_files
from src.ingestion.cicflowmeter_v3_adapter import (ADAPTER_IDENTITY, ADAPTER_VERSION,
    CICFLOWMETER_V3_COMMIT, CICFLOWMETER_V3_IMAGE_DIGEST, CROSSWALK_PATH,
    CROSSWALK_SHA256, MODEL_FEATURES, CICFlowMeterV3ModelAdapter)

ROOT = PROJECT_ROOT
DATA = ROOT / "data/lab/experiment_d"
SEALED = DATA / "final_test/manifests/sealed_capture_manifest.json"
RF1 = ROOT / "models/random_forest_active.joblib"
RF1_META = ROOT / "models/model_metadata.json"
RF2 = ROOT / "models/experiment_d/random_forest_rf_v2.joblib"
RF2_META = ROOT / "models/experiment_d/random_forest_rf_v2_metadata.json"
RF2_FREEZE = ROOT / "reports/experiment_d/audit/rf_v2_frozen_manifest.json"
LEAKAGE = ROOT / "reports/experiment_d/audit/final_test_leakage_audit.json"
DATASET_AUDIT = ROOT / "reports/experiment_d/final_test/dataset_audit.json"
CLASSES = ("Normal", "DDoS", "PortScan")
COUNTS = {"Normal": 30, "DDoS": 15482, "PortScan": 437}
TOTAL = 15949
FINAL_ID = "a60d79e66690dcb146e76a80dee5ff4e550abd298575a92d77be6db447881d18"
TRUTH_ID = "a5dec5d0197eee4601843f4832d51de1c86b52361e5f42f36fecebc157749e79"
RF2_SHA = "fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31"
ZERO_DIVISION = 0
OUT = {
    "rows": ROOT / "reports/experiment_d/final_test/canonical_row_order_manifest.csv",
    "rf1_pred": ROOT / "reports/experiment_d/final_test/rf_v1_predictions.csv",
    "rf2_pred": ROOT / "reports/experiment_d/final_test/rf_v2_predictions.csv",
    "rf1_cm": ROOT / "reports/experiment_d/final_test/rf_v1_confusion_matrix.csv",
    "rf2_cm": ROOT / "reports/experiment_d/final_test/rf_v2_confusion_matrix.csv",
    "rf1_sessions": ROOT / "reports/experiment_d/final_test/rf_v1_session_metrics.csv",
    "rf2_sessions": ROOT / "reports/experiment_d/final_test/rf_v2_session_metrics.csv",
    "metrics": ROOT / "reports/experiment_d/final_test/metrics.json",
    "comparison_csv": ROOT / "reports/experiment_d/comparison/rf_v1_vs_rf_v2_final_metrics.csv",
    "comparison_json": ROOT / "reports/experiment_d/comparison/rf_v1_vs_rf_v2_final_report.json",
    "manifest": ROOT / "reports/experiment_d/audit/d6_evaluation_manifest.json",
    "docs": ROOT / "docs/experiment_d_phase_d6_blind_final_evaluation.md",
}

def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as f:
        json.dump(value, f, indent=2, sort_keys=True); f.write("\n")

def write_csv(path: Path, fields: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields); writer.writeheader(); writer.writerows(rows)

def evidence_snapshot() -> dict[str, Any]:
    excluded = {p.resolve(strict=False) for p in OUT.values()}
    roots = [ROOT/"reports/experiment_d/adaptation", ROOT/"reports/experiment_d/audit",
             ROOT/"reports/experiment_d/final_test", ROOT/"data/lab/experiment_d", ROOT/"models/experiment_d"]
    paths = sorted(set(p for base in roots for p in base.rglob("*") if p.is_file()
                       and p.name != ".gitkeep" and p.resolve(strict=False) not in excluded))
    records = [{"logical_path": str(p.relative_to(ROOT)), "sha256": sha256_file(p),
                "size_bytes": p.stat().st_size} for p in paths]
    return {"file_count": len(records), "identity": canonical_identity(records)}

def integrity_gate() -> dict[str, Any]:
    existing = [str(p.relative_to(ROOT)) for p in OUT.values() if p.exists()]
    if existing: raise FileExistsError(f"D6 output path already exists; refusing inference: {existing}")
    baseline = verify_rf_v1_baseline()
    frozen_baseline = read_json(ROOT/"reports/experiment_d/audit/frozen_baseline_manifest.json")
    if frozen_baseline.get("status") != "PASS" or frozen_baseline.get("entries") != baseline.get("entries") or frozen_baseline.get("path_independent_scientific_identity") != baseline.get("path_independent_scientific_identity"):
        raise ValueError("RF-v1 frozen manifest/artifacts mismatch")
    rf1_meta, rf2_meta = read_json(RF1_META), read_json(RF2_META)
    if sha256_file(RF1) != rf1_meta.get("model_sha256"): raise ValueError("RF-v1 artifact/metadata mismatch")
    freeze = verify_frozen_manifest(RF2_FREEZE, RF2)
    if freeze["model_sha256"] != RF2_SHA or sha256_file(RF2_META) != freeze["model_metadata_sha256"] or rf2_meta.get("model_sha256") != RF2_SHA:
        raise ValueError("RF-v2 artifact, metadata, or frozen manifest mismatch")
    manifest = load_manifest(SEALED)
    if not manifest.sealed or manifest.scientific_identity != FINAL_ID: raise ValueError("sealed test identity mismatch")
    verify_manifest_files(manifest, DATA)
    meta = manifest.metadata or {}
    if meta.get("ground_truth_identity") != TRUTH_ID or meta.get("rf_v2_frozen_identity") != freeze["frozen_identity"]:
        raise ValueError("ground-truth or RF-v2 freeze identity mismatch")
    if meta.get("adapter") != {"identity":ADAPTER_IDENTITY,"version":ADAPTER_VERSION,"crosswalk_sha256":CROSSWALK_SHA256} or sha256_file(ROOT/CROSSWALK_PATH) != CROSSWALK_SHA256:
        raise ValueError("adapter identity/version/crosswalk mismatch")
    if freeze["cicflowmeter_v3"]["commit"] != CICFLOWMETER_V3_COMMIT or freeze["cicflowmeter_v3"]["image_digest"] != CICFLOWMETER_V3_IMAGE_DIGEST:
        raise ValueError("CICFlowMeter V3 provenance mismatch")
    leakage, dataset = read_json(LEAKAGE), read_json(DATASET_AUDIT)
    if leakage.get("status") != "PASS" or not all(leakage.get("checks",{}).values()) or leakage.get("final_test_manifest_identity") != FINAL_ID:
        raise ValueError("D5 leakage audit failed")
    if dataset.get("status") != "PASS" or dataset.get("ground_truth_distribution") != COUNTS or dataset.get("total_flows") != TOTAL:
        raise ValueError("sealed counts mismatch")
    if rf1_meta.get("feature_names") != rf2_meta.get("feature_names") or rf1_meta.get("feature_names") != list(MODEL_FEATURES):
        raise ValueError("ordered 78-feature schemas mismatch")
    records = meta.get("flow_records")
    if not isinstance(records,list) or len(records) != 9: raise ValueError("expected nine sealed flow records")
    counts, sessions, captures = Counter(), set(), set()
    for rec in records:
        path = DATA/rec["raw_csv_logical_path"]
        if sha256_file(path) != rec["raw_csv_sha256"]: raise ValueError(f"flow hash mismatch: {path}")
        counts[rec["ground_truth"]] += int(rec["row_count"]); sessions.add(rec["session_id"]); captures.add(rec["capture_id"])
    if dict(counts) != COUNTS or len(sessions) != 9 or len(captures) != 9: raise ValueError("sealed record counts/identities mismatch")
    return {"status":"PASS","models_loaded":False,"inference_performed":False,
            "rf_v1_sha256":sha256_file(RF1),"rf_v1_metadata_sha256":sha256_file(RF1_META),
            "rf_v1_frozen_identity":baseline["path_independent_scientific_identity"],
            "rf_v2_sha256":sha256_file(RF2),"rf_v2_frozen_identity":freeze["frozen_identity"],
            "sealed_final_test_identity":FINAL_ID,"ground_truth_identity":TRUTH_ID,
            "feature_count":78,"flow_counts":dict(counts),"total_flows":sum(counts.values()),
            "session_count":9,"output_paths_unused":True}

def build_matrix() -> tuple[pd.DataFrame,pd.Series,list[dict[str,Any]],str]:
    records = read_json(SEALED)["metadata"]["flow_records"]
    adapter = CICFlowMeterV3ModelAdapter.from_metadata(RF1_META)
    frames, labels, provenance = [], [], []
    for rec in records:
        path = DATA/rec["raw_csv_logical_path"]; raw = pd.read_csv(path)
        if len(raw) != rec["row_count"]: raise ValueError(f"row count mismatch: {path}")
        frames.append(adapter.adapt(raw,raw_input_path=path,raw_input_sha256=rec["raw_csv_sha256"]).features)
        labels.extend([rec["ground_truth"]]*len(raw))
        for source_index, flow_id in enumerate(raw["Flow ID"].astype(str)):
            row_id = canonical_identity(["experiment_d_final_test",rec["raw_csv_sha256"],source_index,flow_id])
            provenance.append({"canonical_index":len(provenance),"canonical_row_identity":row_id,
                "source_flow_identity":flow_id,"source_row_index":source_index,"source_file":rec["raw_csv_logical_path"],
                "session_id":rec["session_id"],"capture_id":rec["capture_id"],"scenario_id":rec["scenario_id"],"ground_truth":rec["ground_truth"]})
    x, y = pd.concat(frames,ignore_index=True), pd.Series(labels,name="ground_truth")
    if x.shape != (TOTAL,78) or tuple(x.columns) != MODEL_FEATURES or Counter(y) != Counter(COUNTS): raise ValueError("canonical matrix contract failed")
    if len({r["canonical_row_identity"] for r in provenance}) != TOTAL: raise ValueError("canonical row identities not unique")
    order_id = canonical_identity([r["canonical_row_identity"] for r in provenance])
    write_csv(OUT["rows"],list(provenance[0]),provenance)
    return x,y,provenance,order_id

def predict_once(model: Any, x: pd.DataFrame) -> tuple[np.ndarray,np.ndarray,list[str]]:
    classes = [str(v) for v in model.classes_]
    if set(classes) != set(CLASSES) or len(classes) != 3: raise ValueError(f"invalid model classes: {classes}")
    predictions = model.predict(x)
    probabilities = model.predict_proba(x)
    if predictions.shape != (TOTAL,) or probabilities.shape != (TOTAL,3) or not np.isfinite(probabilities).all(): raise ValueError("prediction contract failed")
    return predictions,probabilities,classes

def prediction_rows(prov: list[dict[str,Any]], y: pd.Series, pred: np.ndarray, prob: np.ndarray, classes: list[str]) -> list[dict[str,Any]]:
    pos={name:i for i,name in enumerate(classes)}; rows=[]
    for i,source in enumerate(prov):
        label=str(pred[i]); rows.append({"canonical_row_identity":source["canonical_row_identity"],"source_flow_identity":source["source_flow_identity"],
            "session_id":source["session_id"],"capture_id":source["capture_id"],"scenario_id":source["scenario_id"],"ground_truth":str(y.iloc[i]),
            "predicted_class":label,"confidence":float(prob[i,pos[label]]),"P(Normal)":float(prob[i,pos["Normal"]]),"P(DDoS)":float(prob[i,pos["DDoS"]]),"P(PortScan)":float(prob[i,pos["PortScan"]])})
    return rows

def metrics(y: pd.Series, pred: np.ndarray) -> dict[str,Any]:
    cm=confusion_matrix(y,pred,labels=CLASSES); macro=precision_recall_fscore_support(y,pred,labels=CLASSES,average="macro",zero_division=ZERO_DIVISION); weighted=precision_recall_fscore_support(y,pred,labels=CLASSES,average="weighted",zero_division=ZERO_DIVISION); pc=precision_recall_fscore_support(y,pred,labels=CLASSES,average=None,zero_division=ZERO_DIVISION)
    per={name:{"support":int(pc[3][i]),"precision":float(pc[0][i]),"recall":float(pc[1][i]),"f1":float(pc[2][i])} for i,name in enumerate(CLASSES)}
    normal_fp=int(cm[1:,0].sum()); normal_tn=int(cm[1:,1:].sum()); attack_total=int(cm[1:,:].sum()); detected=int(cm[1:,1:].sum())
    return {"total_samples":len(y),"accuracy":float(accuracy_score(y,pred)),"macro_precision":float(macro[0]),"macro_recall":float(macro[1]),"macro_f1":float(macro[2]),"weighted_precision":float(weighted[0]),"weighted_recall":float(weighted[1]),"weighted_f1":float(weighted[2]),"per_class":per,
        "normal_false_positive_rate":normal_fp/(normal_fp+normal_tn) if normal_fp+normal_tn else 0.0,"attack_detection_rate":detected/attack_total if attack_total else 0.0,"ddos_detection_rate":per["DDoS"]["recall"],"portscan_detection_rate":per["PortScan"]["recall"],"confusion_matrix_labels":list(CLASSES),"confusion_matrix":cm.tolist(),"zero_division_policy":ZERO_DIVISION}

def session_rows(prov: list[dict[str,Any]], pred: np.ndarray) -> list[dict[str,Any]]:
    result=[]
    for session in dict.fromkeys(r["session_id"] for r in prov):
        ix=[i for i,r in enumerate(prov) if r["session_id"]==session]; src=prov[ix[0]]; counts=Counter(str(pred[i]) for i in ix); correct=counts[src["ground_truth"]]
        result.append({"class":src["ground_truth"],"session_id":session,"capture_id":src["capture_id"],"scenario_id":src["scenario_id"],"flow_count":len(ix),"correct_count":correct,"predicted_Normal":counts["Normal"],"predicted_DDoS":counts["DDoS"],"predicted_PortScan":counts["PortScan"],"ground_truth_recall":correct/len(ix)})
    if len(result)!=9: raise ValueError("expected nine session rows")
    return result

def comparisons(a: dict[str,Any], b: dict[str,Any]) -> list[dict[str,Any]]:
    pairs={"accuracy":(a["accuracy"],b["accuracy"]),"macro_precision":(a["macro_precision"],b["macro_precision"]),"macro_recall":(a["macro_recall"],b["macro_recall"]),"macro_f1":(a["macro_f1"],b["macro_f1"]),"Normal_recall":(a["per_class"]["Normal"]["recall"],b["per_class"]["Normal"]["recall"]),"DDoS_recall":(a["per_class"]["DDoS"]["recall"],b["per_class"]["DDoS"]["recall"]),"PortScan_recall":(a["per_class"]["PortScan"]["recall"],b["per_class"]["PortScan"]["recall"]),"Normal_FPR":(a["normal_false_positive_rate"],b["normal_false_positive_rate"]),"attack_detection_rate":(a["attack_detection_rate"],b["attack_detection_rate"])}
    return [{"metric":k,"rf_v1":v[0],"rf_v2":v[1],"rf_v2_minus_rf_v1":v[1]-v[0]} for k,v in pairs.items()]

def post_integrity(pre: dict[str,Any]) -> dict[str,Any]:
    baseline=verify_rf_v1_baseline(); sealed=load_manifest(SEALED); verify_manifest_files(sealed,DATA)
    checks={"rf_v1_unchanged":sha256_file(RF1)==pre["rf_v1_sha256"] and sha256_file(RF1_META)==pre["rf_v1_metadata_sha256"] and baseline["path_independent_scientific_identity"]==pre["rf_v1_frozen_identity"],"rf_v2_unchanged":sha256_file(RF2)==RF2_SHA,"sealed_final_test_unchanged":sealed.scientific_identity==FINAL_ID,"ground_truth_unchanged":(sealed.metadata or {}).get("ground_truth_identity")==TRUTH_ID,"experiment_c_unchanged":baseline["status"]=="PASS","adapter_crosswalk_unchanged":sha256_file(ROOT/CROSSWALK_PATH)==CROSSWALK_SHA256,"no_training_occurred":True,"rf_v2_not_activated":sha256_file(ROOT/"models/random_forest_active.joblib")==pre["rf_v1_sha256"]}
    if not all(checks.values()): raise ValueError(f"post-inference integrity failure: {checks}")
    return {"status":"PASS","checks":checks}

def write_docs(a:dict[str,Any],b:dict[str,Any],comp:list[dict[str,Any]],s1:list[dict[str,Any]],s2:list[dict[str,Any]],order_id:str,pre:dict[str,Any]) -> None:
    delta={r["metric"]:r["rf_v2_minus_rf_v1"] for r in comp}
    def class_table(m:dict[str,Any])->str: return "\n".join(f"| {n} | {v['support']} | {v['precision']:.6f} | {v['recall']:.6f} | {v['f1']:.6f} |" for n,v in m["per_class"].items())
    def matrix(m:dict[str,Any])->str: return "\n".join("| "+" | ".join([CLASSES[i],*[str(v) for v in row]])+" |" for i,row in enumerate(m["confusion_matrix"]))
    sessions="\n".join(f"| {x['class']} | {x['session_id']} | {x['flow_count']} | {x['ground_truth_recall']:.6f} | {y['ground_truth_recall']:.6f} |" for x,y in zip(s1,s2,strict=True)); improved=sum(y["ground_truth_recall"]>x["ground_truth_recall"] for x,y in zip(s1,s2,strict=True))
    conclusion="demonstrates improved external generalization relative to RF-v1" if delta["macro_f1"]>0 and b["per_class"]["DDoS"]["recall"]>0 and b["per_class"]["PortScan"]["recall"]>0 else "does not provide sufficient evidence to claim improved external generalization relative to RF-v1"
    text=f"""# Experiment D Phase D6: Blind Final Evaluation

## Methodology and pre-inference integrity

This was a one-shot blind evaluation. The fail-closed gate verified RF-v1 and RF-v2 artifacts and metadata, the RF-v2 frozen manifest, all sealed PCAP and flow hashes, adapter and crosswalk identity, CICFlowMeter V3 provenance, leakage status, sealed counts, and unused output paths. Both frozen sklearn pipelines received one canonical 15,949-row, 78-feature matrix. No fitting, tuning, threshold selection, feature selection, resampling, or adaptation occurred. `predict(X)` and `predict_proba(X)` were called exactly once per model.

Sealed identity: `{pre['sealed_final_test_identity']}`. Ground-truth identity: `{pre['ground_truth_identity']}`. Canonical row-order identity: `{order_id}`. Distribution: Normal 30, DDoS 15,482, PortScan 437.

## RF-v1 results

Accuracy {a['accuracy']:.9f}; macro F1 {a['macro_f1']:.9f}; weighted F1 {a['weighted_f1']:.9f}; Normal FPR {a['normal_false_positive_rate']:.9f}; attack detection rate {a['attack_detection_rate']:.9f}.

| Class | Support | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
{class_table(a)}

| Actual | Normal | DDoS | PortScan |
|---|---:|---:|---:|
{matrix(a)}

## RF-v2 results

Accuracy {b['accuracy']:.9f}; macro F1 {b['macro_f1']:.9f}; weighted F1 {b['weighted_f1']:.9f}; Normal FPR {b['normal_false_positive_rate']:.9f}; attack detection rate {b['attack_detection_rate']:.9f}.

| Class | Support | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
{class_table(b)}

| Actual | Normal | DDoS | PortScan |
|---|---:|---:|---:|
{matrix(b)}

## Same-row comparison and sessions

RF-v2 minus RF-v1 macro F1 was {delta['macro_f1']:+.9f}. Recall deltas were Normal {delta['Normal_recall']:+.9f}, DDoS {delta['DDoS_recall']:+.9f}, and PortScan {delta['PortScan_recall']:+.9f}. RF-v2 achieved non-zero DDoS recall: **{b['per_class']['DDoS']['recall']>0}**; non-zero PortScan recall: **{b['per_class']['PortScan']['recall']>0}**; Normal recall {b['per_class']['Normal']['recall']:.9f}. Recall improved in {improved} of nine independent sessions.

| Class | Session | Flows | RF-v1 recall | RF-v2 recall |
|---|---|---:|---:|---:|
{sessions}

## Context, limitations, and interpretation

Experiment C remains immutable historical evidence: RF-v1 recognized 61/61 Normal flows but 0/10,226 DDoS and 0/1,000 PortScan flows (accuracy 0.005404447594577833). It demonstrates RF-v1 failure on the earlier external laboratory set. Experiment D uses a new sealed set; the fair causal comparison is RF-v1 versus RF-v2 on identical D6 rows, not a direct comparison of Experiment C and D scores.

The set is extremely imbalanced and has only 30 Normal observations. Accuracy is secondary; macro F1, per-class recall, and session consistency are essential. No rows were rebalanced or resampled. D4 CICIDS2017 internal-control performance remains contextual evidence that adaptation did not materially destroy original-distribution performance; it was not recomputed or used to alter D6.

On this sealed set, RF-v2 {conclusion}. This is limited to the preregistered captures and should not be generalized without further independently sealed evaluation.

## Scientific-integrity audit

Status: **PASS**. RF-v1, RF-v2, sealed inputs, ground truth, Experiment C, D2-D5 evidence, adapter, and crosswalk remained unchanged. RF-v2 remained `{RF2_SHA}`; RF-v2 was not activated; no training occurred. Metrics use `zero_division=0`.
"""
    OUT["docs"].parent.mkdir(parents=True,exist_ok=True)
    with OUT["docs"].open("x",encoding="utf-8") as f: f.write(text)

def execute() -> dict[str,Any]:
    before=evidence_snapshot(); pre=integrity_gate(); x,y,prov,order_id=build_matrix()
    rf1=joblib.load(RF1); p1,q1,c1=predict_once(rf1,x)
    pred_fields=["canonical_row_identity","source_flow_identity","session_id","capture_id","scenario_id","ground_truth","predicted_class","confidence","P(Normal)","P(DDoS)","P(PortScan)"]
    write_csv(OUT["rf1_pred"],pred_fields,prediction_rows(prov,y,p1,q1,c1))
    rf2=joblib.load(RF2); p2,q2,c2=predict_once(rf2,x)
    write_csv(OUT["rf2_pred"],pred_fields,prediction_rows(prov,y,p2,q2,c2))
    a,b=metrics(y,p1),metrics(y,p2); s1,s2=session_rows(prov,p1),session_rows(prov,p2); comp=comparisons(a,b)
    cm_fields=["actual_class",*CLASSES]
    for key,m in (("rf1_cm",a),("rf2_cm",b)): write_csv(OUT[key],cm_fields,[{"actual_class":name,**dict(zip(CLASSES,m["confusion_matrix"][i],strict=True))} for i,name in enumerate(CLASSES)])
    session_fields=["class","session_id","capture_id","scenario_id","flow_count","correct_count","predicted_Normal","predicted_DDoS","predicted_PortScan","ground_truth_recall"]
    write_csv(OUT["rf1_sessions"],session_fields,s1); write_csv(OUT["rf2_sessions"],session_fields,s2)
    write_json(OUT["metrics"],{"schema":"experiment_d_d6_final_metrics","schema_version":1,"dataset":{"sealed_identity":FINAL_ID,"ground_truth_identity":TRUTH_ID,"canonical_row_order_identity":order_id,"rows":TOTAL,"features":78,"class_distribution":COUNTS},"evaluation_policy":{"one_shot":True,"threshold_selection":False,"resampling":False,"zero_division":ZERO_DIVISION,"class_order":list(CLASSES)},"rf_v1":a,"rf_v2":b})
    write_csv(OUT["comparison_csv"],["metric","rf_v1","rf_v2","rf_v2_minus_rf_v1"],comp)
    primary={"rf_v2_nonzero_ddos_recall":b["per_class"]["DDoS"]["recall"]>0,"rf_v2_nonzero_portscan_recall":b["per_class"]["PortScan"]["recall"]>0,"rf_v2_normal_recall":b["per_class"]["Normal"]["recall"],"rf_v2_macro_f1_improved":b["macro_f1"]>a["macro_f1"],"sessions_with_recall_improvement":sum(y2["ground_truth_recall"]>y1["ground_truth_recall"] for y1,y2 in zip(s1,s2,strict=True)),"d4_internal_performance_role":"contextual evidence only; not recomputed or used for D6 decisions"}
    write_json(OUT["comparison_json"],{"schema":"experiment_d_d6_rf_v1_vs_rf_v2","schema_version":1,"comparison_basis":"same sealed Experiment D D6 rows in identical canonical order","metrics":comp,"confusion_matrices":{"labels":list(CLASSES),"rf_v1":a["confusion_matrix"],"rf_v2":b["confusion_matrix"]},"primary_questions":primary,"experiment_c_context":{"same_dataset_comparison":False,"rf_v1_accuracy":0.005404447594577833,"normal_recall":1.0,"ddos_recall":0.0,"portscan_recall":0.0},"class_imbalance_limitation":"Accuracy is secondary because DDoS dominates and Normal has only 30 rows; macro F1, per-class recall, and session results are essential."})
    del rf1,rf2,x
    after=evidence_snapshot()
    if before!=after: raise ValueError("D2-D5 evidence changed during D6")
    final=post_integrity(pre); write_docs(a,b,comp,s1,s2,order_id,pre)
    hashes={k:sha256_file(p) for k,p in OUT.items() if p.is_file() and k!="manifest"}
    commit=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,check=True,capture_output=True,text=True).stdout.strip()
    dirty=bool(subprocess.run(["git","status","--porcelain"],cwd=ROOT,check=True,capture_output=True,text=True).stdout)
    command=" ".join([str(Path(sys.executable)),str(Path(__file__).relative_to(ROOT)),*sys.argv[1:]])
    manifest={"schema":"experiment_d_d6_evaluation_manifest","schema_version":1,"status":"PASS","evaluation_timestamp_utc":datetime.now(timezone.utc).isoformat(),"exact_evaluation_command":command,"code_commit":commit,"working_tree_dirty":dirty,"runtime":{"python":platform.python_version(),"scikit_learn":sklearn.__version__,"joblib":joblib.__version__,"numpy":np.__version__,"pandas":pd.__version__},"rf_v1_artifact_sha256":pre["rf_v1_sha256"],"rf_v1_metadata_sha256":pre["rf_v1_metadata_sha256"],"rf_v1_frozen_identity":pre["rf_v1_frozen_identity"],"rf_v2_artifact_sha256":pre["rf_v2_sha256"],"rf_v2_frozen_identity":pre["rf_v2_frozen_identity"],"sealed_final_test_identity":FINAL_ID,"ground_truth_identity":TRUTH_ID,"canonical_row_order_identity":order_id,"prediction_table_hashes":{k:hashes[k] for k in ("rf1_pred","rf2_pred")},"metric_report_hashes":{k:hashes[k] for k in ("metrics","comparison_csv","comparison_json")},"confusion_matrix_hashes":{k:hashes[k] for k in ("rf1_cm","rf2_cm")},"session_report_hashes":{k:hashes[k] for k in ("rf1_sessions","rf2_sessions")},"canonical_row_manifest_sha256":hashes["rows"],"documentation_sha256":hashes["docs"],"scientific_integrity":final,"d2_d5_evidence_snapshot":{"file_count":before["file_count"],"identity_before":before["identity"],"identity_after":after["identity"],"unchanged":True},"inference":{"one_shot":True,"valid_inference_runs":1,"rf_v1_predict_calls":1,"rf_v1_predict_proba_calls":1,"rf_v2_predict_calls":1,"rf_v2_predict_proba_calls":1,"training_fit_calls":0,"retry_count":0}}
    write_json(OUT["manifest"],manifest)
    return {"status":"PASS","one_shot":True,"canonical_row_order_identity":order_id,"rf_v1":a,"rf_v2":b}

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__); mode=parser.add_mutually_exclusive_group(required=True); mode.add_argument("--preflight",action="store_true"); mode.add_argument("--execute-one-shot",action="store_true"); args=parser.parse_args()
    print(json.dumps(integrity_gate() if args.preflight else execute(),sort_keys=True)); return 0

if __name__ == "__main__": raise SystemExit(main())
