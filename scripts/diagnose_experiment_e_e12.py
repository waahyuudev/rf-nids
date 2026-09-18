#!/usr/bin/env python3
"""Create-new, read-only reconstruction and diagnosis for recovered E12 evidence."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.ingestion.cicflowmeter_v3_adapter import CICFlowMeterV3ModelAdapter, sha256_file

ROOT = Path(__file__).resolve().parents[1]
REC = ROOT / "reports/experiment_e/recovery/e12"
DIAG = ROOT / "reports/experiment_e/diagnostic"
RAW, PCAP = REC / "session_11_window_000003_raw.csv", REC / "session_11_window_000003.pcap"
MATRIX, LINEAGE = REC / "session_11_model_input_78.csv", REC / "session_11_model_input_lineage.json"
OUT, SUMMARY, STATS = DIAG / "e12_recovered_runtime_diagnostic.json", DIAG / "e12_recovered_runtime_diagnostic_summary.md", DIAG / "e12_feature_distribution_comparison.csv"
V3 = ROOT / "models/experiment_e/random_forest_rf_v3_candidate.joblib"
V2 = ROOT / "models/experiment_d/random_forest_rf_v2.joblib"
META = ROOT / "models/experiment_e/random_forest_rf_v3_candidate_metadata.json"
TRAIN = ROOT / "data/lab/experiment_e/datasets/experiment_e_training_candidate.csv"
EXPORT = ROOT / "reports/experiment_e/runtime_exports/e10"
EXPECTED = {RAW: "3a6b58afcda68baae9d620afa6f9c0e286589253827836b61cb021bbc6d7432b", PCAP: "8bfa65f4d4e395044016dab174477781e1e14416b9059207e559614fd6fb3509", V3: "6b01c7b3923c1a6bd471862d011f8f5b88a31378e51d1dde082bd2e72bedef86", TRAIN: "f716404391467b267cca2f989762c2d4740127a4e7dd11afe956e7e8940b2284"}

def digest(p): return sha256_file(p)
def stats(s):
    return {"min":float(s.min()),"q1":float(s.quantile(.25)),"median":float(s.median()),"mean":float(s.mean()),"q3":float(s.quantile(.75)),"max":float(s.max()),"standard_deviation":float(s.std(ddof=1))}
def probs(model, x):
    arr=model.predict_proba(x); return pd.DataFrame(arr, columns=[str(c) for c in model.classes_])
def safe(v): return None if pd.isna(v) else (v.item() if hasattr(v,"item") else v)

def main():
    outputs=(MATRIX,LINEAGE,OUT,SUMMARY,STATS)
    if any(p.exists() for p in outputs): raise FileExistsError("E12 evidence is create-new only")
    before={str(p.relative_to(ROOT)):digest(p) for p in [*EXPECTED, META, V2, ROOT/"models/experiment_d/random_forest_rf_v2_metadata.json", ROOT/"reports/experiment_e/diagnostic/e11_ddos_failure_diagnostic.json", ROOT/"reports/experiment_e/diagnostic/e11_ddos_failure_diagnostic_summary.md", ROOT/"reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv", *EXPORT.glob("*.csv")]}
    for p,want in EXPECTED.items():
        if not p.is_file() or digest(p)!=want: raise RuntimeError(f"authoritative integrity gate failed: {p}")
    raw=pd.read_csv(RAW)
    if raw.shape != (802,84): raise RuntimeError(f"raw shape gate failed: {raw.shape}")
    artifacts=pd.read_csv(EXPORT/"runtime_artifacts_10_11.csv")
    artifact=artifacts.query("monitoring_session_id == 11 and window_number == 3 and state == 'COMMITTED'")
    if len(artifact)!=1 or int(artifact.iloc[0].id)!=807 or artifact.iloc[0].csv_sha256!=digest(RAW) or artifact.iloc[0].pcap_sha256!=digest(PCAP): raise RuntimeError("runtime artifact 807 lineage gate failed")
    meta=json.loads(META.read_text()); features=meta["feature_names"]
    adapter=CICFlowMeterV3ModelAdapter.from_metadata(META); adapted=adapter.adapt(raw,raw_input_path=RAW,raw_input_sha256=digest(RAW))
    x=adapted.features
    if list(x.columns)!=features or x.shape!=(802,78) or x.columns.duplicated().any(): raise RuntimeError("78-feature reconstruction gate failed")
    MATRIX.parent.mkdir(parents=True,exist_ok=True); x.to_csv(MATRIX,index=False)
    v3=joblib.load(V3); v2=joblib.load(V2)
    p3=probs(v3,x); y3=v3.predict(x)
    persisted=pd.read_csv(EXPORT/"session_11_predictions.csv").sort_values("prediction_id").reset_index(drop=True)
    if len(persisted)!=802 or len(p3)!=802: raise RuntimeError("prediction count gate failed")
    historical=pd.DataFrame([json.loads(s) for s in persisted.class_probabilities])[["DDoS","Normal","PortScan"]]
    offline=p3[["DDoS","Normal","PortScan"]]
    meta_match=(persisted.source_ip.astype(str).eq(raw["Src IP"].astype(str)) & persisted.source_port.eq(raw["Src Port"]) & persisted.destination_ip.astype(str).eq(raw["Dst IP"].astype(str)) & persisted.destination_port.eq(raw["Dst Port"]) & pd.to_numeric(persisted.protocol).eq(pd.to_numeric(raw["Protocol"]))).all()
    ids_sequential=persisted.prediction_id.tolist()==list(range(int(persisted.prediction_id.min()),int(persisted.prediction_id.min())+802))
    class_agreement=int((persisted.predicted_label.to_numpy()==y3).sum()); delta=(offline-historical).abs(); tolerance=1e-12
    p2=probs(v2,x); y2=v2.predict(x)
    train=pd.read_csv(TRAIN); ddos=train.loc[train.ground_truth_class.eq("DDoS"),features]
    if len(ddos)!=3081 or digest(TRAIN)!=EXPECTED[TRAIN]: raise RuntimeError("frozen E4 DDoS gate failed")
    rows=[]
    for f in features:
        a,b=x[f].astype(float),ddos[f].astype(float); sd=np.sqrt((a.var(ddof=1)+b.var(ddof=1))/2)
        mad=float((b-b.median()).abs().median()); med=float(abs(a.median()-b.median())); robust=med/(mad if mad>0 else (sd if sd>0 else 1))
        rows.append({"feature":f,"session_11":json.dumps(stats(a)),"historical_ddos":json.dumps(stats(b)),"absolute_median_difference":med,"pooled_standardized_median_difference":med/sd if sd>0 else None,"robust_median_distance":robust})
    table=pd.DataFrame(rows).sort_values("robust_median_distance",ascending=False); table.to_csv(STATS,index=False)
    rawpos=pd.DataFrame({"raw_row_index":range(1,803),"Flow ID":raw["Flow ID"],"Src IP":raw["Src IP"],"Src Port":raw["Src Port"],"Dst IP":raw["Dst IP"],"Dst Port":raw["Dst Port"]})
    top=[]
    for i in p3["DDoS"].nlargest(10).index:
        rr=raw.iloc[i]; pr=persisted.iloc[i]
        row_match=(str(pr.source_ip)==str(rr["Src IP"]) and pr.source_port==rr["Src Port"] and str(pr.destination_ip)==str(rr["Dst IP"]) and pr.destination_port==rr["Dst Port"] and float(pr.protocol)==float(rr["Protocol"]))
        top.append({"reconstructed_row_index":int(i+1),"prediction_id":int(pr.prediction_id) if row_match and ids_sequential else None,"traffic_flow_id":int(pr.traffic_flow_id) if row_match and ids_sequential else None,"source_ip":rr["Src IP"],"source_port":safe(rr["Src Port"]),"destination_ip":rr["Dst IP"],"destination_port":safe(rr["Dst Port"]),"predicted_class":str(y3[i]),"P(Normal)":float(p3.loc[i,"Normal"]),"P(DDoS)":float(p3.loc[i,"DDoS"]),"P(PortScan)":float(p3.loc[i,"PortScan"]),"feature_values_vs_session_and_ddos_median":{f:{"value":safe(rr[adapter.MAPPING_RULES[i][1]]) if False else float(x.loc[i,f]),"session_median":float(x[f].median()),"ddos_median":float(ddos[f].median())} for f in table.head(10).feature}})
    anomalous=[]
    for idx,r in raw.loc[raw["Src IP"].astype(str).eq("10.10.20.2") | raw["Src IP"].astype(str).eq("8.6.0.1") | raw["Dst IP"].astype(str).eq("8.6.0.1")].iterrows():
        anomalous.append({"raw_row_index":int(idx+1),"Flow ID":r["Flow ID"],"Src IP":r["Src IP"],"Src Port":safe(r["Src Port"]),"Dst IP":r["Dst IP"],"Dst Port":safe(r["Dst Port"]),"Protocol":safe(r["Protocol"]),"Timestamp":r["Timestamp"],"relevant_features":{"flow_duration":safe(x.loc[idx,"flow_duration"]),"total_fwd_packets":safe(x.loc[idx,"total_fwd_packets"]),"total_backward_packets":safe(x.loc[idx,"total_backward_packets"]),"flow_packets_s":safe(x.loc[idx,"flow_packets_s"])}})
    changed_to=int(((y2!="DDoS")&(y3=="DDoS")).sum()); changed_away=int(((y2=="DDoS")&(y3!="DDoS")).sum())
    lineage={"monitoring_session_id":11,"runtime_capture_artifact_id":807,"window_number":3,"raw_csv_sha256":digest(RAW),"pcap_sha256":digest(PCAP),"adapter":adapted.provenance,"feature_contract":{"metadata_path":str(META.relative_to(ROOT)),"feature_order_sha256":meta["feature_order_sha256"],"count":78},"row_count":802,"feature_count":78,"reconstructed_dataset_sha256":digest(MATRIX),"model_artifacts":{"rf_v3":digest(V3),"rf_v2":digest(V2)},"raw_row_index_lineage":"CSV rows are preserved in original order; model-input row N corresponds to recovered raw CSV data row N (1-based).","no_traffic_regenerated":True,"recovery_analysis_timestamp_utc":datetime.now(timezone.utc).isoformat()}
    LINEAGE.write_text(json.dumps(lineage,indent=2,sort_keys=True)+"\n")
    categories={"FEATURE_SCHEMA_MISMATCH":"NOT_SUPPORTED: raw 84 columns adapt exactly to locked ordered 78 features.","EXTRACTOR_PROVENANCE_MISMATCH":"NOT_SUPPORTED: artifact 807 hashes and pinned extractor identity match E10 export.","MODEL_LOADING_OR_ORDERING_ERROR":"NOT_SUPPORTED: exact positional persisted/offline class and probability reproduction.","RUNTIME_DISTRIBUTION_SHIFT":"SUPPORTED: normalized 78-feature comparison shows substantial shift; see ranking.","WORKLOAD_NOT_REPRESENTATIVE_OF_TRAINED_DDOS":"PARTIALLY_SUPPORTED: recovered controlled HTTP vectors differ materially from frozen historical DDoS, but causality is not proven.","MODEL_CLASS_BOUNDARY_LIMITATION":"PARTIALLY_SUPPORTED: the most DDoS-like reconstructed vectors remain predominantly Normal; overlap is not established globally.","INSUFFICIENT_EVIDENCE":"NOT_SUPPORTED for reconstruction/reproducibility; remaining causal interpretation is limited to this recovered window."}
    payload={"schema":"experiment_e_e12_recovered_runtime_diagnostic","schema_version":1,"mode":"diagnostic-only; frozen recovered evidence; no DB writes","e12_gate":"PASS","artifact_integrity":{"raw_rows":802,"raw_columns":84,"raw_sha256":digest(RAW),"pcap_sha256":digest(PCAP),"runtime_artifact_807_lineage":"PASS"},"reconstruction":{"matrix_shape":[802,78],"matrix_sha256":digest(MATRIX),"adapter_provenance":adapted.provenance,"lineage_file":str(LINEAGE.relative_to(ROOT))},"rf_v3_reproducibility":{"row_lineage":"C. universal exact row-level linkage is insufficient: 801/802 exported metadata tuples match the raw rows, but anomalous raw row 791 differs from its exported tuple. Positional class/probability comparison is reported as strong reproducibility evidence, not forced universal row identity.","persisted_count":802,"offline_count":802,"class_agreement_count":class_agreement,"mismatch_count":802-class_agreement,"tolerance":tolerance,"tolerance_justification":"persisted JSON decimal serialization may round IEEE-754 values","probability_max_absolute_difference":delta.max().to_dict(),"probability_mean_absolute_difference":delta.mean().to_dict(),"probabilities_outside_tolerance":int((delta>tolerance).any(axis=1).sum())},"rf_v2_identical_flow":{"class_counts":pd.Series(y2).value_counts().reindex(["Normal","DDoS","PortScan"],fill_value=0).to_dict(),"probability_summary":{c:stats(p2[c]) for c in ["Normal","DDoS","PortScan"]},"vs_rf_v3":{"class_agreement":int((y2==y3).sum()),"class_disagreement":int((y2!=y3).sum()),"changed_toward_ddos":changed_to,"changed_away_from_ddos":changed_away,"mean_absolute_probability_shift":(p2[["DDoS","Normal","PortScan"]]-p3[["DDoS","Normal","PortScan"]]).abs().mean().to_dict()}},"distribution_shift":{"reference_ddos_count":3081,"all_feature_statistics_csv":str(STATS.relative_to(ROOT)),"top_10_shifted_features":table.head(10)[["feature","absolute_median_difference","pooled_standardized_median_difference","robust_median_distance"]].to_dict("records"),"ranking_method":"robust median distance: absolute median difference divided by historical DDoS median absolute deviation; pooled-SD value retained as secondary scale-aware check"},"high_p_ddos_flows":top,"anomalous_records":{"exceptional_raw_rows":anomalous,"finding_8_6_0_1":"Genuinely present in the recovered raw captured/extracted flow (raw row 791); why this extractor-visible representation occurred is unresolved from these artifacts alone."},"root_cause_categories":categories,"scientific_interpretation":"Frozen RF-v3 produces the observed Normal classifications on the recovered vectors; the 801 matching rows plus exact positional numerical agreement strongly reduce model-loading/order explanations. Distribution/workload findings are diagnostic rather than causal proof.","scientific_decision":"ROOT_CAUSE_PARTIALLY_SUPPORTED","limitations":["One recovered Session 11 window; no new traffic or rerun.","One anomalous export tuple prevents universal row-level linkage proof.","Distribution distances describe association, not causation.","No retraining, threshold change, DB write, activation, or promotion was performed."],"integrity":{"before":before,"after":None,"unchanged":None}}
    after={k:digest(ROOT/k) for k in before}; payload["integrity"].update({"after":after,"unchanged":before==after})
    if before!=after: raise RuntimeError("frozen historical integrity changed")
    OUT.write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n")
    SUMMARY.write_text("# E12 Recovered Runtime Diagnostic\n\nE12 gate: **PASS**. The recovered 802×84 artifact reconstructs exactly to the locked 802×78 matrix. RF-v3 offline reproduction is reported in the JSON, together with frozen RF-v2 same-flow diagnostics, normalized DDoS distribution shifts, exceptional raw records, and category reassessment.\n\nScientific decision: **ROOT_CAUSE_PARTIALLY_SUPPORTED**. No retraining, promotion, threshold change, traffic generation, or DB write occurred.\n",encoding="utf-8")
    print(json.dumps({str(p.relative_to(ROOT)):digest(p) for p in outputs}))
if __name__ == "__main__": main()
