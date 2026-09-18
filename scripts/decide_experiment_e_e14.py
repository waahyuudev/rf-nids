#!/usr/bin/env python3
"""Create-new, offline E14 remediation decision from committed E6--E13 evidence."""
from __future__ import annotations
import csv, hashlib, json
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT/'reports/experiment_e/decision'; PRE=ROOT/'reports/experiment_e/preregistration'
inputs=['reports/experiment_e/evaluation/e6_offline_validation.json','reports/experiment_e/runtime_validation/e7_runtime_validation.json','reports/experiment_e/audit/e8_scientific_decision.json','reports/experiment_e/analysis/e10_runtime_validation_analysis.json','reports/experiment_e/diagnostic/e12_recovered_runtime_diagnostic.json','reports/experiment_e/analysis/e13_final_analysis.json','reports/experiment_e/analysis/e13_feature_distribution_comparison.csv','reports/experiment_e/analysis/e13_rf_v2_rf_v3_paired_comparison.csv','models/experiment_d/random_forest_rf_v2.joblib','models/experiment_e/random_forest_rf_v3_candidate.joblib','models/experiment_e/random_forest_rf_v3_candidate_metadata.json','reports/experiment_d/final_test/dataset_audit.json']
def h(p):
 d=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''): d.update(b)
 return d.hexdigest()
def main():
 targets=[OUT/'e14_remediation_decision.json',OUT/'e14_remediation_decision_summary.md',OUT/'e14_evidence_matrix.csv',PRE/'e14_future_rfv4_requirements.md']
 if any(p.exists() for p in targets): raise FileExistsError('E14 is create-new only')
 hashes={x:h(ROOT/x) for x in inputs}
 e6=json.loads((ROOT/inputs[0]).read_text()); e7=json.loads((ROOT/inputs[1]).read_text()); e8=json.loads((ROOT/inputs[2]).read_text()); e10=json.loads((ROOT/inputs[3]).read_text()); e12=json.loads((ROOT/inputs[4]).read_text()); e13=json.loads((ROOT/inputs[5]).read_text())
 # Fail closed on the key frozen conclusions used by the decision.
 if not (e8['decision']=='MORE_VALIDATION_REQUIRED' and e12['e12_gate']=='PASS' and e13['gate_1_artifact_integrity']['status']=='PASS'): raise RuntimeError('authoritative input gate failed')
 r=e13['offline_model_results']; d1,d2=r['E13-D1-R1'],r['E13-D2-R1'];
 q={
 'Q1_PortScan_remediation':{'decision':'SUPPORTED','evidence':'E6 RF-v2/RF-v3 PortScan recall 0/0.9993337775; E7 independent runtime recall 0/0.9983361065.','limitation':'One unseen PortScan runtime session and narrow tested scope.'},
 'Q2_Normal_preservation':{'decision':'SUPPORTED','evidence':'Normal recall was 1.0 in E6 and E7; E13-N-R1 was 32/32 RF-v3 Normal.','scope':'Only the tested Experiment E Normal sessions/profiles; not universal Normal performance.'},
 'Q3_DDoS_runtime_weakness':{'decision':'SUPPORTED','evidence':f"E10 was 0/802 DDoS; E13 D1 was {d1['rf_v3']['class_counts']['DDoS']}/801 and D2 {d2['rf_v3']['class_counts']['DDoS']}/1612 RF-v3 DDoS on controlled DDoS-like profiles.",'scope':'Very low sensitivity on the controlled DDoS-like runtime workloads evaluated, not universal DDoS recall.'},
 'Q4_RFv2_to_RFv3_regression_signal':{'decision':'PARTIALLY_SUPPORTED','changed_decisions':{'D1_DDoS_to_Normal':d1['paired']['ddos_to_normal'],'D2_DDoS_to_Normal':d2['paired']['ddos_to_normal'],'E12_DDoS_to_Normal':5},'evidence':'Paired same-vector comparisons establish changed decisions and more RF-v2 DDoS classifications on these vectors.','not_proven':'Universal model degradation or a causal class-boundary mechanism.'},
 'Q5_Workload_domain_mismatch':{'decision':'SUPPORTED','evidence':'E12 and E13 all-78-feature scale-aware comparisons show material shifts from frozen E4 DDoS; D2 did not become closer than D1.','limitation':'Association/distribution diagnostics do not identify the causal source of mismatch.'},
 'Q6_Pipeline_defect':{'decision':'NOT_SUPPORTED','evidence':'E12 exact 802-vector reconstruction reproduced RF-v3 persisted classes/probabilities; E13 locked 84-to-78 reconstruction and model hashes passed.','scope':'No evidence that schema/order/extractor/model loading/dashboard serialization/runtime inference plumbing is the primary explanation in the analyzed evidence.'},
 'Q7_future_model_experiment':{'decision':'RFV4_EXPERIMENT_JUSTIFIED','rationale':'A new, separately preregistered three-class experiment is justified to preserve demonstrated PortScan/Normal gains while explicitly testing and improving DDoS behavior. This decision neither creates nor authorizes RF-v4.'}
 }
 rows=[
 ['PortScan generalization','E6; E7','RF-v3 recall 0.999334 (E6), 0.998336 (E7); RF-v2 0 in both','None within tested sessions','Narrow session coverage','PortScan remediation is supported in scope'],
 ['Normal preservation','E6; E7; E13-N-R1','Normal recall 1.0 (E6/E7); E13 32/32 Normal','None within tested profiles','Not universal Normal validation','Require preservation gate'],
 ['DDoS-like runtime sensitivity','E10; E13','RF-v3 0/802 E10; 2/801 D1; 4/1612 D2','Some DDoS predictions occur','Controlled DDoS-like, not universal recall','Explicit DDoS objective required'],
 ['RF-v2→RF-v3 DDoS regression signal','E12; E13','DDoS→Normal: 5 E12, 9 D1, 21 D2','RF-v3 has a small number of DDoS predictions','Not proof of universal degradation','Compare both baselines'],
 ['runtime/training distribution shift','E12; E13','All-78-feature robust diagnostics shift from E4; D2 not closer than D1','No causal mechanism isolated','Distribution association only','Do not assume workload represents training DDoS'],
 ['pipeline correctness','E12; E13','Exact E12 reproduction; locked E13 contract/hash gates pass','No contrary evidence','Does not rule out every unobserved deployment defect','Pipeline defect not primary explanation'],
 ['training-data representativeness','E10; E12; E13','Bounded one-VM logical-source workloads differ from E4 DDoS','Historical DDoS remains valid historical evidence','No directly equivalent new ground truth','Design new labeled sessions; do not relabel E10/E13'],
 ['evidence sufficiency','D; E6–E13','Enough for a new research experiment, not promotion','E8 remains MORE_VALIDATION_REQUIRED','Unseen final evidence still required','RFV4 experiment justified, promotion not authorized']]
 OUT.mkdir(parents=True,exist_ok=True)
 with (OUT/'e14_evidence_matrix.csv').open('w',newline='') as f: csv.writer(f).writerows([['Experiment','Evidence','Supports','Against','Limitation','Scientific implication'],*rows])
 future='''# E14 Future Three-Class Remediation Experiment Requirements

Status: requirements only. This document does not authorize training, RF-v4 creation, traffic generation, model activation, promotion, or E9.

## Objective

Improve runtime generalization across Normal, DDoS, and PortScan while explicitly preventing PortScan adaptation from sacrificing DDoS behavior.

## Locked foundations

- Retain the exact ordered 78-feature contract and CICFlowMeter V3 provenance.
- Keep Experiment D sealed final-test evidence permanently excluded from training and model selection.
- Preserve frozen RF-v2 and RF-v3 unchanged; compare every candidate with both.
- Retain historical DDoS evidence, PortScan runtime adaptation evidence, and Normal runtime evidence without relabeling E10/E13 as DDoS.

## Data and split design

- Separate adaptation, validation, and final evaluation by session/capture; prevent flow leakage.
- If adding DDoS ground truth, collect it only in an isolated lab with multiple genuinely independent generator nodes, bounded safe/reproducible profiles, explicit labels, and preserved PCAP, 84-column CSV, exact 78-feature matrix, and capture/extraction provenance.
- Record workload intensity from extracted network features, not client concurrency alone.

## Preregistered evaluation and acceptance gates

- Define per-class recall and F1, confusion matrices, macro F1, and probability diagnostics before training; do not optimize accuracy alone.
- Require Normal preservation, PortScan preservation, and measurable DDoS improvement relative to both RF-v2 and RF-v3 before any promotion consideration.
- Keep final validation unseen and session-separated. A successful candidate remains inactive until a separate promotion decision.
'''
 (PRE/'e14_future_rfv4_requirements.md').write_text(future)
 payload={'schema':'experiment_e_e14_remediation_decision','schema_version':1,'generated_at_utc':datetime.now(timezone.utc).isoformat(),'mode':'offline scientific decision/audit only','input_hashes':hashes,'questions':q,'ddos_labeling_decision':{'decision':'REQUIRES_NEW_GROUND_TRUTH_DESIGN','direct_relabeling_of_E10_E13_prohibited':True,'reason':'They are bounded controlled DDoS-like HTTP workloads from logical aliases on one physical VM, and E13 did not establish convergence to frozen training DDoS. They are useful diagnostic evidence, not scientifically adequate direct DDoS labels.'},'future_data_methodology':['isolated lab only','multiple independent traffic-generator nodes rather than logical aliases','bounded safe reproducible profiles','explicit ground-truth labels','independent adaptation/validation/final sessions','raw PCAP, 84-column CSV, exact 78 matrix, and provenance preservation','extracted-feature workload-intensity recording'],'future_requirements_file':'reports/experiment_e/preregistration/e14_future_rfv4_requirements.md','evidence_matrix_file':'reports/experiment_e/decision/e14_evidence_matrix.csv','thesis_interpretation':{'demonstrated':['RF-v3 materially corrected the scoped PortScan runtime-generalization failure and preserved Normal behavior in tested E6/E7/E13 scope.','RF-v3 had very low detection sensitivity on evaluated controlled DDoS-like runtime profiles.'],'strongly_indicated':['The paired RF-v2/RF-v3 evidence signals changed DDoS decision boundaries on recovered/evaluated vectors.','Runtime DDoS-like workloads materially differ from frozen E4 DDoS distributions.'],'unresolved':['Mechanism and universality of DDoS weakness; broader lab-vs-training domain mismatch; performance on properly designed new DDoS ground truth.'],'must_not_claim':['RF-v3 cannot detect DDoS.','E10/E13 were real distributed DDoS attacks.','E10/E13 are directly suitable DDoS training labels.','RF-v4 has been created, trained, authorized, or promoted.']},'safety_assertions':{'no_traffic':True,'no_training_or_model_change':True,'no_runtime_database_writes':True,'no_promotion_or_E9_authorization':True}}
 (OUT/'e14_remediation_decision.json').write_text(json.dumps(payload,indent=2,sort_keys=True)+'\n')
 summary='''# E14 Remediation Decision

Decision: **RFV4_EXPERIMENT_JUSTIFIED** — only as a future, separately preregistered three-class research experiment. No RF-v4 was created or authorized, and RF-v3 remains inactive.

- PortScan remediation: **SUPPORTED** in the tested E6/E7 scope (RF-v3 recall 0.999334/0.998336 vs RF-v2 0).
- Normal preservation: **SUPPORTED** within the tested E6/E7/E13 scope.
- Controlled DDoS-like runtime weakness: **SUPPORTED** in scope; this is not universal DDoS recall.
- RF-v2→RF-v3 DDoS regression signal: **PARTIALLY_SUPPORTED**; paired changed decisions are demonstrated, universal degradation is not.
- Runtime/training DDoS distribution shift: **SUPPORTED**; causal mechanism remains unresolved.
- Primary pipeline defect explanation: **NOT_SUPPORTED** by exact E12 reproduction and E13 contract/hash checks.

E10/E13 must not be directly relabeled as DDoS training data. The required next design uses new explicit ground truth and independent generator nodes in an isolated, bounded lab; see the future requirements document.
'''
 (OUT/'e14_remediation_decision_summary.md').write_text(summary)
 print(json.dumps({str(p.relative_to(ROOT)):h(p) for p in targets}))
if __name__=='__main__': main()
