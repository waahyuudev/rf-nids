#!/usr/bin/env python3
"""Create-new F1 preflight plans; deliberately performs no VM/network actions."""
from __future__ import annotations
import hashlib,json
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
frozen=['config/experiment_f.yaml','reports/experiment_f/preregistration/f0_preregistration.json','reports/experiment_f/preregistration/f0_ground_truth_design.json','reports/experiment_f/preregistration/f0_acceptance_gates.json','docs/experiment_f_operator_plan.md','models/experiment_d/random_forest_rf_v2.joblib','models/experiment_e/random_forest_rf_v3_candidate.joblib','models/experiment_e/random_forest_rf_v3_candidate_metadata.json','reports/experiment_d/final_test/dataset_audit.json','reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv']
def h(p):
 d=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''):d.update(b)
 return d.hexdigest()
def w(p,s):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(s,encoding='utf-8')
def main():
 out=[ROOT/'reports/experiment_f/preflight/f1_topology_plan.json',ROOT/'reports/experiment_f/preflight/f1_resource_plan.md',ROOT/'reports/experiment_f/preflight/f1_operator_checklist.md',ROOT/'reports/experiment_f/preflight/f1_preflight_evidence.json']
 if any(p.exists() for p in out):raise FileExistsError('F1 evidence is create-new only')
 before={x:h(ROOT/x) for x in frozen};f0=json.loads((ROOT/frozen[1]).read_text());gt=json.loads((ROOT/frozen[2]).read_text())
 if f0['gate']!='PASS' or f0['topology']['nodes']['ubuntu-nids_egress_capture']!='10.10.20.1/24, enp0s3':raise RuntimeError('F0 topology contract gate failed')
 topology={'schema':'experiment_f_f1_topology_plan','version':1,'status':'PENDING_OPERATOR_VALIDATION','design_consistency_audit':{'historical_reusable_conditional':['ubuntu-nids at 10.10.10.1 and 10.10.20.1, with scientific capture enp0s3','ubuntu-target at 10.10.20.2:8080'],'not_reusable_as_generators':['historical ubuntu-traffic at 10.10.10.2','the E10/E13 one-VM logical-source design'],'new_required':['ubuntu-traffic-1','ubuntu-traffic-2','ubuntu-traffic-3','ubuntu-traffic-4'],'conflict_warning':'10.10.10.11-.14 were historical logical identities, not proof of currently free addresses. Live address/ARP/VM inventory checks must pass before assignment.'},'ip_allocation':[{'node':'ubuntu-traffic-1','experiment_ip':'10.10.10.11/24','gateway':'10.10.10.1','role':'independent generator'},{'node':'ubuntu-traffic-2','experiment_ip':'10.10.10.12/24','gateway':'10.10.10.1','role':'independent generator'},{'node':'ubuntu-traffic-3','experiment_ip':'10.10.10.13/24','gateway':'10.10.10.1','role':'independent generator'},{'node':'ubuntu-traffic-4','experiment_ip':'10.10.10.14/24','gateway':'10.10.10.1','role':'independent generator'},{'node':'ubuntu-nids','source_ip':'10.10.10.1/24','target_ip':'10.10.20.1/24','scientific_capture_interface':'enp0s3','role':'router/observer'},{'node':'ubuntu-target','experiment_ip':'10.10.20.2/24','gateway':'10.10.20.1','service':'owned HTTP :8080'}],'routing_requirements':['Each generator has a route to 10.10.20.0/24 via 10.10.10.1.','ubuntu-nids has IP forwarding enabled and routes between 10.10.10.0/24 and 10.10.20.0/24.','ubuntu-target return route for 10.10.10.0/24 is via 10.10.20.1.','Management network, if used, is a separate NIC/subnet and is not a scientific capture or traffic route.','Scientific observation is only ubuntu-nids enp0s3; never `any` and no duplicate capture.'],'independence_gate':{'required_per_generator':['hostname','machine-id/VM UUID','experiment NIC MAC address','experiment IP','routing table','VM inventory record'],'pass_rule':'Four distinct VM identities and MAC addresses map one-to-one to the four experiment IPs; each is separately provisioned.','fail_rule':'Any repeated machine-id/VM UUID, shared OS instance/namespace, or alias-only identity is INVALID.'},'not_authorized':['F2 traffic collection','DDoS/PortScan/load generation','RF-v4 training or creation','runtime DB writes','model/threshold changes']}
 evidence={'schema':'experiment_f_f1_preflight_evidence','version':1,'status':'PENDING_OPERATOR_VALIDATION','created_at_utc':datetime.now(timezone.utc).isoformat(),'scope':'Repository/F0 consistency audit and operator-plan creation only; no live VM/network check was performed.','f0_consistency':'PASS','live_gates':{k:'PENDING' for k in ['four independent generator VM identities','IP conflict clearance for 10.10.10.11-.14','observer/router identity and IP forwarding','generator routes','target return route','enp0s3 capture-interface identity/visibility','controlled target and benign HTTP response','CICFlowMeter provenance','RF-v2/RF-v3 hashes','78-feature contract','no D/E frozen-evidence change']},'frozen_hashes_before':before,'provenance_expected':{'rf_v2_sha256':'fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31','rf_v3_sha256':'6b01c7b3923c1a6bd471862d011f8f5b88a31378e51d1dde082bd2e72bedef86','rf_v3_metadata_sha256':'30b6bdf2a6cb2d60e2be36d4db1e124d71504393081b229e6d94da7e70322cbc','crosswalk_sha256':'66e517cdcea217f19de4d0a2cd45302ede999388393f539fb8ca4a2c68b74cf4','feature_count':78,'feature_order_sha256':'9338f50fc3e7efc78d678cc65ab38d428a7f6912ed9467a2b99a449a7c8e3c13','capture_interface':'enp0s3'},'F2_authorized':False,'pass_condition':'Only an operator-completed evidence update showing every live gate PASS may support F1 PASS; configuration alone cannot.'}
 resources='''# F1 Resource Plan — Apple Silicon Host (16 GB RAM)

This is a lightweight headless topology plan. It intentionally leaves substantial host RAM for macOS, the hypervisor, and capture tooling.

| VM | vCPU | RAM | Disk | NICs | Notes |
|---|---:|---:|---:|---:|---|
| ubuntu-traffic-1..4 | 1 each | 768 MB each | 8 GB each | 2 | Headless; experiment NIC plus optional separate management NIC. |
| ubuntu-nids | 2 | 3 GB | 24 GB | 3 | Source experiment NIC, target experiment NIC (`enp0s3` capture), optional management NIC. |
| ubuntu-target | 1 | 1.5 GB | 16 GB | 2 | Target experiment NIC plus optional separate management NIC. |

Provisioned guest RAM is 7.5 GB and 7 vCPU total. Do not use a management interface for scientific traffic or capture. If a hypervisor uses different interface names, resolve and document which target-side NIC is `enp0s3` before F2; changing F0's capture interface is not allowed.
'''
 checklist='''# F1 Operator Checklist — Preflight Only

Status remains **PENDING_OPERATOR_VALIDATION**. Do not run traffic generators, scanners, load tests, training, or model changes.

1. Inventory the six VMs. On each generator record hostname, `/etc/machine-id` (or VM UUID), experiment-NIC MAC, experiment IP, and `ip route`. Confirm all four identities and MACs are distinct.
2. Before assigning `.11`–`.14`, check the VM inventory and local lab address allocation for conflicts. Historical logical aliases do not clear these addresses.
3. On `ubuntu-nids`, verify `10.10.10.1`, `10.10.20.1`, forwarding state, routes, and the physical mapping of `enp0s3` to the target-side experiment network. Record link state.
4. On each generator, verify only the route to `10.10.20.0/24` through `10.10.10.1`. Use a bounded, low-count reachability check only if required.
5. On `ubuntu-target`, verify `10.10.20.2`, the return route for `10.10.10.0/24` through `10.10.20.1`, ownership/control, and the HTTP service at port 8080. At most one basic benign HTTP request per generator is permitted for connectivity; this is not F2 collection.
6. If a tiny benign connectivity check is performed, verify it is visible once on `ubuntu-nids:enp0s3`; do not use `any`, do not start a scientific capture session, and do not preserve it as F2 evidence.
7. Record Docker/API health only where needed for the locked extractor. Verify CICFlowMeter V3 identity, crosswalk SHA-256, RF-v2/RF-v3 hashes, metadata hash, 78-feature count/order SHA-256.
8. Attach command outputs/screenshots/logs to a new operator evidence addendum. Any source-identity conflict, shared VM identity, route/capture failure, checksum mismatch, or unowned target is `INVALID`/`ABORTED`; stop and do not authorize F2.
'''
 w(out[0],json.dumps(topology,indent=2,sort_keys=True)+'\n');w(out[1],resources);w(out[2],checklist)
 after={x:h(ROOT/x) for x in frozen}
 if before!=after:raise RuntimeError('frozen F0/D/E evidence changed')
 evidence['frozen_hashes_after']=after;evidence['frozen_inputs_unchanged']=True;w(out[3],json.dumps(evidence,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'status':'PENDING_OPERATOR_VALIDATION','outputs':{str(p.relative_to(ROOT)):h(p) for p in out},'integrity':'PASS'}))
if __name__=='__main__':main()
