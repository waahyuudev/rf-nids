# E14 Future Three-Class Remediation Experiment Requirements

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
