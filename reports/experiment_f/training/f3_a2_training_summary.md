# Experiment F3-A2 RF-v4 candidate training

Decision: `F3_A2_RF_V4_TRAINING_PASS`. Validation readiness: `F4_RF_V4_VALIDATION_READY`.

One inactive candidate, `rf-v4.0-candidate-01`, was fitted on all 6,698 authorized rows using the exact RF-v3 preprocessing and Random Forest parameters. No split, tuning, cross-validation, validation/final inspection, runtime activation, or promotion occurred.

The estimator has 78 ordered features, 200 trees, class order `['DDoS', 'Normal', 'PortScan']`, and random state 42. The independent repeat-fit matched fixed-subset predictions and probabilities, estimator random states, complete parameters, classes, and exact tree identity.

The additional Experiment F DDoS rows are controlled HTTP DDoS-like/load profiles under Amendment A1. Training success is not evidence of improved detection or generalization; validation is required.

Model SHA256: `d5dccd339a5c67635e760d7d3760e1d006278362c6f70ea06bf20928ccdece13`. Metadata SHA256: `9f8bb215740943b326b6ec6f76e55caef4d094290ac43ed30cb7e32884a47a1a`. Reproducibility-audit SHA256: `314269a72da6053f2af1c7e63818b46fef1c403fb472a5cd19b27bffe14cab70`. Training-audit SHA256: `904913caa8c2c8b027a09b40eb5db9aff4688f28923fbae878bc469971e156de`.
