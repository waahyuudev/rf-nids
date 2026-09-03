from __future__ import annotations

import numpy as np
import pandas as pd

from src.experiment_d.d4 import (
    apply_selection_rule,
    confusion_rows,
    metrics_with_predictions,
    prediction_rows,
)


def sample_metrics(ddos: float, portscan: float, normal: float, macro_f1: float) -> dict:
    return {
        "macro_f1": macro_f1,
        "classification_report": {
            "DDoS": {"recall": ddos},
            "PortScan": {"recall": portscan},
            "Normal": {"recall": normal},
        },
    }


def test_pre_registered_selection_rule_is_applied_unchanged() -> None:
    rf_v1 = sample_metrics(0.1, 0.2, 0.8, 0.3)
    accepted = apply_selection_rule(rf_v1, sample_metrics(0.2, 0.4, 0.5, 0.3))
    assert accepted["passed"] is True
    assert accepted["rule_changed_after_results"] is False
    assert apply_selection_rule(rf_v1, sample_metrics(0.2, 0.0, 0.9, 0.8))["passed"] is False
    assert apply_selection_rule(rf_v1, sample_metrics(0.2, 0.4, 0.49, 0.8))["passed"] is False
    assert apply_selection_rule(rf_v1, sample_metrics(0.2, 0.4, 0.9, 0.29))["passed"] is False


def test_d4_metrics_and_confusion_matrix_have_frozen_class_order() -> None:
    truth = pd.Series(["Normal", "DDoS", "PortScan"])
    predicted = np.array(["Normal", "Normal", "PortScan"])
    metrics = metrics_with_predictions(truth, predicted, 0.1)
    assert metrics["confusion_matrix_labels"] == ["Normal", "DDoS", "PortScan"]
    assert metrics["prediction_count_per_class"] == {"Normal": 2, "DDoS": 0, "PortScan": 1}
    assert confusion_rows(metrics)[1] == {"ground_truth": "DDoS", "Normal": 1, "DDoS": 0, "PortScan": 0}


def test_prediction_rows_preserve_provenance_and_probability_mapping() -> None:
    provenance = [{"row_identity":"r1","source_family":"CICIDS2017","source_file":"a.csv"}]
    rows = prediction_rows(
        provenance, pd.Series(["Normal"]), np.array(["Normal"]),
        np.array([[0.2, 0.7, 0.1]]), np.array(["DDoS", "Normal", "PortScan"]),
    )
    assert rows[0]["row_identity"] == "r1"
    assert rows[0]["confidence"] == 0.7
    assert rows[0]["probability_DDoS"] == 0.2
    assert rows[0]["probability_Normal"] == 0.7
