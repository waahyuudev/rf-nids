import numpy as np
import pandas as pd
import pytest

from src.evaluation.baseline import evaluate_predictions


def test_multiclass_metrics_and_false_positive_rates() -> None:
    truth = pd.Series(["Normal", "Normal", "DDoS", "DDoS", "PortScan", "PortScan"])
    predicted = np.array(["Normal", "DDoS", "DDoS", "Normal", "PortScan", "Normal"])
    metrics = evaluate_predictions(truth, predicted, prediction_time_seconds=0.6)
    assert metrics["confusion_matrix"] == [[1, 1, 0], [1, 1, 0], [1, 0, 1]]
    assert metrics["false_positive_rate_one_vs_rest"] == {
        "Normal": 0.5,
        "DDoS": 0.25,
        "PortScan": 0.0,
    }
    assert metrics["ids_error_counts"] == {
        "normal_predicted_as_attack": 1,
        "ddos_predicted_as_normal": 1,
        "portscan_predicted_as_normal": 1,
    }
    assert metrics["average_inference_time_seconds_per_row"] == pytest.approx(0.1)
