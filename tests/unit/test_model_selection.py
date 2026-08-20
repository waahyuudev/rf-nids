from src.evaluation.compare_models import choose_active_model, selection_criteria


def result(
    *, macro_f1: float, ddos_recall: float, portscan_recall: float, false_alarms: int
) -> dict:
    return {
        "metrics": {
            "macro_f1": macro_f1,
            "classification_report": {
                "Normal": {"support": 100},
                "DDoS": {"recall": ddos_recall},
                "PortScan": {"recall": portscan_recall},
            },
            "ids_error_counts": {"normal_predicted_as_attack": false_alarms},
            "average_inference_time_seconds_per_row": 0.001,
        }
    }


def test_tuned_is_not_selected_when_macro_f1_is_lower() -> None:
    baseline = result(macro_f1=0.99, ddos_recall=0.98, portscan_recall=0.97, false_alarms=2)
    tuned = result(macro_f1=0.98, ddos_recall=1.0, portscan_recall=1.0, false_alarms=0)
    selected, comparison = choose_active_model(baseline, tuned)
    assert selected == "baseline"
    assert comparison["selected"] == "baseline"


def test_lower_false_positive_rate_breaks_complete_metric_tie() -> None:
    baseline = result(macro_f1=0.99, ddos_recall=0.98, portscan_recall=0.97, false_alarms=2)
    tuned = result(macro_f1=0.99, ddos_recall=0.98, portscan_recall=0.97, false_alarms=1)
    selected, _ = choose_active_model(baseline, tuned)
    assert selected == "tuned"
    assert selection_criteria(tuned)["normal_traffic_false_positive_rate"] == 0.01

