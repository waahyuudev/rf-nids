from dashboard.presentation import (
    class_probability_rows,
    comparison_rows,
    confusion_matrix_view,
    dataset_view,
    model_view,
    percent,
    prediction_context,
    split_evaluations,
)


def test_dataset_and_model_mapping_preserve_imported_values_and_nulls():
    dataset = dataset_view({"name": "cicids2017", "total_rows": None, "total_features": 78})
    assert dataset["Dataset name"] == "cicids2017"
    assert dataset["Total rows"] == "Not available"
    assert dataset["Total features"] == 78
    model = model_view({
        "model_name": "RF-NIDS Random Forest", "is_active": True, "feature_count": 78,
        "class_labels": ["Normal", "DDoS", "PortScan"], "artifact_sha256": "a" * 64,
        "experiment_name": "Experiment A",
    })
    assert model["Status"] == "Active"
    assert model["Feature count"] == 78
    assert model["Artifact SHA-256"] == "a" * 64
    assert model["Linked experiment"] == "Experiment A"


def test_experiment_rows_null_metrics_and_confusion_matrix_mapping():
    rows = [
        {"metric_key": "CLASS:DDoS", "class_name": "DDoS", "recall_score": 0.0},
        {"metric_key": "OVERALL", "class_name": None, "accuracy": 0.005404447594577833, "macro_f1": None,
         "confusion_matrix": {"labels": ["Normal", "DDoS", "PortScan"], "values": [[61, 0, 0], [10226, 0, 0], [1000, 0, 0]]}},
        {"metric_key": "CLASS:Normal", "class_name": "Normal", "recall_score": 1.0},
        {"metric_key": "CLASS:PortScan", "class_name": "PortScan", "recall_score": 0.0},
    ]
    overall, classes = split_evaluations(rows)
    assert [row["class_name"] for row in classes] == ["Normal", "DDoS", "PortScan"]
    assert percent(overall["macro_f1"]) == "Not available"
    assert confusion_matrix_view(overall["confusion_matrix"]) == (
        ["Normal", "DDoS", "PortScan"], [[61, 0, 0], [10226, 0, 0], [1000, 0, 0]]
    )
    assert confusion_matrix_view({"labels": ["Normal"], "values": []}) is None


def test_experiment_a_b_c_selector_comparison_uses_available_values_only():
    experiments = [
        {"id": 1, "experiment_code": "EXPERIMENT_A", "experiment_type": "INTERNAL"},
        {"id": 2, "experiment_code": "EXPERIMENT_B", "experiment_type": "HOLDOUT"},
        {"id": 3, "experiment_code": "EXPERIMENT_C", "experiment_type": "EXTERNAL_VALIDATION"},
    ]
    evaluations = {
        1: [{"metric_key": "OVERALL", "accuracy": .99, "macro_f1": .98}],
        2: [{"metric_key": "OVERALL", "accuracy": .8, "macro_f1": .7}],
        3: [{"metric_key": "OVERALL", "accuracy": .005404447594577833, "macro_f1": None},
            {"metric_key": "CLASS:DDoS", "class_name": "DDoS", "recall_score": 0.0},
            {"metric_key": "CLASS:PortScan", "class_name": "PortScan", "recall_score": 0.0}],
    }
    result = comparison_rows(experiments, evaluations)
    assert [row["Experiment"] for row in result] == ["Experiment A", "Experiment B", "Experiment C"]
    assert result[2]["Accuracy"] == 0.005404447594577833
    assert result[2]["Macro F1"] is None
    assert result[2]["DDoS Recall"] == result[2]["PortScan Recall"] == 0.0


def test_prediction_mapping_uses_only_actual_probabilities_and_provenance():
    assert class_probability_rows(None) == []
    assert class_probability_rows({"DDoS": 0.8, "Normal": 0.1}) == [
        {"Class": "Normal", "Probability": 0.1},
        {"Class": "DDoS", "Probability": 0.8},
    ]
    runtime = prediction_context({"source_type": None, "experiment_code": None})
    assert runtime["Runtime context"] == "Runtime inference"
    assert runtime["Experiment"] == "Not available"
    imported = prediction_context({"source_type": "EXPERIMENT_IMPORT"})
    assert imported["Runtime context"] == "Imported context"
