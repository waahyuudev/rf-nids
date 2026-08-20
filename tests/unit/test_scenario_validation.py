import numpy as np
import pandas as pd
import pytest
from sklearn.impute import SimpleImputer

from src.evaluation.scenario_validation import (
    build_validation_comparison,
    prepare_scenario_dataset,
)


def scenario_frame(rows: int = 30) -> pd.DataFrame:
    parts = []
    for source, label, offset in (
        ("normal.csv", "BENIGN", 0),
        ("ddos.csv", "DDoS", 100),
        ("portscan.csv", "PortScan", 200),
    ):
        parts.append(
            pd.DataFrame(
                {
                    "Label": [label] * rows,
                    "source_file": [source] * rows,
                    "Flow Duration": np.arange(rows, dtype=float) + offset,
                    "Packets": np.arange(rows, dtype=float) + 1,
                    "Fwd Header Length": np.arange(rows, dtype=float),
                    "Fwd Header Length.1": np.arange(rows, dtype=float),
                }
            )
        )
    return pd.concat(parts, ignore_index=True)


def test_scenario_has_no_group_overlap_and_source_is_not_feature() -> None:
    result = prepare_scenario_dataset(
        scenario_frame(), label_column="label", leakage_columns={}, block_size=5
    )
    prepared = result.prepared
    assert "source_file" not in prepared.audit["feature_names"]
    assert prepared.audit["source_file_used_as_feature"] is False
    train_groups = set(prepared.metadata_train["scenario_group"])
    test_groups = set(prepared.metadata_test["scenario_group"])
    assert train_groups.isdisjoint(test_groups)
    assert set(prepared.y_train) == {"Normal", "DDoS", "PortScan"}
    assert set(prepared.y_test) == {"Normal", "DDoS", "PortScan"}
    assert result.feature_audit["fwd_header_length_comparison"]["identical"] is True


def test_imputer_statistics_are_fit_from_training_only() -> None:
    frame = scenario_frame(rows=10)
    # Last ordered block is test and contains values that would move a global median.
    frame.loc[frame.groupby(["source_file", "Label"]).tail(2).index, "Packets"] = 10000
    result = prepare_scenario_dataset(
        frame, label_column="label", leakage_columns={}, block_size=2
    )
    imputer = SimpleImputer(strategy="median").fit(result.prepared.x_train)
    packet_index = result.prepared.x_train.columns.get_loc("packets")
    assert imputer.statistics_[packet_index] == pytest.approx(
        result.prepared.x_train["packets"].median()
    )
    assert imputer.statistics_[packet_index] != pytest.approx(
        pd.concat([result.prepared.x_train, result.prepared.x_test])["packets"].median()
    )


def test_validation_comparison_contains_required_metrics() -> None:
    baseline = {
        "metrics": {
            "accuracy": 0.9,
            "macro_f1": 0.8,
            "classification_report": {
                "Normal": {"support": 10},
                "DDoS": {"recall": 0.7},
                "PortScan": {"recall": 0.6},
            },
            "ids_error_counts": {"normal_predicted_as_attack": 1},
        }
    }
    scenario = {
        "metrics": {
            "accuracy": 0.8,
            "macro_f1": 0.7,
            "recall_by_class": {"DDoS": 0.5, "PortScan": 0.4},
            "false_positive_rate_normal_as_attack": 0.2,
        }
    }
    comparison = build_validation_comparison(baseline, scenario)
    assert comparison["change_b_minus_a"]["accuracy"] == pytest.approx(-0.1)
    assert comparison["active_model_reselected"] is False
