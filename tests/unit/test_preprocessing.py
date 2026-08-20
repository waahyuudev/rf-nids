import numpy as np
import pandas as pd
import pytest

from src.preprocessing.dataset import prepare_dataset


def sample_frame(rows_per_class: int = 10) -> pd.DataFrame:
    labels = (
        ["BENIGN"] * rows_per_class
        + ["DDoS Hulk"] * rows_per_class
        + ["Port Scan"] * rows_per_class
    )
    size = len(labels)
    return pd.DataFrame(
        {
            " Label ": labels,
            "Flow ID": [f"flow-{index}" for index in range(size)],
            "Source IP": [f"10.0.0.{index}" for index in range(size)],
            "Protocol": ["TCP"] * size,
            "Flow Duration": np.arange(size, dtype=float),
            "Packets": np.arange(size, dtype=float) + 2,
        }
    )


def test_filtering_leakage_numeric_selection_and_infinity() -> None:
    frame = sample_frame()
    frame.loc[0, "Flow Duration"] = np.inf
    frame.loc[len(frame)] = ["Bot", "bot-flow", "10.1.1.1", "TCP", 999, 999]
    prepared = prepare_dataset(
        frame,
        label_column="Label",
        leakage_columns={"flow_id": "identifier", "source_ip": "identity", "label": "target"},
    )
    assert prepared.audit["rows_excluded_out_of_scope"] == 1
    assert prepared.audit["feature_names"] == ["flow_duration", "packets"]
    assert prepared.audit["metadata_columns"] == ["flow_id", "source_ip"]
    assert prepared.audit["removed_features"] == {
        "flow_id": "identifier",
        "source_ip": "identity",
        "protocol": "non-numeric feature",
    }
    assert prepared.audit["infinite_values_replaced"]["flow_duration"] == 1
    assert prepared.x_train.isna().sum().sum() + prepared.x_test.isna().sum().sum() == 1
    assert prepared.audit["test_distribution"] == {"Normal": 2, "DDoS": 2, "PortScan": 2}


def test_duplicate_removal_happens_before_split() -> None:
    frame = sample_frame()
    frame = pd.concat([frame, frame.iloc[[0]]], ignore_index=True)
    prepared = prepare_dataset(frame, label_column="label", leakage_columns={})
    assert prepared.audit["duplicate_rows_removed"] == 1
    assert prepared.audit["rows_after_filtering_and_deduplication"] == 30
    assert prepared.audit["train_rows"] == 24
    assert prepared.audit["test_rows"] == 6


def test_missing_label_is_rejected() -> None:
    with pytest.raises(ValueError, match="Label column"):
        prepare_dataset(sample_frame(), label_column="target", leakage_columns={})


def test_all_target_classes_are_required() -> None:
    frame = sample_frame()
    frame = frame.loc[frame[" Label "] != "Port Scan"]
    with pytest.raises(ValueError, match="missing"):
        prepare_dataset(frame, label_column="label", leakage_columns={})

