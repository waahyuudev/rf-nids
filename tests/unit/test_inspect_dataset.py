import numpy as np
import pandas as pd

from src.data.inspect_dataset import inspect_dataframe


def test_inspection_filters_classes_and_records_quality_issues() -> None:
    frame = pd.DataFrame(
        {
            " Label ": ["BENIGN", "DDoS Hulk", "Port Scan", "Bot"],
            "Flow Duration": [1.0, np.inf, 3.0, 4.0],
            "Source IP": ["a", "b", "c", "d"],
        }
    )
    report, labels = inspect_dataframe(
        frame,
        dataset_name="tiny.csv",
        label_column="label",
        leakage_columns={"label": "target", "source_ip": "identity"},
    )
    assert labels.tolist() == ["Normal", "DDoS", "PortScan"]
    assert report["excluded_rows"] == 1
    assert report["excluded_class_distribution"] == {"Bot": 1}
    assert report["infinite_values"]["flow_duration"] == 1
    assert report["potential_leakage_columns"] == {"label": "target", "source_ip": "identity"}

