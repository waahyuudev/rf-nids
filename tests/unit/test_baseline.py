import numpy as np
import pandas as pd

from src.preprocessing.dataset import prepare_dataset
from src.training.train_baseline import BASELINE_PARAMETERS, build_baseline_pipeline, train_baseline


def test_pipeline_fits_imputer_from_training_partition_only() -> None:
    random = np.random.default_rng(42)
    labels = np.repeat(["Normal", "DDoS", "PortScan"], 20)
    centers = np.repeat([0.0, 10.0, 20.0], 20)
    frame = pd.DataFrame(
        {
            "label": labels,
            "feature_a": centers + random.normal(0, 0.1, len(labels)),
            "feature_b": centers + random.normal(0, 0.1, len(labels)),
        }
    )
    frame.loc[0, "feature_a"] = np.nan
    prepared = prepare_dataset(frame, label_column="label", leakage_columns={})
    pipeline, metrics = train_baseline(prepared)
    expected_medians = np.nanmedian(prepared.x_train.to_numpy(), axis=0)
    np.testing.assert_allclose(pipeline.named_steps["imputer"].statistics_, expected_medians)
    assert list(pipeline.named_steps) == ["imputer", "classifier"]
    assert pipeline.named_steps["classifier"].get_params()["n_estimators"] == 100
    assert pipeline.named_steps["classifier"].get_params()["class_weight"] == "balanced"
    assert 0.8 <= metrics["macro_f1"] <= 1.0


def test_baseline_configuration_and_unfitted_pipeline() -> None:
    pipeline = build_baseline_pipeline()
    assert BASELINE_PARAMETERS == {
        "n_estimators": 100,
        "random_state": 42,
        "n_jobs": -1,
        "class_weight": "balanced",
    }
    assert not hasattr(pipeline.named_steps["imputer"], "statistics_")
