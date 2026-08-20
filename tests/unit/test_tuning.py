import numpy as np
import pandas as pd

from src.preprocessing.dataset import prepare_dataset
from src.training.train_tuned import PARAMETER_DISTRIBUTIONS, tune_random_forest


def test_parameter_space_matches_project_specification() -> None:
    assert PARAMETER_DISTRIBUTIONS == {
        "classifier__n_estimators": [100, 200, 300, 500],
        "classifier__max_depth": [None, 10, 20, 30, 50],
        "classifier__min_samples_split": [2, 5, 10],
        "classifier__min_samples_leaf": [1, 2, 4],
        "classifier__max_features": ["sqrt", "log2", None],
        "classifier__class_weight": [None, "balanced"],
        "classifier__bootstrap": [True, False],
    }


def test_randomized_search_uses_stratified_cv_and_returns_metrics() -> None:
    random = np.random.default_rng(42)
    labels = np.repeat(["Normal", "DDoS", "PortScan"], 12)
    centers = np.repeat([0.0, 10.0, 20.0], 12)
    frame = pd.DataFrame(
        {
            "label": labels,
            "feature_a": centers + random.normal(0, 0.01, len(labels)),
            "feature_b": centers + random.normal(0, 0.01, len(labels)),
        }
    )
    prepared = prepare_dataset(frame, label_column="label", leakage_columns={})
    parameters = {
        "classifier__n_estimators": [10],
        "classifier__max_depth": [5],
    }
    model, metrics, results = tune_random_forest(
        prepared,
        iterations=1,
        cv=2,
        parameter_distributions=parameters,
        n_jobs=1,
        tuning_sample_size=24,
    )
    assert model.named_steps["classifier"].n_estimators == 10
    assert metrics["best_cross_validation_index"] == 0
    assert 0 <= metrics["best_cross_validation_f1_macro"] <= 1
    assert len(results) == 1
    assert metrics["tuning_sample_rows"] == 24
    assert metrics["full_training_refit_time_seconds"] >= 0
