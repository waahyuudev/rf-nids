from pathlib import Path

import pandas as pd

from src.data.loading import load_csv_files


def test_cicids_schemas_match_after_normalization(tmp_path: Path) -> None:
    first = pd.DataFrame({" Feature ": [1], " Label ": ["BENIGN"]})
    second = pd.DataFrame({" Feature ": [2], " Label ": ["DDoS"]})
    first_path = tmp_path / "first.csv"
    second_path = tmp_path / "second.csv"
    first.to_csv(first_path, index=False)
    second.to_csv(second_path, index=False)
    combined = load_csv_files([first_path, second_path])
    assert list(combined.columns) == ["feature", "label", "source_file"]
    assert combined["source_file"].tolist() == ["first.csv", "second.csv"]
    assert combined["feature"].tolist() == [1, 2]
