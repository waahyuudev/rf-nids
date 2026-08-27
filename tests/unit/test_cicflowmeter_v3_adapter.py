from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pandas.testing as pdt
import pytest

from src.ingestion.cicflowmeter_v3_adapter import (
    ARTIFACT_FIELDS,
    MAPPING_RULES,
    MODEL_FEATURES,
    CICFlowMeterV3AdapterError,
    CICFlowMeterV3ModelAdapter,
)


ROOT = Path(__file__).resolve().parents[2]
NORMAL = ROOT / "data/lab/flows/cicflowmeter-v3/normal-http-test.pcap_ISCX.csv"
PORTSCAN = ROOT / "data/lab/flows/cicflowmeter-v3/portscan-test.pcap_ISCX.csv"


@pytest.fixture
def raw_row() -> pd.DataFrame:
    return pd.read_csv(NORMAL, nrows=1)


def test_output_has_exactly_78_columns(raw_row: pd.DataFrame) -> None:
    assert CICFlowMeterV3ModelAdapter().adapt(raw_row).features.shape == (1, 78)


def test_output_order_is_active_model_order(raw_row: pd.DataFrame) -> None:
    result = CICFlowMeterV3ModelAdapter.from_metadata(ROOT / "models/model_metadata.json").adapt(raw_row)
    assert tuple(result.features.columns) == MODEL_FEATURES


def test_output_has_no_missing_or_extra_features(raw_row: pd.DataFrame) -> None:
    columns = CICFlowMeterV3ModelAdapter().adapt(raw_row).features.columns
    assert set(columns) == set(MODEL_FEATURES)


def test_output_has_no_duplicate_features(raw_row: pd.DataFrame) -> None:
    assert not CICFlowMeterV3ModelAdapter().adapt(raw_row).features.columns.duplicated().any()


def test_missing_source_field_fails_closed(raw_row: pd.DataFrame) -> None:
    with pytest.raises(CICFlowMeterV3AdapterError, match="Missing required V3"):
        CICFlowMeterV3ModelAdapter().adapt(raw_row.drop(columns=["Dst Port"]))


def test_duplicate_source_header_fails_closed(raw_row: pd.DataFrame) -> None:
    duplicate = pd.concat([raw_row, raw_row[["Dst Port"]]], axis=1)
    with pytest.raises(CICFlowMeterV3AdapterError, match="Duplicate V3"):
        CICFlowMeterV3ModelAdapter().adapt(duplicate)


def test_artifact_reproductions_use_reviewed_sources(raw_row: pd.DataFrame) -> None:
    adapted = CICFlowMeterV3ModelAdapter().adapt(raw_row).features.iloc[0]
    rules = {target: source for target, source, _ in MAPPING_RULES}
    assert len(ARTIFACT_FIELDS) == 9
    for target in ARTIFACT_FIELDS:
        assert adapted[target] == pytest.approx(float(raw_row.iloc[0][rules[target]]))
    assert adapted["cwe_flag_count"] == adapted["fwd_urg_flags"]
    assert adapted["fwd_header_length.1"] == adapted["fwd_header_length"]


def test_nonfinite_values_become_nan_without_imputation(raw_row: pd.DataFrame) -> None:
    changed = raw_row.copy(deep=True)
    changed.loc[0, "Flow Byts/s"] = np.inf
    changed.loc[0, "Flow Pkts/s"] = -np.inf
    result = CICFlowMeterV3ModelAdapter().adapt(changed)
    assert np.isnan(result.features.loc[0, "flow_bytes_s"])
    assert np.isnan(result.features.loc[0, "flow_packets_s"])
    assert result.provenance["imputation_performed"] is False


def test_input_dataframe_is_not_mutated(raw_row: pd.DataFrame) -> None:
    before = raw_row.copy(deep=True)
    CICFlowMeterV3ModelAdapter().adapt(raw_row)
    pdt.assert_frame_equal(raw_row, before)


def test_adaptation_is_deterministic(raw_row: pd.DataFrame) -> None:
    adapter = CICFlowMeterV3ModelAdapter()
    first = adapter.adapt(raw_row)
    second = adapter.adapt(raw_row)
    pdt.assert_frame_equal(first.features, second.features)
    assert first.provenance == second.provenance


@pytest.mark.parametrize("fixture", [NORMAL, PORTSCAN])
def test_official_v3_fixture_adapts_without_prediction(fixture: Path) -> None:
    result = CICFlowMeterV3ModelAdapter().adapt_csv(fixture)
    assert len(result.features) == len(pd.read_csv(fixture))
    assert result.features.shape[1] == 78
    assert result.provenance["schema_validation"] == "PASS"

