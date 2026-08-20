from __future__ import annotations

from src.ingestion.flow_extractor import FlowCsvExtractor


def test_offline_flow_csv_conversion(tmp_path) -> None:
    path = tmp_path / "flows.csv"
    path.write_text("Flow Duration,Destination Port\n100,80\n", encoding="utf-8")
    rows = list(FlowCsvExtractor().read(path))
    assert rows[0].fields == {"Flow Duration": "100", "Destination Port": "80"}
    assert FlowCsvExtractor.field_names(path) == ["Flow Duration", "Destination Port"]
