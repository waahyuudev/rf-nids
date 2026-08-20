import pytest

from src.preprocessing.columns import normalize_column_name, normalize_columns


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (" Flow Duration ", "flow_duration"),
        ("Source IP/Port", "source_ip_port"),
        ("  Multiple   Spaces ", "multiple_spaces"),
    ],
)
def test_normalize_column_name(raw: str, expected: str) -> None:
    assert normalize_column_name(raw) == expected


def test_normalize_columns_rejects_collision() -> None:
    with pytest.raises(ValueError, match="duplicates"):
        normalize_columns(["Source IP", "source_ip"])

