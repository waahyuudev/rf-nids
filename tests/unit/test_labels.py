import pytest

from src.preprocessing.labels import map_label


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("BENIGN", "Normal"),
        (" normal ", "Normal"),
        ("DDoS", "DDoS"),
        ("  DDoS   Hulk ", "DDoS"),
        ("PortScan", "PortScan"),
        ("port scan", "PortScan"),
        ("Bot", None),
        (None, None),
    ],
)
def test_map_label(raw: object, expected: str | None) -> None:
    assert map_label(raw) == expected

