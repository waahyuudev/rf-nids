from pathlib import Path

from scripts.run_rf_v2_application_integration import run_validation


def test_actual_rf_v2_application_integration_and_rollback(tmp_path: Path) -> None:
    result = run_validation(tmp_path / "validation.json")
    assert result["status"] == "PASS"
    assert result["black_box_passed"] == 8
    assert result["rf_v2"]["active_after_validation"] is True
    assert result["rollback_verified"] is True
    assert result["scientific_integrity"]["status"] == "PASS"
