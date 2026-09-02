# Final Black-Box Testing

Executed: 2026-09-02T08:01:15Z  
Scope: final application behavior only; no scientific experiment was rerun and no frozen source was mutated.

## Method

The black-box cases were executed through FastAPI's HTTP boundary with isolated SQLite databases and deterministic development-only inference doubles. Dashboard authentication, presentation mapping, and failure behavior were exercised through the Streamlit client/presentation boundary. Canonical A/B/C data was loaded only by the allowlisted read-only evidence synchronizer. This is the same safe method established in Phases 2–7 and keeps Experiment C separate from runtime traffic.

The authoritative full-suite command was:

```text
PYTHONPATH=. .venv/bin/python -m pytest -q
```

Result: **156 passed, 0 failed, 329 warnings in 13.01 seconds**. The warnings comprise one Starlette/TestClient compatibility deprecation and 328 Joblib/NumPy deprecations; none is a functional failure.

## Results

The machine-readable execution record is `reports/application/black_box_test_results.csv`. All **24 required cases passed**: authentication 4/4, dataset 1/1, model 1/1, evaluation 3/3, monitoring 2/2, predictions 2/2, alerts 5/5, exports 4/4, graceful error handling 1/1, and restart/session handling 1/1.

The controlled end-to-end sequence passed: administrator creation/login → protected dashboard/dataset/model/evaluation reads → runtime inference → atomic flow/prediction persistence → monitoring/prediction/detail reads → deterministic attack alert/detail → authenticated acknowledgment → authenticated exports → logout/revocation. The sequence is distributed across isolated integration cases so each precondition and outcome is independently assertable. Experiment C per-flow rows were not used as runtime input.

## Limitations

This final run did not capture a new browser screenshot set or exercise a production PostgreSQL server. UI behavior was validated at the client/presentation boundary and had already received live browser smoke verification in Phases 3–7. Alembic migration tests validate SQLite upgrade behavior and PostgreSQL DDL generation. Chapter IV screenshots remain a human capture task listed in `docs/chapter_4_screenshot_checklist.md`.
