# Pinned historical Java CICFlowMeter

This image is isolated from `docker/cicflowmeter/` and exists only for offline
Experiment C compatibility validation. It targets `linux/amd64`, Java 8, Gradle
4.2, and jNetPcap 1.4.1/r1425.

The source is pinned to commit
`98a5ebad0df579cc8b43eedd3421b3ae87699901`; the build verifies the immutable
source archive SHA-256 before compiling.

This public source currently describes CICFlowMeter V4. It is not claimed to be
the exact CICFlowMeter V3 binary used to generate CICIDS2017. Successful output
only establishes runtime feasibility, not semantic compatibility.

Use the repository scripts:

```text
python scripts/build_historical_cicflowmeter.py
python scripts/run_historical_cicflowmeter.py
```

Raw Java CSVs are written to `data/lab/flows/historical/` and are never adapted
or passed to model inference by these scripts.

