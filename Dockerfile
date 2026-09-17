FROM docker:28-cli AS docker-cli
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y libgomp1 tcpdump libcap2-bin \
    && setcap cap_net_raw=ep "$(command -v tcpdump)" \
    && rm -rf /var/lib/apt/lists/*

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

COPY requirements.txt ./
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

COPY alembic.ini ./
COPY migrations ./migrations
COPY config ./config
COPY models/model_metadata.json ./models/model_metadata.json
COPY models/random_forest_active.joblib ./models/random_forest_active.joblib
COPY models/experiment_d/random_forest_rf_v2.joblib ./models/experiment_d/random_forest_rf_v2.joblib
COPY models/experiment_d/random_forest_rf_v2_metadata.json ./models/experiment_d/random_forest_rf_v2_metadata.json
COPY models/experiment_d/random_forest_rf_v2_runtime_metadata.json ./models/experiment_d/random_forest_rf_v2_runtime_metadata.json
COPY reports/experiment_d/final_test/metrics.json ./reports/experiment_d/final_test/metrics.json
COPY reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv ./reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv
COPY reports/experiment_e/audit/e3_provenance_amendment_a1.json ./reports/experiment_e/audit/e3_provenance_amendment_a1.json
COPY src ./src

RUN echo "66e517cdcea217f19de4d0a2cd45302ede999388393f539fb8ca4a2c68b74cf4  reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv" | sha256sum -c - \
    && echo "5267b0195b0ebded335df8f306e3abecef2b2b369bd5934e553dc9cba8b913a5  reports/experiment_e/audit/e3_provenance_amendment_a1.json" | sha256sum -c -

RUN useradd --create-home --uid 10001 rf-nids \
    && chown -R rf-nids:rf-nids /app

USER rf-nids

EXPOSE 8000

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
