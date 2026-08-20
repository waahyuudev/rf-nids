FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

COPY alembic.ini ./
COPY migrations ./migrations
COPY config ./config
COPY models/model_metadata.json ./models/model_metadata.json
COPY models/random_forest_active.joblib ./models/random_forest_active.joblib
COPY src ./src

RUN useradd --create-home --uid 10001 rf-nids \
    && chown -R rf-nids:rf-nids /app

USER rf-nids

EXPOSE 8000

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
