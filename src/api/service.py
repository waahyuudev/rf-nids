"""Inference orchestration and transactional persistence."""

from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from src.api.models import Alert, ModelRecord, Prediction, TrafficFlow


SEVERITY = {"DDoS": "HIGH", "PortScan": "MEDIUM"}


def metadata_metrics(metadata: dict) -> dict:
    metrics = metadata.get("metrics", {})
    report = metrics.get("classification_report", {})
    return {
        "accuracy": metrics.get("accuracy"),
        "macro_f1": metrics.get("macro_f1"),
        "ddos_recall": report.get("DDoS", {}).get("recall"),
        "portscan_recall": report.get("PortScan", {}).get("recall"),
    }


def sync_active_model(db: Session, metadata: dict) -> ModelRecord:
    version = metadata["model_version"]
    record = db.scalar(select(ModelRecord).where(ModelRecord.model_version == version))
    values = metadata_metrics(metadata)
    provenance = {
        "artifact_path": metadata.get("model_path"),
        "artifact_sha256": metadata.get("model_sha256"),
        "parameters": metadata.get("parameters"),
        "feature_count": len(metadata.get("feature_names", [])) or None,
    }
    db.execute(
        update(ModelRecord)
        .where(ModelRecord.model_version != version)
        .values(is_active=False)
    )
    if record is None:
        record = ModelRecord(
            model_name=metadata.get("model_name", "RF-NIDS Random Forest"),
            model_version=version,
            algorithm="Random Forest",
            is_active=True,
            **values,
            **provenance,
        )
        db.add(record)
    else:
        record.is_active = True
        record.model_name = metadata.get("model_name", "RF-NIDS Random Forest")
        record.algorithm = "Random Forest"
        for field, value in values.items():
            setattr(record, field, value)
        for field, value in provenance.items():
            setattr(record, field, value)
    db.commit()
    db.refresh(record)
    return record


def persist_predictions(db: Session, requests, outputs, model_id: int):
    results = []
    try:
        for request, output in zip(requests, outputs, strict=True):
            metadata = request.metadata.model_dump() if request.metadata else {}
            flow = TrafficFlow(raw_features=request.features, **metadata)
            prediction = Prediction(
                traffic_flow=flow,
                model_id=model_id,
                source_type="RUNTIME",
                predicted_label=output["prediction"],
                confidence_score=output["confidence"],
                class_probabilities=output["probabilities"],
            )
            db.add(prediction)
            if output["prediction"] in SEVERITY:
                severity = SEVERITY[output["prediction"]]
                db.add(
                    Alert(
                        prediction=prediction,
                        severity=severity,
                        title=f"{severity} severity {output['prediction']} detected",
                        description=(
                            f"RF-NIDS classified this flow as {output['prediction']} "
                            f"with confidence {output['confidence']:.4f}."
                        ),
                        status="ACTIVE",
                    )
                )
            results.append((prediction, output))
        # Flush assigns every ID and exposes constraint failures before the one commit.
        db.flush()
        db.commit()
    except Exception:
        db.rollback()
        raise
    return [
        {
            "prediction_id": prediction.id,
            "prediction": output["prediction"],
            "confidence": output["confidence"],
            "probabilities": output["probabilities"],
            "model_version": output["model_version"],
        }
        for prediction, output in results
    ]
