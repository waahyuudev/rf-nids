"""Opt-in real PostgreSQL checks for runtime controller constraints and provenance."""

import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError


POSTGRES_URL = os.getenv("RF_NIDS_POSTGRES_TEST_URL")
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="PostgreSQL test URL not configured")


def test_postgresql_runtime_constraints_foreign_key_and_alert_transaction():
    engine = create_engine(POSTGRES_URL)
    connection = engine.connect()
    transaction = connection.begin()
    suffix = uuid4().hex
    try:
        user_id = connection.execute(text(
            "INSERT INTO users(name,email,password_hash,role,is_active,created_at,updated_at) "
            "VALUES ('Phase10 Verify',:email,'x','ADMIN',true,now(),now()) RETURNING id"
        ), {"email": f"phase10-{suffix}@example.test"}).scalar_one()
        model_id = connection.execute(text(
            "INSERT INTO models(model_name,model_version,algorithm,is_active,created_at) "
            "VALUES ('Verify RF',:version,'Random Forest',false,now()) RETURNING id"
        ), {"version": f"phase10-{suffix}"}).scalar_one()
        session_id = connection.execute(text(
            "INSERT INTO monitoring_sessions(target_ip,interface_name,model_id,status,"
            "created_by_user_id,created_at,updated_at,flow_count,prediction_count,alert_count) "
            "VALUES ('192.168.128.2','verify0',:model,'RUNNING',:user,now(),now(),0,0,0) "
            "RETURNING id"
        ), {"model": model_id, "user": user_id}).scalar_one()
        duplicate_blocked = False
        nested = connection.begin_nested()
        try:
            connection.execute(text(
                "INSERT INTO monitoring_sessions(target_ip,interface_name,model_id,status,"
                "created_at,updated_at,flow_count,prediction_count,alert_count) "
                "VALUES ('192.168.128.2','verify1',:model,'RUNNING',now(),now(),0,0,0)"
            ), {"model": model_id})
        except IntegrityError:
            duplicate_blocked = True
            nested.rollback()
        assert duplicate_blocked

        flow_id = connection.execute(text(
            "INSERT INTO traffic_flows(raw_features,created_at) VALUES ('{}'::jsonb,now()) RETURNING id"
        )).scalar_one()
        prediction_id = connection.execute(text(
            "INSERT INTO predictions(traffic_flow_id,model_id,monitoring_session_id,source_type,"
            "external_key,predicted_label,confidence_score,class_probabilities,prediction_time,created_at) "
            "VALUES (:flow,:model,:session,'RUNTIME',:key,'DDoS',0.9,"
            "CAST(:probabilities AS jsonb),now(),now()) RETURNING id"
        ), {"flow": flow_id, "model": model_id, "session": session_id,
            "key": f"phase10-{suffix}", "probabilities": '{"DDoS":0.9}'}).scalar_one()
        alert_id = connection.execute(text(
            "INSERT INTO alerts(prediction_id,severity,title,description,status,created_at) "
            "VALUES (:prediction,'HIGH','verify','verify','ACTIVE',now()) RETURNING id"
        ), {"prediction": prediction_id}).scalar_one()
        assert alert_id
        assert connection.execute(text(
            "SELECT monitoring_session_id FROM predictions WHERE id=:id"
        ), {"id": prediction_id}).scalar_one() == session_id
    finally:
        transaction.rollback()
        connection.close()
        engine.dispose()
