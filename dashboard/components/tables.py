import pandas as pd
import streamlit as st


def predictions_table(rows: list[dict]) -> None:
    if not rows:
        st.info("No traffic predictions available yet.")
        return
    fields = ["id", "prediction_time", "source_ip", "destination_ip", "predicted_label", "confidence_score", "model_version", "alert_status"]
    frame = pd.DataFrame(rows).reindex(columns=fields).rename(columns={"id": "ID", "prediction_time": "Time", "source_ip": "Source IP", "destination_ip": "Destination IP", "predicted_label": "Class", "confidence_score": "Confidence", "model_version": "Model", "alert_status": "Alert"})
    frame["Time"] = pd.to_datetime(frame["Time"]).dt.strftime("%d %b %Y · %H:%M:%S")
    st.dataframe(frame, width="stretch", hide_index=True, column_config={"Confidence": st.column_config.ProgressColumn("Confidence", min_value=0.0, max_value=1.0, format="percent")})


def monitoring_table(rows: list[dict]) -> None:
    if not rows:
        st.info("No runtime traffic flows match the current filters.")
        return
    fields = ["flow_timestamp", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "predicted_label", "confidence_score"]
    frame = pd.DataFrame(rows).reindex(columns=fields).rename(columns={"flow_timestamp": "Time", "source_ip": "Source IP", "source_port": "Src Port", "destination_ip": "Destination IP", "destination_port": "Dst Port", "protocol": "Protocol", "predicted_label": "Class", "confidence_score": "Confidence"})
    frame["Time"] = pd.to_datetime(frame["Time"]).dt.strftime("%d %b %Y · %H:%M:%S")
    st.dataframe(frame, width="stretch", hide_index=True, column_config={"Confidence": st.column_config.ProgressColumn("Confidence", min_value=0.0, max_value=1.0, format="percent")})


def alerts_table(rows: list[dict]) -> None:
    if not rows:
        st.info("No alerts available yet.")
        return
    fields = ["id", "created_at", "severity", "title", "predicted_label", "confidence_score", "source_ip", "destination_ip", "status"]
    frame = pd.DataFrame(rows).reindex(columns=fields).rename(columns={"id": "ID", "created_at": "Time", "severity": "Severity", "title": "Alert", "predicted_label": "Class", "confidence_score": "Confidence", "source_ip": "Source IP", "destination_ip": "Destination IP", "status": "Status"})
    frame["Time"] = pd.to_datetime(frame["Time"]).dt.strftime("%d %b %Y · %H:%M:%S")
    st.dataframe(frame, width="stretch", hide_index=True, column_config={"Confidence": st.column_config.ProgressColumn("Confidence", min_value=0.0, max_value=1.0, format="percent")})
