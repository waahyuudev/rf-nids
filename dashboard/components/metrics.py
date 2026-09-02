import streamlit as st


def render_overview_metrics(summary: dict) -> None:
    values = [
        ("Total Processed Flows", summary.get("total_flows", 0), "Runtime classified traffic"),
        ("Normal", summary.get("total_normal", 0), "Expected traffic"),
        ("DDoS", summary.get("total_ddos", 0), "Detected attacks"),
        ("PortScan", summary.get("total_portscan", 0), "Detected scans"),
        ("Total Alerts", summary.get("active_alerts", 0) + summary.get("acknowledged_alerts", 0), "All runtime alerts"),
        ("Active Alerts", summary.get("active_alerts", 0), "Needs review"),
    ]
    for start in range(0, len(values), 3):
        row = values[start : start + 3]
        for column, (label, value, help_text) in zip(st.columns(len(row)), row, strict=True):
            column.metric(label, f"{value:,}", help=help_text)
    if summary.get("latest_prediction_timestamp"):
        st.caption(f"Last Prediction: {summary['latest_prediction_timestamp']}")


def render_monitoring_metrics(summary: dict) -> None:
    values = [
        ("Total Flows", summary.get("total_flows", 0)),
        ("Normal", summary.get("total_normal", 0)),
        ("DDoS", summary.get("total_ddos", 0)),
        ("PortScan", summary.get("total_portscan", 0)),
        ("Total Alerts", summary.get("total_alerts", 0)),
        ("Active Alerts", summary.get("active_alerts", 0)),
    ]
    for column, (label, value) in zip(st.columns(6), values, strict=True):
        column.metric(label, f"{value:,}")
    context = []
    if summary.get("latest_detection_timestamp"):
        context.append(f"Most recent detection: {summary['latest_detection_timestamp']}")
    if summary.get("active_model"):
        context.append(f"Active model: {summary['active_model']}")
    if context:
        st.caption(" · ".join(context))
