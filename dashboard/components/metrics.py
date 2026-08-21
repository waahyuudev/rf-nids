import streamlit as st


def render_overview_metrics(summary: dict) -> None:
    values = [
        ("Total Flows", summary.get("total_flows", 0), "All classified traffic"),
        ("Normal", summary.get("total_normal", 0), "Expected traffic"),
        ("DDoS", summary.get("total_ddos", 0), "Detected attacks"),
        ("PortScan", summary.get("total_portscan", 0), "Detected scans"),
        ("Active Alerts", summary.get("active_alerts", 0), "Needs review"),
        ("Acknowledged", summary.get("acknowledged_alerts", 0), "Reviewed alerts"),
    ]
    for start in range(0, len(values), 3):
        row = values[start : start + 3]
        for column, (label, value, help_text) in zip(st.columns(len(row)), row, strict=True):
            column.metric(label, f"{value:,}", help=help_text)
    if summary.get("latest_prediction_timestamp"):
        st.caption(f"Last Prediction: {summary['latest_prediction_timestamp']}")
