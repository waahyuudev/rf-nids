import streamlit as st

from dashboard.components.tables import alerts_table
from dashboard.components.styles import section_heading


def render(client) -> None:
    section_heading("Alerts", "Review active alerts and acknowledge completed investigations.")
    summary = client.summary()
    acknowledged = summary.get("acknowledged_alerts", 0)
    high = summary.get("active_high_alerts", 0)
    medium = summary.get("active_medium_alerts", 0)
    for column, (label, value) in zip(st.columns(4), [("Active", summary.get("active_alerts", 0)), ("HIGH", high), ("MEDIUM", medium), ("Acknowledged", acknowledged)], strict=True):
        column.metric(label, f"{value:,}")
    st.write("")
    c1, c2 = st.columns(2)
    severity = c1.selectbox("Severity", ["All", "HIGH", "MEDIUM"])
    status = c2.selectbox("Status", ["All", "ACTIVE", "ACKNOWLEDGED"])
    rows = client.alerts(limit=50, severity=None if severity == "All" else severity, status=None if status == "All" else status)
    alerts_table(rows)
    acknowledgeable = [row["id"] for row in rows if row.get("status") == "ACTIVE"]
    if acknowledgeable:
        st.markdown("#### Alert action")
        selected = st.selectbox("Active alert", acknowledgeable, format_func=lambda value: f"Alert #{value}")
        if st.button("Acknowledge Alert", type="primary"):
            client.acknowledge_alert(selected)
            st.success(f"Alert {selected} acknowledged.")
            st.rerun()
