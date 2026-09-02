import streamlit as st

from dashboard.components.metrics import render_monitoring_metrics
from dashboard.components.styles import section_heading
from dashboard.components.tables import monitoring_table


PAGE_SIZE = 20


def render(client) -> None:
    section_heading(
        "Monitoring",
        "Operational runtime traffic flows and their persisted classifier results.",
    )
    render_monitoring_metrics(client.monitoring_summary())
    st.divider()

    c1, c2, c3, c4 = st.columns(4)
    label = c1.selectbox("Predicted class", ["All", "Normal", "DDoS", "PortScan"])
    protocol = c2.text_input("Protocol", placeholder="For example: TCP")
    source = c3.text_input("Source IP")
    destination = c4.text_input("Destination IP")
    page = int(st.number_input("Page", min_value=1, step=1, key="monitoring_page"))
    filters = {
        "predicted_label": None if label == "All" else label,
        "protocol": protocol or None,
        "source_ip": source or None,
        "destination_ip": destination or None,
    }
    rows = client.traffic_flows(
        limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE, **filters
    )
    monitoring_table(rows)
    st.caption(
        f"Page {page} · showing {len(rows)} of at most {PAGE_SIZE} records. "
        "Filters and pagination are applied by the API."
    )
