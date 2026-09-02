import streamlit as st

from dashboard.api_client import APIError
from dashboard.components.charts import render_distribution, render_timeline
from dashboard.components.metrics import render_overview_metrics
from dashboard.components.tables import predictions_table
from dashboard.components.styles import section_heading


def render(client) -> None:
    summary = client.summary()
    section_heading("Dashboard", "Runtime/application monitoring statistics only.")
    try:
        model = client.active_model()
    except APIError:
        st.warning("No active model is available.")
    else:
        st.info(f"Active model: {model['model_name']} · {model['model_version']} · {model['algorithm']}")
    render_overview_metrics(summary)
    st.write("")
    left, right = st.columns(2)
    with left:
        section_heading("Traffic distribution", "Classification totals for processed flows.")
        chart_type = st.segmented_control("Chart type", ["Bar", "Donut"], default="Bar", label_visibility="collapsed")
        render_distribution(summary, chart_type or "Bar")
    with right:
        section_heading("Recent activity", "Classification volume grouped by minute.")
        window = st.selectbox("Time range", [15, 60, 360, 1440], index=1, format_func=lambda value: {15: "Last 15 minutes", 60: "Last hour", 360: "Last 6 hours", 1440: "Last 24 hours"}[value], label_visibility="collapsed")
        render_timeline(client.timeline(minutes=window))
    section_heading("Recent predictions", "Latest 20 classified flows.")
    predictions_table(client.predictions(limit=20))
