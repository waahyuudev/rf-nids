"""Streamlit entry point: streamlit run dashboard/app.py."""

from pathlib import Path
import sys

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dashboard.api_client import APIError, RFNIDSClient
from dashboard.config import DashboardConfig
from dashboard.components.sidebar import render_sidebar
from dashboard.components.styles import apply_styles, render_header
from dashboard.pages import alerts, dataset, evaluation, model_info, monitoring, overview, predictions

st.set_page_config(page_title="RF-NIDS Monitoring Dashboard", page_icon="🛡️", layout="wide")
apply_styles()
config = DashboardConfig.from_env()
client = RFNIDSClient(config.api_base_url, config.request_timeout)

try:
    health = client.health()
    online = health.get("status") == "healthy"
    model = client.model_info() if online else {}
except APIError:
    online, model = False, {}

page, auto_refresh = render_sidebar(online, model.get("model_version"), config.refresh_seconds)
render_header(online)

if not online:
    st.warning("Backend API is currently unavailable.")
    st.stop()


@st.fragment(run_every=config.refresh_seconds if auto_refresh else None)
def page_content():
    try:
        {"Dashboard": overview, "Dataset": dataset, "Models": model_info,
         "Evaluation": evaluation, "Monitoring": monitoring, "Predictions": predictions,
         "Alerts": alerts}[page].render(client)
    except APIError as exc:
        st.error(str(exc))


page_content()
