"""Streamlit entry point: streamlit run dashboard/app.py."""

from pathlib import Path
import sys

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dashboard.api_client import APIError, RFNIDSClient
from dashboard.auth import (
    NOTICE_KEY,
    clear_auth,
    handle_auth_failure,
    require_login,
    store_login,
    token_from,
)
from dashboard.config import DashboardConfig
from dashboard.components.sidebar import render_sidebar
from dashboard.components.styles import apply_styles, render_header
from dashboard.pages import alerts, dataset, evaluation, model_info, monitoring, overview, predictions

st.set_page_config(page_title="RF-NIDS Monitoring Dashboard", page_icon="🛡️", layout="wide")
apply_styles()
config = DashboardConfig.from_env()
client = RFNIDSClient(
    config.api_base_url,
    config.request_timeout,
    token_provider=lambda: token_from(st.session_state),
)

try:
    health = client.health()
    online = health.get("status") == "healthy"
except APIError:
    online = False


def render_login() -> None:
    st.title("RF-NIDS")
    st.subheader("Random Forest Network Intrusion Detection System")
    st.caption("Administrator login")
    notice = st.session_state.pop(NOTICE_KEY, None)
    if notice:
        st.warning(notice)
    if not online:
        st.error("The RF-NIDS API is unavailable. Start the API and try again.")
    with st.form("administrator_login"):
        email = st.text_input("Email", autocomplete="email")
        password = st.text_input("Password", type="password", autocomplete="current-password")
        submitted = st.form_submit_button("Login", type="primary", disabled=not online)
    if submitted:
        try:
            result = client.login(email, password)
            store_login(st.session_state, result)
        except APIError as exc:
            if exc.status_code in (401, 403):
                clear_auth(st.session_state)
                st.error("Invalid email or password, or this administrator account is unavailable.")
            else:
                st.error("Login is currently unavailable. Please try again.")
        except ValueError:
            clear_auth(st.session_state)
            st.error("Login could not be completed. Please try again.")
        else:
            st.rerun()


if token_from(st.session_state) is None:
    render_login()
    st.stop()

if not online:
    st.warning("Backend API is currently unavailable. Your session has not been changed.")
    st.stop()

try:
    user = require_login(st.session_state, client)
except APIError:
    st.error("The current session could not be verified because the API is unavailable.")
    st.stop()
if user is None:
    st.rerun()

try:
    model = client.model_info()
except APIError as exc:
    if handle_auth_failure(st.session_state, exc):
        st.rerun()
    model = {}

page, auto_refresh, logout = render_sidebar(
    online, model.get("model_version"), config.refresh_seconds, user
)
if logout:
    try:
        client.logout()
    except APIError:
        pass
    clear_auth(st.session_state)
    st.rerun()
render_header(online)


@st.fragment(run_every=config.refresh_seconds if auto_refresh else None)
def page_content():
    try:
        {"Dashboard": overview, "Dataset": dataset, "Models": model_info,
         "Evaluation": evaluation, "Monitoring": monitoring, "Predictions": predictions,
         "Alerts": alerts}[page].render(client)
    except APIError as exc:
        if handle_auth_failure(st.session_state, exc):
            st.rerun()
        st.error(str(exc))


page_content()
