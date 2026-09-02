import streamlit as st


def render_sidebar(online: bool, model_version: str | None, refresh_seconds: int) -> tuple[str, bool]:
    with st.sidebar:
        st.title("RF-NIDS")
        st.caption("Thesis application")
        page = st.radio(
            "Navigation",
            ["Dashboard", "Dataset", "Models", "Evaluation", "Monitoring", "Predictions", "Alerts"],
            label_visibility="collapsed",
        )
        st.divider()
        st.caption("System status")
        st.markdown("<span style='color:#62d6ad'>●</span>&nbsp; **API Online**" if online else "<span style='color:#ff7b7b'>●</span>&nbsp; **API Offline**", unsafe_allow_html=True)
        st.caption(f"Active model · {model_version or 'Unavailable'}")
        auto_refresh = st.toggle("Auto Refresh", value=True)
        if auto_refresh:
            st.caption(f"Updating every {refresh_seconds} seconds")
        if st.button("Refresh now", width="stretch"):
            st.rerun()
        st.caption("Development environment")
    return page, auto_refresh
