import streamlit as st
import pandas as pd
from dashboard.api_client import APIError
from dashboard.components.evidence import render_provenance
from dashboard.components.styles import section_heading
from dashboard.presentation import model_view


def _percent(value):
    return "N/A" if value is None else f"{value:.2%}"


def render(client) -> None:
    section_heading("Models", "Active model metadata imported into the application database.")
    try:
        info = client.active_model()
    except APIError as exc:
        st.info("No active model is available.")
        st.caption(str(exc))
        return
    view = model_view(info)
    st.subheader(view["Model name"])
    st.caption(f"Version {view['Version']} · {view['Algorithm']} · {view['Status']}")
    columns = st.columns(4)
    for column, (label, key) in zip(columns, [("Accuracy", "accuracy"), ("Macro F1", "macro_f1"), ("DDoS Recall", "ddos_recall"), ("PortScan Recall", "portscan_recall")], strict=True):
        column.metric(label, _percent(info.get(key)))
    st.caption(f"Trained: {info.get('trained_at') or 'Not available'}")
    st.markdown(f"**Input:** {view['Feature count']} ordered CICIDS2017-compatible features")
    st.markdown("**Classes:** " + view["Classes"].replace(", ", " · "))
    st.markdown(f"**Linked experiment:** {view['Linked experiment']}")
    st.dataframe(
        pd.DataFrame(
            [(key, str(value)) for key, value in view.items()],
            columns=["Field", "Value"],
        ),
        width="stretch",
        hide_index=True,
    )
    st.divider()
    section_heading("Training information", "Recorded configuration only; training cannot be triggered from this page.")
    parameters = info.get("parameters")
    if parameters:
        st.dataframe(
            pd.DataFrame(
                [(key, "Not available" if value is None else str(value)) for key, value in parameters.items()],
                columns=["Parameter", "Value"],
            ),
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("Training parameters are not available.")
    render_provenance(client.evidence_sources(owner_type="MODEL", owner_key=info["model_version"]), {
        "Artifact path": info.get("artifact_path"), "Artifact SHA-256": info.get("artifact_sha256")
    })
