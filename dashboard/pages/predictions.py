import pandas as pd
import streamlit as st

from dashboard.components.styles import section_heading
from dashboard.components.tables import predictions_table
from dashboard.presentation import class_probability_rows, prediction_context


PAGE_SIZE = 20


def _value(value):
    return "Not available" if value is None or value == "" else value


def _confidence(value):
    return "Not available" if value is None else f"{value:.2%}"


def _metadata_table(values: dict) -> None:
    st.dataframe(
        pd.DataFrame([{"Field": key, "Value": _value(value)} for key, value in values.items()]),
        hide_index=True,
        width="stretch",
    )


def _render_detail(detail: dict) -> None:
    st.divider()
    st.subheader(f"Prediction Detail · #{detail.get('id')}")
    st.markdown("#### Prediction Information")
    _metadata_table({
        "Prediction ID": detail.get("id"),
        "Timestamp": detail.get("prediction_time"),
        "Predicted class": detail.get("predicted_label"),
        "Confidence": _confidence(detail.get("confidence_score")),
        "Model": detail.get("model_name"),
        "Model version": detail.get("model_version"),
    })

    st.markdown("#### Class Probabilities")
    probabilities = class_probability_rows(detail.get("class_probabilities"))
    if probabilities:
        st.dataframe(
            probabilities,
            hide_index=True,
            width="stretch",
            column_config={"Probability": st.column_config.ProgressColumn(
                "Probability", min_value=0.0, max_value=1.0, format="percent"
            )},
        )
    else:
        st.info("Full class probabilities were not stored for this prediction. Confidence is shown above.")

    left, right = st.columns(2)
    with left:
        st.markdown("#### Flow Information")
        _metadata_table({
            "Source IP": detail.get("source_ip"),
            "Source port": detail.get("source_port"),
            "Destination IP": detail.get("destination_ip"),
            "Destination port": detail.get("destination_port"),
            "Protocol": detail.get("protocol"),
            "Capture timestamp": detail.get("capture_time"),
            "Capture session": detail.get("capture_session_id"),
            "Capture interface": detail.get("capture_interface"),
            "PCAP segment": detail.get("pcap_segment"),
        })
    with right:
        st.markdown("#### Context / Provenance")
        _metadata_table(prediction_context(detail))
        st.markdown("#### Alert Information")
        if detail.get("alert_id") is None:
            st.info("No alert is associated with this prediction.")
        else:
            _metadata_table({
                "Alert ID": detail.get("alert_id"),
                "Severity": detail.get("alert_severity"),
                "Status": detail.get("alert_status"),
            })

    st.markdown("#### Feature Information")
    features = detail.get("flow_features")
    if isinstance(features, dict) and features:
        with st.expander(f"Stored raw feature representation ({len(features)} fields)"):
            st.json(features)
    else:
        st.info("No stored raw feature representation is available for this prediction.")


def render(client) -> None:
    section_heading(
        "Predictions",
        "Classifier results with model, confidence, alert state, and detailed provenance.",
    )
    c1, c2, c3 = st.columns(3)
    label = c1.selectbox("Class", ["All", "Normal", "DDoS", "PortScan"])
    source = c2.text_input("Source IP", key="prediction_source_ip")
    destination = c3.text_input("Destination IP", key="prediction_destination_ip")
    page = int(st.number_input(
        "Page", min_value=1, step=1, key="predictions_page",
        help=f"Each page contains at most {PAGE_SIZE} predictions.",
    ))
    filters = {
        "predicted_label": None if label == "All" else label,
        "source_ip": source or None,
        "destination_ip": destination or None,
    }
    rows = client.predictions(
        limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE, **filters
    )
    predictions_table(rows)
    st.caption(f"Page {page} · showing {len(rows)} of at most {PAGE_SIZE} records.")
    if not rows:
        return
    selected = st.selectbox(
        "Open prediction detail",
        [row["id"] for row in rows],
        format_func=lambda value: f"Prediction #{value}",
    )
    _render_detail(client.prediction(selected))
