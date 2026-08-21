import streamlit as st

from dashboard.components.tables import predictions_table
from dashboard.components.styles import section_heading


def render(client) -> None:
    section_heading("Predictions", "Filter classification records by class or IP address.")
    c1, c2, c3 = st.columns(3)
    label = c1.selectbox("Class", ["All", "Normal", "DDoS", "PortScan"])
    source = c2.text_input("Source IP")
    destination = c3.text_input("Destination IP")
    page = st.number_input("Page", min_value=1, step=1, help="Each page contains up to 20 predictions.")
    filters = {"predicted_label": None if label == "All" else label, "source_ip": source or None, "destination_ip": destination or None}
    rows = client.predictions(limit=20, offset=(page - 1) * 20, **filters)
    predictions_table(rows)
    if rows:
        selected = st.selectbox("Prediction detail", [row["id"] for row in rows], format_func=lambda value: f"Prediction #{value}")
        detail = client.prediction(selected)
        with st.expander(f"Prediction {selected} details", expanded=True):
            probabilities = detail.get("class_probabilities", {})
            c1, c2, c3 = st.columns(3)
            c1.metric("Class", detail.get("predicted_label", "—"))
            c2.metric("Confidence", f"{detail.get('confidence_score', 0):.2%}")
            c3.metric("Model", detail.get("model_version", "—"))
            st.caption(f"{detail.get('source_ip') or 'Unknown'}:{detail.get('source_port') or '—'} → {detail.get('destination_ip') or 'Unknown'}:{detail.get('destination_port') or '—'} · {detail.get('protocol') or 'Unknown protocol'}")
            st.markdown("**Class probabilities**")
            st.dataframe({"Class": list(probabilities), "Probability": list(probabilities.values())}, hide_index=True, width="stretch", column_config={"Probability": st.column_config.ProgressColumn("Probability", min_value=0.0, max_value=1.0, format="percent")})
            if detail.get("flow_features"):
                with st.expander("Flow Features"):
                    st.json(detail["flow_features"])
