import pandas as pd
import streamlit as st

from dashboard.components.styles import section_heading
from dashboard.components.tables import alerts_table
from dashboard.presentation import class_probability_rows


PAGE_SIZE = 20


def _value(value):
    return "Not available" if value is None or value == "" else str(value)


def _metadata_table(values: dict) -> None:
    st.dataframe(
        pd.DataFrame([{"Field": key, "Value": _value(value)} for key, value in values.items()]),
        hide_index=True,
        width="stretch",
    )


def _render_detail(detail: dict) -> None:
    st.divider()
    st.subheader(f"Alert Detail · #{detail.get('id')}")
    left, right = st.columns(2)
    with left:
        st.markdown("#### Alert Information")
        _metadata_table({
            "Alert ID": detail.get("id"),
            "Severity": detail.get("severity"),
            "Status": detail.get("status"),
            "Created at": detail.get("created_at"),
            "Acknowledged at": detail.get("acknowledged_at"),
            "Acknowledged by": detail.get("acknowledged_by_name"),
            "Acknowledging user ID": detail.get("acknowledged_by_user_id"),
        })
        st.markdown("#### Related Prediction")
        _metadata_table({
            "Prediction ID": detail.get("prediction_id"),
            "Predicted class": detail.get("predicted_label"),
            "Confidence": (
                f"{detail['confidence_score']:.2%}"
                if detail.get("confidence_score") is not None else None
            ),
        })
    with right:
        st.markdown("#### Related Flow")
        _metadata_table({
            "Source IP": detail.get("source_ip"),
            "Source port": detail.get("source_port"),
            "Destination IP": detail.get("destination_ip"),
            "Destination port": detail.get("destination_port"),
            "Protocol": detail.get("protocol"),
            "Capture time": detail.get("capture_time"),
        })
        st.markdown("#### Model and Context")
        _metadata_table({
            "Model": detail.get("model_name"),
            "Model version": detail.get("model_version"),
            "Source type": detail.get("source_type"),
            "Context": (
                "Runtime inference"
                if detail.get("source_type") in (None, "RUNTIME") else "Imported context"
            ),
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
        st.info("No stored class probability vector is available for this alert's prediction.")


def render(client) -> None:
    section_heading(
        "Alerts",
        "Review deterministic runtime attack alerts and acknowledge completed investigations.",
    )
    summary = client.summary()
    active = summary.get("active_alerts", 0)
    acknowledged = summary.get("acknowledged_alerts", 0)
    values = [
        ("Total Alerts", active + acknowledged),
        ("Active Alerts", active),
        ("Active HIGH", summary.get("active_high_alerts", 0)),
        ("Active MEDIUM", summary.get("active_medium_alerts", 0)),
        ("Acknowledged", acknowledged),
    ]
    for column, (label, value) in zip(st.columns(5), values, strict=True):
        column.metric(label, f"{value:,}")

    st.write("")
    c1, c2, c3 = st.columns(3)
    attack_type = c1.selectbox("Attack type", ["All", "DDoS", "PortScan"])
    severity = c2.selectbox("Severity", ["All", "HIGH", "MEDIUM"])
    status = c3.selectbox("Status", ["All", "ACTIVE", "ACKNOWLEDGED"])
    c4, c5 = st.columns(2)
    source_ip = c4.text_input("Source IP", key="alert_source_ip")
    destination_ip = c5.text_input("Destination IP", key="alert_destination_ip")
    page = int(st.number_input("Page", min_value=1, step=1, key="alerts_page"))
    filters = dict(
        predicted_label=None if attack_type == "All" else attack_type,
        severity=None if severity == "All" else severity,
        status=None if status == "All" else status,
        source_ip=source_ip or None,
        destination_ip=destination_ip or None,
    )
    rows = client.alerts(
        limit=PAGE_SIZE,
        offset=(page - 1) * PAGE_SIZE,
        **filters,
    )
    export = client.export_alerts(format="csv", **filters)
    st.download_button(
        "Export current filtered alerts", export.content,
        file_name=export.filename, mime=export.content_type,
        help="Exports up to 10,000 matching records in deterministic ID order.",
    )
    alerts_table(rows)
    st.caption(f"Page {page} · showing {len(rows)} of at most {PAGE_SIZE} alerts.")
    if not rows:
        return

    selected = st.selectbox(
        "Open alert detail",
        [row["id"] for row in rows],
        format_func=lambda value: f"Alert #{value}",
    )
    detail = client.alert(selected)
    _render_detail(detail)

    if detail.get("status") == "ACTIVE":
        st.markdown("#### Alert Action")
        if st.button(
            "Acknowledge Alert",
            type="primary",
        ):
            client.acknowledge_alert(selected)
            st.success(f"Alert {selected} acknowledged.")
            st.rerun()
    else:
        st.success("This alert is acknowledged.")
