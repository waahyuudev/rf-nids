from datetime import datetime, timezone

import streamlit as st

from dashboard.components.styles import section_heading

PAGE_SIZE = 20
ACTIVE = {"STARTING", "RUNNING", "STOPPING"}


def _elapsed(started_at: str | None) -> str:
    if not started_at:
        return "—"
    started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    seconds = max(0, int((datetime.now(timezone.utc) - started).total_seconds()))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def render(client) -> None:
    section_heading(
        "Monitoring",
        "Live defensive capture, CICFlowMeter V3 extraction, and Random Forest inference.",
    )
    state = client.monitoring_status()
    current = state.get("session")
    running = state["status"] in ACTIVE

    st.subheader("Monitoring Configuration")
    interfaces = client.monitoring_interfaces()
    choices = [item["name"] for item in interfaces["interfaces"]]
    model = client.active_model()
    with st.form("monitoring_configuration"):
        target = st.text_input(
            "Target IP", value="", placeholder="192.168.128.4", disabled=running
        )
        interface = st.selectbox(
            "Capture Interface", choices or ["Interface discovery unavailable"],
            disabled=running or not choices,
        )
        st.text_input(
            "Active Model", value=f'{model["model_name"]} ({model["model_version"]})',
            disabled=True,
        )
        submitted = st.form_submit_button(
            "START MONITORING", type="primary", disabled=running or not choices
        )
    if not interfaces["discovery_available"]:
        st.warning("Network interface discovery is unavailable on the API host.")
    if submitted:
        client.start_monitoring(target, interface)
        st.rerun()

    st.divider()
    st.subheader("Current Session")
    st.metric("Controller status", state["status"])
    if current:
        columns = st.columns(4)
        values = [
            ("Session ID", current["id"]), ("Target", current["target_ip"]),
            ("Interface", current["interface_name"]), ("Model", current["model_version"]),
            ("Elapsed", _elapsed(current["started_at"])), ("Flows", current["flow_count"]),
            ("Predictions", current["prediction_count"]), ("Alerts", current["alert_count"]),
        ]
        for index, (label, value) in enumerate(values):
            columns[index % 4].metric(label, value)
        if current.get("last_error"):
            st.error(current["last_error"])
        st.caption(
            f'Extractor: {current.get("extractor_name") or "—"} · '
            f'Latest processing: {current.get("latest_processing_at") or "—"}'
        )
        if current.get("processing_state"):
            st.info(f'Current processing state: {current["processing_state"]}')
        recent = client.monitoring_session_predictions(current["id"], limit=5)
        if recent:
            st.markdown("##### Recent Predictions")
            st.dataframe([
                {
                    "time": row.get("prediction_time"), "source": row.get("source_ip"),
                    "destination": row.get("destination_ip"),
                    "class": row.get("predicted_label"),
                    "probability": row.get("confidence_score"),
                }
                for row in recent
            ], use_container_width=True)
    else:
        st.info("No monitoring session has been created.")
    if running and st.button("STOP MONITORING", type="primary"):
        with st.spinner("Flushing the final capture window before stopping…"):
            client.stop_monitoring()
        st.rerun()

    if current:
        st.divider()
        st.subheader("Runtime Validation")
        scenario_labels = {
            "Normal HTTP": "NORMAL_HTTP", "PortScan": "PORTSCAN",
            "Stop / Restart": "STOP_RESTART",
        }
        scenario_label = st.selectbox("Scenario", list(scenario_labels))
        if st.button("START VALIDATION"):
            client.create_runtime_validation(current["id"], scenario_labels[scenario_label])
            st.rerun()
        validations = client.runtime_validations(current["id"])
        if validations:
            validation = validations[0]
            if validation["status"] == "RUNNING" and st.button("COMPLETE FROM SERVER EVIDENCE"):
                client.complete_runtime_validation(current["id"], validation["id"])
                st.rerun()
            result_columns = st.columns(2)
            result_columns[0].metric("Pipeline validation", validation["pipeline_result"])
            result_columns[1].metric(
                "PortScan detection" if validation["scenario"] == "PORTSCAN" else "Detection",
                validation["detection_result"],
            )
            if validation["scenario"] == "PORTSCAN" and validation["detection_result"] == "FAIL":
                st.info("The runtime pipeline may pass while PortScan detection fails; this is a valid scientific result.")
            fields = [
                ("Validation ID", "id"), ("Scenario", "scenario"), ("Status", "status"),
                ("PCAPs Processed", "pcap_files_processed"), ("Flows Extracted", "flows_extracted"),
                ("Adapter-Valid Flows", "flows_adapter_valid"), ("Predictions", "predictions_committed"),
                ("Alerts", "alerts_committed"), ("Normal", "normal_predictions"),
                ("PortScan", "portscan_predictions"), ("DDoS", "ddos_predictions"),
                ("Model Version", "model_version"), ("Extractor", "extractor_identity"),
                ("Adapter", "adapter_identity"), ("Started", "started_at"), ("Finished", "finished_at"),
            ]
            st.dataframe([{"Field": label, "Value": validation.get(key)} for label, key in fields], hide_index=True, use_container_width=True)

    st.divider()
    st.subheader("Session History")
    page = int(st.number_input("Page", min_value=1, step=1, key="session_history_page"))
    rows = client.monitoring_sessions(limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE)
    fields = ["id", "target_ip", "interface_name", "model_version", "status",
              "started_at", "stopped_at", "flow_count", "prediction_count", "alert_count"]
    st.dataframe([{key: row.get(key) for key in fields} for row in rows], use_container_width=True)
    st.caption(f"Page {page} · showing {len(rows)} of at most {PAGE_SIZE} sessions.")
