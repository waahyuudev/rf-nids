from datetime import datetime, timezone

import streamlit as st

from dashboard.components.styles import section_heading
from dashboard.config import DashboardConfig

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


def session_model_display(model_version: str | None, demo_model_version: str | None) -> str:
    """Label only the current demo inference model; historical sessions stay literal."""
    value = model_version or "—"
    return f"{value} · DEMO" if value == demo_model_version else value


def model_metadata_for_display(
    model_by_id: dict[str, dict],
    selected_model_id: str,
    *,
    running: bool,
    current_session: dict | None,
) -> dict | None:
    """Resolve configuration metadata without confusing UI and runtime state."""
    if not running:
        return model_by_id.get(selected_model_id)
    if current_session is None:
        return None

    session_model_id = session_model_id_from(current_session)
    registered = model_by_id.get(session_model_id, {})
    return {
        **registered,
        "model_id": session_model_id,
        "model_version": current_session.get("selected_model_version")
        or current_session.get("model_version")
        or session_model_id,
        "selection_mode": current_session.get("selection_mode")
        or registered.get("selection_mode", "DEFAULT"),
    }


def session_model_id_from(current_session: dict) -> str | None:
    return (
        current_session.get("selected_model_id")
        or current_session.get("selected_model_version")
        or current_session.get("model_version")
    )


def render(client) -> None:
    section_heading(
        "Monitoring",
        "Live defensive capture, CICFlowMeter V3 extraction, and Random Forest inference.",
    )
    state = client.monitoring_status()
    current = state.get("session")
    running = state["status"] in ACTIVE
    dashboard_config = DashboardConfig.from_env()

    st.subheader("Monitoring Configuration")
    interfaces = client.monitoring_interfaces()
    choices = [item["name"] for item in interfaces["interfaces"]]
    models = client.monitoring_models()
    model_by_id = {item["model_id"]: item for item in models}
    model_ids = list(model_by_id)
    active_model = next(
        (item for item in models if item["selection_mode"] == "DEFAULT"), None
    )
    session_model_id = session_model_id_from(current) if current else None
    initial_model_id = (
        session_model_id if running and session_model_id in model_by_id
        else active_model["model_id"] if active_model else None
    )
    default_index = model_ids.index(initial_model_id) if initial_model_id else 0
    target = st.text_input(
        "Target IP", value="", placeholder="192.168.128.4", disabled=running
    )
    interface = st.selectbox(
        "Capture Interface", choices or ["Interface discovery unavailable"],
        disabled=running or not choices,
    )
    selected_model_id = st.selectbox(
        "Model", model_ids or ["No verified runtime models available"],
        index=default_index if model_ids else 0,
        disabled=running or not model_ids,
        key="selected_monitoring_model_id",
    )
    selected_model = model_by_id.get(selected_model_id)
    session_model = model_metadata_for_display(
        model_by_id, selected_model_id, running=running, current_session=current
    )
    displayed_model = session_model if running else selected_model
    if displayed_model:
        st.markdown(
            f'**Model:** {displayed_model["model_version"]}  \n'
            f'**Scientific status:** {displayed_model.get("scientific_status", "—")}  \n'
            f'**Runtime mode:** {displayed_model["selection_mode"]}'
        )
        if displayed_model.get("scientific_decision"):
            st.caption(f'Scientific decision: {displayed_model["scientific_decision"]}')
    submitted = st.button(
        "START MONITORING", type="primary",
        disabled=running or not choices or not model_ids,
    )
    if not interfaces["discovery_available"]:
        st.warning("Network interface discovery is unavailable on the API host.")
    if submitted:
        client.start_monitoring(target, interface, selected_model_id)
        st.rerun()

    st.divider()
    st.subheader("Current Session")
    st.metric("Controller status", state["status"])
    if current:
        columns = st.columns(4)
        values = [
            ("Session ID", current["id"]), ("Target", current["target_ip"]),
            ("Interface", current["interface_name"]),
            ("Model", session_model_display(current["model_version"], dashboard_config.demo_model_version)),
            ("Elapsed", _elapsed(current["started_at"])), ("Flows", current["flow_count"]),
            ("Predictions", current["prediction_count"]), ("Alerts", current["alert_count"]),
        ]
        for index, (label, value) in enumerate(values):
            columns[index % 4].metric(label, value)
        if current.get("last_error"):
            st.error(current["last_error"])
        st.caption(
            f'Model SHA-256: {current.get("selected_model_sha256") or "—"} · '
            f'Selection: {current.get("selection_mode") or "DEFAULT"} · '
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
    fields = ["id", "target_ip", "interface_name", "selected_model_version",
              "selected_model_sha256", "selection_mode", "status",
              "started_at", "stopped_at", "flow_count", "prediction_count", "alert_count"]
    st.dataframe([{key: row.get(key) for key in fields} for row in rows], use_container_width=True)
    st.caption(f"Page {page} · showing {len(rows)} of at most {PAGE_SIZE} sessions.")
