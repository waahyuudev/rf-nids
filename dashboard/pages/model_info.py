import streamlit as st
from dashboard.components.styles import section_heading


def _percent(value):
    return "N/A" if value is None else f"{value:.2%}"


def render(client) -> None:
    section_heading("Active model", "Model currently used by the detection API.")
    info = client.model_info()
    st.subheader(info["model_name"])
    st.caption(f"Version {info['model_version']} · {info['algorithm']} · {info['feature_count']} features")
    columns = st.columns(4)
    for column, (label, key) in zip(columns, [("Accuracy", "accuracy"), ("Macro F1", "macro_f1"), ("DDoS Recall", "ddos_recall"), ("PortScan Recall", "portscan_recall")], strict=True):
        column.metric(label, _percent(info.get(key)))
    st.caption(f"Trained: {info.get('trained_at') or 'Not recorded'}")
    st.markdown("**Classes:** " + " · ".join(info["class_labels"]))
    st.divider()
    section_heading("Evaluation context", "Historical evaluation results for the active model.")
    st.markdown("**Experiment A — Stratified Random Split**  \nEvaluasi utama dengan pembagian acak terstratifikasi 80/20.")
    st.markdown("**Experiment B — Scenario-based / Ordered Block Validation**  \nStress test menggunakan holdout blok berurutan untuk mengurangi overlap capture.")
    st.caption("Runtime Monitoring Data → FastAPI · Historical Experiment Metrics → reports/metrics JSON")
