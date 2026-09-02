import pandas as pd
import streamlit as st

from dashboard.components.evidence import render_provenance
from dashboard.components.styles import section_heading
from dashboard.presentation import comparison_rows, confusion_matrix_view, notes_view, percent, split_evaluations


EXPERIMENT_LABELS = {
    "EXPERIMENT_A": "Experiment A — Internal Model Evaluation",
    "EXPERIMENT_B": "Experiment B — Ordered-Contiguous Holdout Validation",
    "EXPERIMENT_C": "Experiment C — External Virtual Laboratory Validation",
}


def _render_matrix(value) -> None:
    parsed = confusion_matrix_view(value)
    section_heading("Confusion matrix", "Actual class on rows; predicted class on columns.")
    if parsed is None:
        st.info("No confusion matrix is available for this experiment.")
        return
    labels, values = parsed
    frame = pd.DataFrame(values, index=[f"Actual {x}" for x in labels], columns=[f"Predicted {x}" for x in labels])
    st.dataframe(frame.style.background_gradient(cmap="Blues", axis=None).format("{:,}"), width="stretch")


def render(client) -> None:
    section_heading("Evaluation", "Verified Experiment A/B/C results imported into the application database.")
    experiments = client.experiments()
    if not experiments:
        st.info("No verified experiments have been imported.")
        return
    by_code = {row["experiment_code"]: row for row in experiments}
    codes = [code for code in ("EXPERIMENT_A", "EXPERIMENT_B", "EXPERIMENT_C") if code in by_code]
    selected = st.selectbox("Experiment", codes, format_func=lambda code: EXPERIMENT_LABELS.get(code, code))
    experiment = by_code[selected]
    rows = client.experiment_evaluation(experiment["id"])
    overall, classes = split_evaluations(rows)

    st.subheader(EXPERIMENT_LABELS.get(selected, experiment["experiment_name"]))
    st.caption(f"{experiment['experiment_type']} · {experiment['status']}")
    if experiment.get("description"):
        st.write(experiment["description"])
    if selected == "EXPERIMENT_C":
        st.warning(
            "This external virtual-laboratory validation reused the fitted model: no retraining "
            "and no preprocessing refit. The imported evidence shows severe generalization failure "
            "under new lab traffic and environment/distribution shift."
        )
    elif selected == "EXPERIMENT_B":
        st.info("Scenario / ordered-contiguous holdout validation; this is not external production validation.")

    section_heading("Overall metrics", "Only values present in the imported evaluation record are shown.")
    if overall is None:
        st.info("No overall metrics are available.")
    else:
        metrics = [("Accuracy", "accuracy"), ("Macro precision", "macro_precision"),
                   ("Macro recall", "macro_recall"), ("Macro F1", "macro_f1")]
        for column, (label, key) in zip(st.columns(4), metrics, strict=True):
            column.metric(label, percent(overall.get(key)))

    section_heading("Per-class metrics", "Class-specific values retain unavailable fields as unavailable.")
    if classes:
        frame = pd.DataFrame([{
            "Class": row["class_name"], "Precision": row.get("precision_score"),
            "Recall": row.get("recall_score"), "F1": row.get("f1_score"),
            "True positives": row.get("true_positive"), "False negatives": row.get("false_negative"),
        } for row in classes])
        st.dataframe(frame, width="stretch", hide_index=True, column_config={
            "Precision": st.column_config.NumberColumn(format="%.6f"),
            "Recall": st.column_config.NumberColumn(format="%.6f"),
            "F1": st.column_config.NumberColumn(format="%.6f"),
        })
    else:
        st.info("No per-class metrics are available.")
    _render_matrix(overall.get("confusion_matrix") if overall else None)

    notes = notes_view(overall.get("notes")) if overall else None
    section_heading("Notes and limitations", "Imported caveats and evaluation context.")
    if notes is None:
        st.info("No notes or limitations are available.")
    else:
        st.json(notes) if isinstance(notes, (dict, list)) else st.write(notes)
    render_provenance(client.evidence_sources(owner_type="EXPERIMENT", owner_key=selected), {
        "Source path": experiment.get("source_path"), "SHA-256": experiment.get("source_sha256"),
        "Schema version": experiment.get("schema_version"), "Imported at": experiment.get("imported_at"),
    })

    section_heading("Experiment comparison", "A compact view of imported metrics; unavailable values remain blank.")
    all_evaluations = {row["id"]: client.experiment_evaluation(row["id"]) for row in experiments}
    st.dataframe(pd.DataFrame(comparison_rows(experiments, all_evaluations)), width="stretch", hide_index=True)
