import pandas as pd
import streamlit as st
import altair as alt

from dashboard.components.evidence import render_provenance
from dashboard.components.styles import section_heading
from dashboard.presentation import dataset_view


def render(client) -> None:
    section_heading("Dataset", "Read-only information imported from canonical thesis evidence.")
    rows = client.datasets()
    if not rows:
        st.info("No verified dataset evidence has been imported.")
        return
    row = rows[0]
    download = client.export_dataset()
    st.download_button(
        "Download metadata (JSON)", data=download.content,
        file_name=download.filename, mime=download.content_type,
    )
    view = dataset_view(row)
    cols = st.columns(3)
    cols[0].metric("Total rows", f"{view['Total rows']:,}" if isinstance(view["Total rows"], int) else view["Total rows"])
    cols[1].metric("Total features", view["Total features"])
    cols[2].metric("Label column", view["Label column"])
    st.subheader(view["Dataset name"])
    st.caption("Canonical scientific dataset · presentation is read-only")

    distribution = row.get("class_distribution")
    if distribution:
        section_heading("Class distribution", "Mapped class totals from imported evidence.")
        frame = pd.DataFrame({"Class": list(distribution), "Rows": list(distribution.values())})
        chart = alt.Chart(frame).mark_bar(cornerRadiusTopLeft=5, cornerRadiusTopRight=5).encode(
            x=alt.X("Class:N", sort=["Normal", "DDoS", "PortScan"], title=None),
            y=alt.Y("Rows:Q", title="Rows"), color=alt.Color("Class:N", legend=None),
            tooltip=["Class", alt.Tooltip("Rows:Q", format=",")],
        ).properties(height=300)
        st.altair_chart(chart, width="stretch")
        st.dataframe(frame, width="stretch", hide_index=True)
    else:
        st.info("Class distribution is not available in the imported evidence.")

    sources = client.evidence_sources(owner_type="DATASET")
    render_provenance(sources, {
        "Source path": row.get("source_path"), "SHA-256": row.get("source_sha256"),
        "Imported at": row.get("created_at"),
    })
