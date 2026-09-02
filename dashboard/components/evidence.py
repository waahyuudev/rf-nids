import pandas as pd
import streamlit as st


def render_provenance(rows: list[dict], fallback: dict | None = None) -> None:
    with st.expander("Evidence / Provenance"):
        if rows:
            frame = pd.DataFrame(rows).reindex(
                columns=["evidence_role", "source_path", "source_sha256", "schema_version", "imported_at"]
            ).rename(columns={
                "evidence_role": "Role", "source_path": "Source path",
                "source_sha256": "SHA-256", "schema_version": "Schema version",
                "imported_at": "Imported at",
            })
            frame = frame.fillna("Not available")
            st.dataframe(frame, width="stretch", hide_index=True)
        elif fallback:
            st.json({key: ("Not available" if value is None else value) for key, value in fallback.items()})
        else:
            st.info("No provenance records are available.")
