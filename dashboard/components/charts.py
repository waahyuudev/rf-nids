import pandas as pd
import streamlit as st
import altair as alt


def render_distribution(summary: dict, chart_type: str = "Bar") -> None:
    data = pd.DataFrame({"Class": ["Normal", "DDoS", "PortScan"], "Flows": [summary.get("total_normal", 0), summary.get("total_ddos", 0), summary.get("total_portscan", 0)]})
    colors = alt.Scale(domain=["Normal", "DDoS", "PortScan"], range=["#2f8f74", "#d95656", "#e49a3a"])
    if chart_type == "Donut":
        chart = alt.Chart(data).mark_arc(innerRadius=65, outerRadius=105).encode(
            theta="Flows:Q", color=alt.Color("Class:N", scale=colors),
            tooltip=["Class", "Flows"], opacity=alt.condition(alt.datum.Flows > 0, alt.value(1), alt.value(.25)),
        ).properties(height=280)
    else:
        chart = alt.Chart(data).mark_bar(cornerRadiusTopLeft=5, cornerRadiusTopRight=5).encode(
            x=alt.X("Class:N", sort=["Normal", "DDoS", "PortScan"], title=None),
            y=alt.Y("Flows:Q", title="Number of flows"),
            color=alt.Color("Class:N", scale=colors, legend=None), tooltip=["Class", "Flows"],
        ).properties(height=280)
    st.altair_chart(chart, width="stretch")


def render_timeline(rows: list[dict]) -> None:
    if not rows:
        st.info("No traffic predictions available yet.")
        return
    frame = pd.DataFrame(rows)
    frame["bucket"] = pd.to_datetime(frame["bucket"])
    frame = frame.set_index("bucket").rename(columns={"normal": "Normal", "ddos": "DDoS", "portscan": "PortScan"})
    long = frame.reset_index().melt("bucket", var_name="Class", value_name="Flows")
    chart = alt.Chart(long).mark_line(point=True, strokeWidth=2).encode(
        x=alt.X("bucket:T", title="Time"), y=alt.Y("Flows:Q", title="Flows per minute"),
        color=alt.Color("Class:N", scale=alt.Scale(domain=["Normal", "DDoS", "PortScan"], range=["#2f8f74", "#d95656", "#e49a3a"])),
        tooltip=[alt.Tooltip("bucket:T", title="Time"), "Class", "Flows"],
    ).properties(height=280)
    st.altair_chart(chart, width="stretch")
