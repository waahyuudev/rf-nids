"""Small visual system for a calm, academic monitoring interface."""

import streamlit as st


def apply_styles() -> None:
    st.markdown(
        """
        <style>
        .stApp { background: #f8fafc; }
        [data-testid="stSidebar"] { background: #17263a; border-right: 1px solid #24374f; }
        [data-testid="stSidebar"] * { color: #e5edf6; }
        [data-testid="stSidebarNav"] { display: none !important; }
        [data-testid="stSidebarContent"] { padding-top: 1.5rem; }
        [data-testid="stSidebar"] h1 { color: #fff; font-size: 1.35rem; letter-spacing: -.01em; }
        [data-testid="stSidebar"] hr { border-color: #30445d; margin: 1.25rem 0; }
        [data-testid="stSidebar"] [role="radiogroup"] { gap: .35rem; }
        [data-testid="stSidebar"] [role="radiogroup"] label {
            border-radius: 6px; padding: .55rem .7rem; transition: background .12s ease;
        }
        [data-testid="stSidebar"] [role="radiogroup"] label:hover {
            background: #22364e;
        }
        [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
            background: #294766; box-shadow: inset 3px 0 #5fb3d1;
        }
        [data-testid="stSidebar"] [role="radiogroup"] [data-testid="stMarkdownContainer"] p {
            font-size: .92rem; font-weight: 500;
        }
        [data-testid="stSidebar"] [role="radiogroup"] [data-testid="stRadio"] { gap: 0; }
        [data-testid="stSidebar"] [role="radiogroup"] div[role="radio"] { display: none; }
        [data-testid="stSidebar"] .stCheckbox label { padding: .2rem 0; }
        [data-testid="stSidebar"] [data-testid="stButton"] button {
            background: #287aa1;
            border: 1px solid #3d91b7;
            color: #ffffff;
            font-weight: 600;
        }
        [data-testid="stSidebar"] [data-testid="stButton"] button * {
            color: #ffffff;
        }
        [data-testid="stSidebar"] [data-testid="stButton"] button:hover {
            background: #3390b9;
            border-color: #63b8d7;
        }
        [data-testid="stSidebar"] [data-testid="stButton"] button:focus {
            box-shadow: 0 0 0 3px rgba(95,179,209,.28);
        }
        [data-testid="stMetric"] {
            background: white; border: 1px solid #e2e8f0; border-radius: 6px;
            padding: .9rem 1rem; box-shadow: 0 1px 3px rgba(15,23,42,.05);
        }
        [data-testid="stMetricLabel"] { color: #607086; }
        [data-testid="stMetricValue"] { color: #172033; }
        .rf-header {
            background: #fff; padding: 1.1rem 1.25rem; margin: 0 0 1.2rem;
            border: 1px solid #e2e8f0; border-left: 4px solid #287aa1; border-radius: 7px;
        }
        .rf-header h1 { color: #172033; margin: 0; font-size: 1.75rem; font-weight: 650; }
        .rf-header p { margin: .35rem 0 0; color: #64748b; }
        .rf-section-note { color: #65758a; margin-top: -.6rem; }
        .rf-status {
            display: inline-block; padding: .28rem .65rem; border-radius: 999px;
            font-size: .76rem; font-weight: 600;
        }
        .rf-online { color: #116149; background: #dff6ed; }
        .rf-offline { color: #9c2d32; background: #fde9e9; }
        [data-testid="stButton"] button { border-radius: 6px; }
        [data-testid="stSelectbox"] > div > div,
        [data-testid="stTextInput"] input { border-radius: 6px; }
        div[data-testid="stDataFrame"] { border: 1px solid #e2e8f0; border-radius: 6px; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_header(online: bool) -> None:
    state = "Online" if online else "Offline"
    css_class = "rf-online" if online else "rf-offline"
    st.markdown(
        f"""
        <div class="rf-header">
          <h1>RF-NIDS Monitoring Dashboard</h1>
          <p>Traffic classification and alert monitoring &nbsp;
          <span class="rf-status {css_class}">● API {state}</span></p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_heading(title: str, description: str) -> None:
    st.subheader(title)
    st.markdown(f'<p class="rf-section-note">{description}</p>', unsafe_allow_html=True)
