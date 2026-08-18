"""Streamlit dashboard for the Network Anomaly Detector."""

import os
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from pipeline import run_pipeline

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
SAMPLE_FILE = os.path.join(DATA_DIR, "sample_traffic.csv")

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Network Anomaly Detector",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
    div[data-testid="stMetric"] {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 10px;
        padding: 14px 18px;
    }
    div[data-testid="stMetricValue"] { font-size: 1.8rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ Network Anomaly Detector")
st.caption("Isolation Forest · Batch Pipeline · Synthetic Traffic Demo")

# ---------------------------------------------------------------------------
# Sidebar controls
# ---------------------------------------------------------------------------
st.sidebar.header("⚙️ Pipeline Controls")

contamination = st.sidebar.slider(
    "Contamination rate",
    min_value=0.01,
    max_value=0.20,
    value=0.05,
    step=0.01,
    help="Expected proportion of anomalies in the dataset.",
)

run_btn = st.sidebar.button("🚀 Run Pipeline", type="primary", use_container_width=True)

st.sidebar.divider()
st.sidebar.markdown(
    "**Stack:** Python · Pandas · Scikit-learn (Isolation Forest) · Streamlit · Plotly"
)


# ---------------------------------------------------------------------------
# Cached pipeline execution
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner="Running anomaly detection pipeline…")
def _run(filepath: str, contamination: float) -> pd.DataFrame:
    return run_pipeline(filepath, contamination=contamination)


# ---------------------------------------------------------------------------
# Main content
# ---------------------------------------------------------------------------

if not os.path.exists(SAMPLE_FILE):
    st.warning(
        "Sample data not found. Run `python generate_sample_data.py` first to "
        "create `data/sample_traffic.csv`."
    )
    st.stop()

if run_btn or "df" not in st.session_state or st.session_state.get("_contam") != contamination:
    st.session_state["df"] = _run(SAMPLE_FILE, contamination)
    st.session_state["_contam"] = contamination

df: pd.DataFrame = st.session_state["df"]

# ── Summary metrics ──────────────────────────────────────────────────────
total = len(df)
anomalies = int((df["is_anomaly"] == -1).sum())
pct = anomalies / total * 100 if total else 0
top_talker = (
    df.loc[df["is_anomaly"] == -1, "src_ip"].value_counts().idxmax()
    if anomalies else "—"
)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Flows", f"{total:,}")
col2.metric("Anomalies Flagged", f"{anomalies:,}")
col3.metric("% Anomalous", f"{pct:.1f}%")
col4.metric("Top Anomalous Source", top_talker)

st.divider()

# ── Charts row ────────────────────────────────────────────────────────────
chart_df = df.copy()
chart_df["timestamp"] = pd.to_datetime(chart_df["timestamp"])
chart_df["hour"] = chart_df["timestamp"].dt.floor("1h")

c1, c2 = st.columns([1.3, 1])

with c1:
    st.subheader("📈 Anomalies Over Time")
    hourly = (
        chart_df[chart_df["is_anomaly"] == -1]
        .groupby("hour")
        .size()
        .reset_index(name="anomaly_count")
    )
    fig_time = px.bar(
        hourly, x="hour", y="anomaly_count",
        labels={"hour": "Time", "anomaly_count": "Anomalies"},
        color="anomaly_count", color_continuous_scale="Reds",
    )
    fig_time.update_layout(
        template="plotly_dark", height=340, margin=dict(l=10, r=10, t=10, b=10),
        coloraxis_showscale=False,
    )
    st.plotly_chart(fig_time, use_container_width=True)

with c2:
    st.subheader("🎯 Top Anomalous Sources")
    top_ips = (
        df[df["is_anomaly"] == -1]["src_ip"]
        .value_counts()
        .head(8)
        .reset_index()
    )
    top_ips.columns = ["src_ip", "count"]
    fig_top = px.bar(
        top_ips.sort_values("count"), x="count", y="src_ip", orientation="h",
        labels={"count": "Anomaly Count", "src_ip": "Source IP"},
        color="count", color_continuous_scale="Reds",
    )
    fig_top.update_layout(
        template="plotly_dark", height=340, margin=dict(l=10, r=10, t=10, b=10),
        coloraxis_showscale=False,
    )
    st.plotly_chart(fig_top, use_container_width=True)

# ── Score distribution ───────────────────────────────────────────────────
st.subheader("📊 Anomaly Score Distribution")
fig_hist = go.Figure()
fig_hist.add_trace(go.Histogram(
    x=df.loc[df["is_anomaly"] == 1, "anomaly_score"],
    name="Normal", marker_color="#3b82f6", opacity=0.75, nbinsx=50,
))
fig_hist.add_trace(go.Histogram(
    x=df.loc[df["is_anomaly"] == -1, "anomaly_score"],
    name="Anomaly", marker_color="#ef4444", opacity=0.85, nbinsx=50,
))
fig_hist.update_layout(
    barmode="overlay", template="plotly_dark", height=280,
    margin=dict(l=10, r=10, t=10, b=10),
    xaxis_title="Anomaly Score (lower = more anomalous)",
    yaxis_title="Flow Count",
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
)
st.plotly_chart(fig_hist, use_container_width=True)

st.divider()

# ── Results table ────────────────────────────────────────────────────────
st.subheader("📋 Detection Results")

filter_col1, filter_col2 = st.columns([1, 3])
with filter_col1:
    show_only_anomalies = st.checkbox("Show only flagged anomalies", value=True)

sorted_df = df.sort_values("anomaly_score").reset_index(drop=True)
if show_only_anomalies:
    sorted_df = sorted_df[sorted_df["is_anomaly"] == -1]


def _highlight(row):
    if row["is_anomaly"] == -1:
        return ["background-color: rgba(239, 68, 68, 0.15)"] * len(row)
    return [""] * len(row)


display_cols = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "bytes_sent", "packets_sent", "duration_sec",
    "bytes_per_sec", "unique_dst_ports", "flow_count",
    "anomaly_score", "is_anomaly",
]

st.dataframe(
    sorted_df[display_cols].style.apply(_highlight, axis=1),
    use_container_width=True,
    height=420,
)

st.download_button(
    "⬇️ Download results as CSV",
    data=sorted_df[display_cols].to_csv(index=False).encode("utf-8"),
    file_name="anomaly_results.csv",
    mime="text/csv",
)
