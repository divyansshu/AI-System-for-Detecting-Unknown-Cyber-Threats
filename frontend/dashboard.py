from datetime import timedelta
import json
import os
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv
from sqlalchemy import create_engine


load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[1]
THRESHOLD_FILE = PROJECT_ROOT / "models" / "ae_threshold.json"
DB_URL = os.getenv("DB_URL", "postgresql://postgres:postgres@localhost:5432/soc_db")

NORMAL_LABELS = {"Passed Both Stages", "Passed Both stages"}
NORMAL_DISPLAY = "Normal Traffic (Allowed)"
STAGE1_LABEL = "Stage 1 (XGBoost)"
STAGE2_LABEL = "Stage 2 (Autoencoder)"

COLOR_MAP = {
    NORMAL_DISPLAY: "#00c853",
    STAGE1_LABEL: "#ffa500",
    STAGE2_LABEL: "#ff4b4b",
}


st.set_page_config(page_title="SOC Command Center", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    .metric-box {
        background-color: #1e1e1e;
        padding: 15px;
        border-radius: 8px;
        text-align: center;
        border: 1px solid #333;
    }
    .metric-box h3 {
        margin: 0 0 10px 0;
    }
    .alert-text {
        color: #ff4b4b;
        font-weight: bold;
    }
    .normal-text {
        color: #00c853;
        font-weight: bold;
    }
    .log-terminal {
        background-color: #0e1117;
        color: #ff4b4b;
        font-family: monospace;
        padding: 10px;
        border-radius: 5px;
        height: 360px;
        overflow-y: scroll;
        border: 1px solid #333;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_db_engine():
    return create_engine(DB_URL)


@st.cache_data
def load_autoencoder_threshold():
    try:
        with THRESHOLD_FILE.open("r", encoding="utf-8") as f:
            return float(json.load(f)["best_threshold"])
    except Exception:
        return None


def normalize_caught_by(value):
    if value in NORMAL_LABELS:
        return NORMAL_DISPLAY
    return value


engine = get_db_engine()
ae_threshold = load_autoencoder_threshold()


with st.sidebar:
    st.title("SOC Controls")

    monitoring = st.toggle("Live Kafka Feed", value=True)
    refresh_rate = st.slider("Refresh Rate (seconds)", 1, 5, 2)
    # show_all_events = st.toggle("Show normal events", value=False)

    st.markdown("---")
    st.write("**Architecture:**")
    st.code("Producer -> Kafka -> FastAPI -> PostgreSQL -> UI")

    if ae_threshold is not None:
        st.metric("AE Threshold", f"{ae_threshold:.4f}")


st.title("Live SOC Threat Monitor")


def fetch_dashboard_data():
    try:
        stats_query = """
            SELECT caught_by, COUNT(*) AS count
            FROM threat_alerts
            GROUP BY caught_by
        """
        stats_df = pd.read_sql(stats_query, engine)

        events_query = """
            SELECT id, timestamp, action, threat_type, caught_by, anomaly_score
            FROM threat_alerts
            ORDER BY id DESC
            LIMIT 100
        """
        events_df = pd.read_sql(events_query, engine)

        return stats_df, events_df
    except Exception as e:
        st.error(f"Database Connection Error: {e}")
        return pd.DataFrame(), pd.DataFrame()


@st.fragment(run_every=timedelta(seconds=refresh_rate))
def live_dashboard_feed():
    if not monitoring:
        st.info("Dashboard is paused. Toggle Live Kafka Feed to resume polling PostgreSQL.")
        return

    stats_df, events_df = fetch_dashboard_data()

    if stats_df.empty:
        st.info("Awaiting data...")
        return

    stats_df = stats_df.copy()
    stats_df["display_label"] = stats_df["caught_by"].map(normalize_caught_by)
    summary_df = stats_df.groupby("display_label", as_index=False)["count"].sum()

    total_scanned = int(summary_df["count"].sum())
    normal_count = int(summary_df.loc[summary_df["display_label"] == NORMAL_DISPLAY, "count"].sum())
    stage1_count = int(summary_df.loc[summary_df["display_label"] == STAGE1_LABEL, "count"].sum())
    stage2_count = int(summary_df.loc[summary_df["display_label"] == STAGE2_LABEL, "count"].sum())
    total_alerts = stage1_count + stage2_count

    events_df = events_df.copy()
    if not events_df.empty:
        events_df["display_label"] = events_df["caught_by"].map(normalize_caught_by)

    stage2_df = events_df[events_df["display_label"] == STAGE2_LABEL] if not events_df.empty else pd.DataFrame()
    avg_stage2_score = stage2_df["anomaly_score"].mean() if not stage2_df.empty else 0.0

    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(
        f"<div class='metric-box'><h3>{total_scanned:,}</h3><p>Total Flows</p></div>",
        unsafe_allow_html=True,
    )
    c2.markdown(
        f"<div class='metric-box'><h3 class='normal-text'>{normal_count:,}</h3><p>Normal Flows</p></div>",
        unsafe_allow_html=True,
    )
    c3.markdown(
        f"<div class='metric-box'><h3 class='alert-text'>{total_alerts:,}</h3><p>Total Alerts</p></div>",
        unsafe_allow_html=True,
    )
    c4.markdown(
        f"<div class='metric-box'><h3>{avg_stage2_score:.4f}</h3><p>Avg Stage-2 Score</p></div>",
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)

    col_chart1, col_chart2 = st.columns([2, 1])

    with col_chart1:
        st.subheader("Zero-Day Anomaly Scores")
        if not stage2_df.empty:
            line_df = stage2_df.head(20).iloc[::-1]
            fig_line = px.line(
                line_df,
                x="id",
                y="anomaly_score",
                markers=True,
                color_discrete_sequence=[COLOR_MAP[STAGE2_LABEL]],
            )
            if ae_threshold is not None:
                fig_line.add_hline(
                    y=ae_threshold,
                    line_dash="dot",
                    line_color="#00c853",
                    annotation_text=f"threshold {ae_threshold:.4f}",
                    annotation_position="top left",
                )
            fig_line.update_layout(
                height=300,
                margin=dict(l=0, r=0, t=30, b=0),
                plot_bgcolor="#0e1117",
                paper_bgcolor="#0e1117",
                xaxis_title="Alert ID",
                yaxis_title="MAE score",
            )
            st.plotly_chart(fig_line, width="stretch")
        else:
            st.info("No Stage-2 anomalies logged yet.")

    with col_chart2:
        st.subheader("Traffic Distribution")
        fig_pie = px.pie(
            summary_df,
            values="count",
            names="display_label",
            hole=0.4,
            color="display_label",
            color_discrete_map=COLOR_MAP,
        )
        fig_pie.update_traces(textposition="inside", textinfo="percent")
        fig_pie.update_layout(
            height=300,
            margin=dict(l=0, r=0, t=30, b=0),
            paper_bgcolor="#0e1117",
            legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5),
        )
        st.plotly_chart(fig_pie, width="stretch")

    st.markdown("<hr style='border: 1px solid #333;'>", unsafe_allow_html=True)

    filtered_events = events_df
    if not show_all_events and not events_df.empty:
        filtered_events = events_df[~events_df["display_label"].eq(NORMAL_DISPLAY)]

    st.subheader("Recent Events")
    if not filtered_events.empty:
        display_df = filtered_events[
            ["id", "timestamp", "action", "threat_type", "display_label", "anomaly_score"]
        ].head(25)
        display_df = display_df.rename(columns={"display_label": "caught_by"})
        st.dataframe(display_df, width="stretch", hide_index=True)
    else:
        st.info("No matching events yet.")

    st.subheader("Terminal Output")
    alert_events = events_df[~events_df["display_label"].eq(NORMAL_DISPLAY)] if not events_df.empty else pd.DataFrame()
    if not alert_events.empty:
        logs = [
            f"[ALERT] ID {row['id']} | {row['threat_type']} caught by {row['display_label']} "
            f"(Score: {row['anomaly_score']:.4f})"
            for _, row in alert_events.head(25).iterrows()
        ]
        st.markdown(f"<div class='log-terminal'>{'<br>'.join(logs)}</div>", unsafe_allow_html=True)
    else:
        st.markdown(
            "<div class='log-terminal'>System secure. Waiting for alert events...</div>",
            unsafe_allow_html=True,
        )

live_dashboard_feed()
