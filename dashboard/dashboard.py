import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import time
from datetime import datetime
import requests

# --- 1. UI Configuration ---
st.set_page_config(page_title="SOC Command Center", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    .metric-box { background-color: #1e1e1e; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333;}
    .alert-text { color: #ff4b4b; font-weight: bold; }
    .normal-text { color: #00fa9a; font-weight: bold; }
    .log-terminal { background-color: #0e1117; color: #00ff00; font-family: monospace; padding: 10px; border-radius: 5px; height: 250px; overflow-y: scroll; border: 1px solid #333;}
    </style>
""", unsafe_allow_html=True)

# --- 2. Session State Initialization ---
if 'monitoring' not in st.session_state:
    st.session_state.monitoring = False
if 'traffic_history' not in st.session_state:
    st.session_state.traffic_history = pd.DataFrame(columns=["Time", "Score", "Status", "Risk", "Model"])
if 'logs' not in st.session_state:
    st.session_state.logs = []

# --- 3. Sidebar Controls ---
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/cyber-security.png", width=80)
    st.title("SOC Controls")

    start_btn = st.button("▶ Start Monitoring" if not st.session_state.monitoring else "⏸ Stop Monitoring", type="primary")

    if start_btn:
        st.session_state.monitoring = not st.session_state.monitoring
        if st.session_state.monitoring:
            st.session_state.traffic_history = pd.DataFrame(columns=["Time", "Score", "Status", "Risk", "Model"])
            st.session_state.logs = []

    st.markdown("---")
    st.write("**Target API Engine:**")
    st.code("http://127.0.0.1:8000/scan-traffic")

    if st.button("🗑️ Clear Logs"):
        st.session_state.traffic_history = pd.DataFrame(columns=["Time", "Score", "Status", "Risk", "Model"])
        st.session_state.logs = []

# --- 4. Main Dashboard Layout ---
st.title("🛡️ Live SOC Threat Monitor")

status_placeholder = st.empty()
charts_placeholder = st.empty()
tables_placeholder = st.empty()

# --- 5. Feature Definitions ---
TARGET_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Length of Fwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Fwd URG Flags", "Fwd Header Length",
    "Bwd Packets/s", "Min Packet Length", "Packet Length Mean", "Packet Length Variance",
    "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "Down/Up Ratio", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Std"
]

def normalize(name):
    return str(name).lower().replace(" ", "").replace("_", "").replace("/", "")

def load_and_map_csv():
    """Load live_flows.csv and map columns to TARGET_FEATURES."""
    live_df = pd.read_csv("live_flows.csv")
    col_map = {}
    for target in TARGET_FEATURES:
        norm_target = normalize(target)
        for col in live_df.columns:
            if normalize(col) == norm_target:
                col_map[target] = col
                break
    mapped_data = []
    for target in TARGET_FEATURES:
        if target in col_map:
            mapped_data.append(live_df[col_map[target]])
        else:
            mapped_data.append(pd.Series([0.0] * len(live_df)))
    final_df = pd.concat(mapped_data, axis=1)
    final_df.columns = TARGET_FEATURES
    final_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    final_df.fillna(0, inplace=True)
    return live_df, final_df, col_map


def render_ui(status_placeholder, charts_placeholder, tables_placeholder, df, current_row, total_rows, mode="REPLAYING"):
    """Render all dashboard UI elements."""
    with status_placeholder.container():
        c1, c2, c3, c4 = st.columns(4)
        alerts = len(df[df['Status'] == 'Blocked']) if not df.empty else 0
        avg_score = df['Score'].mean() if not df.empty else 0.0

        if mode == "LISTENING":
            c1.markdown("<div class='metric-box'><h3>📡 LISTENING</h3><p>Waiting for new traffic...</p></div>", unsafe_allow_html=True)
        else:
            c1.markdown(f"<div class='metric-box'><h3>🟢 REPLAYING</h3><p>Packet {current_row + 1} / {total_rows}</p></div>", unsafe_allow_html=True)
        c2.markdown(f"<div class='metric-box'><h3>{len(df)}</h3><p>Requests Processed</p></div>", unsafe_allow_html=True)
        c3.markdown(f"<div class='metric-box'><h3 class='{'alert-text' if alerts > 0 else ''}'>{alerts}</h3><p>Alerts Triggered</p></div>", unsafe_allow_html=True)
        c4.markdown(f"<div class='metric-box'><h3>{avg_score:.3f}</h3><p>Avg Anomaly Score</p></div>", unsafe_allow_html=True)

    with charts_placeholder.container():
        st.markdown("<br>", unsafe_allow_html=True)
        col_chart1, col_chart2 = st.columns([2, 1])
        with col_chart1:
            st.subheader("📈 Real-Time Anomaly Score")
            if not df.empty:
                line_df = df.iloc[::-1]
                fig_line = px.line(line_df, x='Time', y='Score', markers=True, color_discrete_sequence=['#00fa9a'])
                fig_line.add_hline(y=0.40, line_dash="dash", line_color="red", annotation_text="Threshold")
                fig_line.update_layout(height=300, margin=dict(l=0, r=0, t=30, b=0), plot_bgcolor='#0e1117', paper_bgcolor='#0e1117')
                st.plotly_chart(fig_line, use_container_width=True)
        with col_chart2:
            st.subheader("📊 Traffic Distribution")
            if not df.empty:
                pie_data = df['Status'].value_counts().reset_index()
                pie_data.columns = ['Status', 'Count']
                fig_pie = px.pie(pie_data, values='Count', names='Status', hole=0.4,
                                 color='Status', color_discrete_map={'Normal':'#00fa9a', 'Blocked':'#ff4b4b', 'Error': '#ffa500'})
                fig_pie.update_layout(height=300, margin=dict(l=0, r=0, t=30, b=0), paper_bgcolor='#0e1117')
                st.plotly_chart(fig_pie, use_container_width=True)

    with tables_placeholder.container():
        st.markdown("<br>", unsafe_allow_html=True)
        col_table, col_logs = st.columns([2, 1.5])
        with col_table:
            st.subheader("📡 Live Traffic Monitor")
            def color_risk(val):
                color = '#ff4b4b' if val in ['High', 'Critical'] else '#00fa9a'
                return f'color: {color}'
            display_df = df.head(8).reset_index(drop=True)
            if not display_df.empty:
                st.dataframe(display_df.style.map(color_risk, subset=['Risk']), use_container_width=True, hide_index=True)
        with col_logs:
            st.subheader("📜 Event History")
            log_html = "<br>".join(st.session_state.logs)
            st.markdown(f"<div class='log-terminal'>{log_html}</div>", unsafe_allow_html=True)


# --- 6. THE MONITORING ENGINE ---
if st.session_state.monitoring:
    try:
        live_df, final_df, col_map = load_and_map_csv()
        total_rows = len(final_df)
        st.sidebar.success(f"✅ Loaded {total_rows} live packets.")
    except Exception as e:
        st.error(f"Failed to load live_flows.csv. Error: {e}")
        st.session_state.monitoring = False
        total_rows = 0

    # THE MONITORING LOOP
    current_row = 0
    while st.session_state.monitoring and current_row < total_rows:
        current_time = datetime.now().strftime("%H:%M:%S")

        packet_features = final_df.iloc[current_row].astype(float).tolist()
        payload = {"features": packet_features}

        try:
            response = requests.post("http://127.0.0.1:8000/scan-traffic", json=payload, timeout=2)

            if response.status_code == 200:
                result = response.json()
                action = result['action']
                threat_type = result['threat_type']
                caught_by = result['caught_by']
                details = result['details']

                try:
                    if "Error:" in details:
                        score = float(details.split("Error: ")[1])
                    elif "error (" in details:
                        score = float(details.split("error (")[1].split(")")[0])
                    else:
                        score = 0.99
                except:
                    score = 0.0

                if action.upper() == "ALLOWED":
                    status, risk, model = "Normal", "Low", "Passed"
                    log_msg = f"[{current_time}] ✅ Traffic Allowed. (MAE: {score:.4f})"
                else:
                    status = "Blocked"
                    if "XGBoost" in caught_by:
                        risk, model = "High", "XGBoost"
                        log_msg = f"[{current_time}] 🚨 BLOCKED: {threat_type} caught by {model}!"
                    else:
                        risk, model = "Critical", "Autoencoder"
                        log_msg = f"[{current_time}] 💀 ZERO-DAY ALERT: Blocked by {model}! (MAE: {score:.4f})"

                new_packet = {"Time": current_time, "Score": score, "Status": status, "Risk": risk, "Model": model}
            else:
                new_packet = {"Time": current_time, "Score": 0, "Status": "Error", "Risk": "Unknown", "Model": "API Error"}
                log_msg = f"[{current_time}] ❌ API Error: {response.status_code}"

        except requests.exceptions.ConnectionError:
            new_packet = {"Time": current_time, "Score": 0, "Status": "Error", "Risk": "Unknown", "Model": "Offline"}
            log_msg = f"[{current_time}] ⚠️ Connection Lost! Is FastAPI running?"
            st.session_state.monitoring = False

        # Update Memory
        st.session_state.traffic_history = pd.concat(
            [pd.DataFrame([new_packet]), st.session_state.traffic_history],
            ignore_index=True
        )
        st.session_state.logs.insert(0, log_msg)
        st.session_state.logs = st.session_state.logs[:20]

        # Render UI
        render_ui(status_placeholder, charts_placeholder, tables_placeholder,
                  st.session_state.traffic_history, current_row, total_rows)

        current_row += 1
        time.sleep(1.0)

    # --- LISTENING MODE: Wait for attack injection ---
    while st.session_state.monitoring:
        try:
            refreshed_df = pd.read_csv("live_flows.csv")
            if len(refreshed_df) > len(live_df):
                new_count = len(refreshed_df) - len(live_df)
                live_df, final_df, col_map = load_and_map_csv()
                new_total = len(final_df)
                st.sidebar.warning(f"⚡ {new_count} new packets detected!")

                # Process the new rows
                for i in range(total_rows, new_total):
                    if not st.session_state.monitoring:
                        break
                    current_time = datetime.now().strftime("%H:%M:%S")
                    packet_features = final_df.iloc[i].astype(float).tolist()
                    payload = {"features": packet_features}

                    try:
                        response = requests.post("http://127.0.0.1:8000/scan-traffic", json=payload, timeout=2)
                        if response.status_code == 200:
                            result = response.json()
                            action = result['action']
                            details = result['details']
                            caught_by = result['caught_by']
                            threat_type = result['threat_type']
                            try:
                                if "Error:" in details:
                                    score = float(details.split("Error: ")[1])
                                elif "error (" in details:
                                    score = float(details.split("error (")[1].split(")")[0])
                                else:
                                    score = 0.99
                            except:
                                score = 0.0

                            if action.upper() == "ALLOWED":
                                status, risk, model = "Normal", "Low", "Passed"
                                log_msg = f"[{current_time}] ✅ Traffic Allowed. (MAE: {score:.4f})"
                            else:
                                status = "Blocked"
                                if "XGBoost" in caught_by:
                                    risk, model = "High", "XGBoost"
                                    log_msg = f"[{current_time}] 🚨 BLOCKED: {threat_type} caught by {model}!"
                                else:
                                    risk, model = "Critical", "Autoencoder"
                                    log_msg = f"[{current_time}] 💀 ZERO-DAY ALERT: Blocked by {model}! (MAE: {score:.4f})"

                            new_packet = {"Time": current_time, "Score": score, "Status": status, "Risk": risk, "Model": model}
                        else:
                            new_packet = {"Time": current_time, "Score": 0, "Status": "Error", "Risk": "Unknown", "Model": "API Error"}
                            log_msg = f"[{current_time}] ❌ API Error: {response.status_code}"
                    except:
                        new_packet = {"Time": current_time, "Score": 0, "Status": "Error", "Risk": "Unknown", "Model": "Offline"}
                        log_msg = f"[{current_time}] ⚠️ Connection Lost!"

                    st.session_state.traffic_history = pd.concat(
                        [pd.DataFrame([new_packet]), st.session_state.traffic_history],
                        ignore_index=True
                    )
                    st.session_state.logs.insert(0, log_msg)
                    st.session_state.logs = st.session_state.logs[:20]

                    render_ui(status_placeholder, charts_placeholder, tables_placeholder,
                              st.session_state.traffic_history, i, new_total)
                    time.sleep(1.0)

                total_rows = new_total
                live_df = refreshed_df
            else:
                # Show listening status
                render_ui(status_placeholder, charts_placeholder, tables_placeholder,
                          st.session_state.traffic_history, 0, 0, mode="LISTENING")
        except:
            pass
        time.sleep(1.0)

if not st.session_state.monitoring:
    st.info("System is currently in Standby Mode. Click 'Start Monitoring' in the sidebar to begin live packet ingestion.")