import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import time
from datetime import datetime
import random
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

# --- 2. Session State Initialization (Memory) ---
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
    
    # Toggle Monitoring State
    if st.button("▶ Start Monitoring" if not st.session_state.monitoring else "⏸ Stop Monitoring", type="primary"):
        st.session_state.monitoring = not st.session_state.monitoring
        
    st.markdown("---")
    st.write("**Target API Engine:**")
    st.code("http://127.0.0.1:8000/scan-traffic")
    
    if st.button("🗑️ Clear Logs"):
        st.session_state.traffic_history = pd.DataFrame(columns=["Time", "Score", "Status", "Risk", "Model"])
        st.session_state.logs = []

# --- 4. Main Dashboard Layout ---
st.title("🛡️ Live SOC Threat Monitor")

# Created placeholders that we will continually overwrite
status_placeholder = st.empty()
charts_placeholder = st.empty()
tables_placeholder = st.empty()

# --- 5. The Monitoring Loop (LIVE API INTEGRATION) ---
while st.session_state.monitoring:
    current_time = datetime.now().strftime("%H:%M:%S")
    
    # 1. Generate a realistic 44-feature payload array
    base_features = [0.0] * 44 
    base_features[0] = 443.0 
    base_features[1] = random.uniform(100, 500) 
    
    roll = random.random()
    if roll > 0.15:
        payload = {"features": base_features}
    elif roll > 0.05:
        mutated = base_features.copy()
        mutated[1] = 9999999.0 
        mutated[4] = 85500.0   
        payload = {"features": mutated}
    else:
        mutated = base_features.copy()
        mutated[10] = 50000.0  
        mutated[12] = 0.0001   
        payload = {"features": mutated}

    # 2. FIRE THE PACKET AT THE FASTAPI ENGINE
    try:
        response = requests.post("http://127.0.0.1:8000/scan-traffic", json=payload, timeout=2)
        
        if response.status_code == 200:
            result = response.json()
            
            # 3. Parse the real AI predictions
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
                
            # 4. Map the AI logic to our UI visuals (ADDED .upper() FOR SAFETY)
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
        log_msg = f"[{current_time}] ⚠️ Connection to Engine Lost! Is FastAPI running?"
        st.session_state.monitoring = False 

    # 5. Update Memory
    st.session_state.traffic_history = pd.concat(
        [pd.DataFrame([new_packet]), st.session_state.traffic_history], 
        ignore_index=True
    ).head(50)
    
    st.session_state.logs.insert(0, log_msg)
    st.session_state.logs = st.session_state.logs[:20]
    
    df = st.session_state.traffic_history
    
    # --- 6. THE MISSING UI RENDERING BLOCKS ---
    
    # Update Status Panel
    with status_placeholder.container():
        c1, c2, c3, c4 = st.columns(4)
        total_reqs = len(df)
        alerts = len(df[df['Status'] == 'Blocked'])
        avg_score = df['Score'].mean() if not df.empty else 0.0
        
        c1.markdown(f"<div class='metric-box'><h3>🟢 RUNNING</h3><p>System Status</p></div>", unsafe_allow_html=True)
        c2.markdown(f"<div class='metric-box'><h3>{total_reqs}</h3><p>Requests Processed</p></div>", unsafe_allow_html=True)
        c3.markdown(f"<div class='metric-box'><h3 class='{'alert-text' if alerts > 0 else ''}'>{alerts}</h3><p>Alerts Triggered</p></div>", unsafe_allow_html=True)
        c4.markdown(f"<div class='metric-box'><h3>{avg_score:.3f}</h3><p>Avg Anomaly Score</p></div>", unsafe_allow_html=True)

    # Update Charts
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

    # Update Tables & Logs
    with tables_placeholder.container():
        st.markdown("<br>", unsafe_allow_html=True)
        col_table, col_logs = st.columns([2, 1.5])
        
        with col_table:
            st.subheader("📡 Live Traffic Monitor")
            def color_risk(val):
                color = '#ff4b4b' if val in ['High', 'Critical'] else '#00fa9a'
                return f'color: {color}'
            
            display_df = df.head(8).reset_index(drop=True)
            st.dataframe(display_df.style.map(color_risk, subset=['Risk']), use_container_width=True, hide_index=True)
            
        with col_logs:
            st.subheader("📜 Event History")
            log_html = "<br>".join(st.session_state.logs)
            st.markdown(f"<div class='log-terminal'>{log_html}</div>", unsafe_allow_html=True)

    # Wait before next packet
    time.sleep(1.2)

# Standby message
if not st.session_state.monitoring:
    st.info("System is currently in Standby Mode. Click 'Start Monitoring' in the sidebar to begin live packet ingestion.")