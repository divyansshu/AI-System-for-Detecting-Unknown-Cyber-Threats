<![CDATA[<div align="center">

# 🛡️ Next-Gen Hybrid SOC Pipeline

### AI System for Detecting Unknown Cyber Threats

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![TensorFlow](https://img.shields.io/badge/TensorFlow-FF6F00?style=for-the-badge&logo=tensorflow&logoColor=white)
![XGBoost](https://img.shields.io/badge/XGBoost-189FDD?style=for-the-badge&logo=xgboost&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)

A **two-stage intrusion detection system** that combines a supervised XGBoost classifier with an unsupervised deep-learning Autoencoder to detect both **known attack patterns** and **novel zero-day anomalies** in real-time network traffic.

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [Usage](#-usage) · [Project Structure](#-project-structure)

</div>

---

## ✨ Features

- **Two-Stage Detection Pipeline** — XGBoost catches known attacks; an Autoencoder catches what XGBoost misses.
- **Zero-Day Anomaly Detection** — Flags traffic that deviates from learned "normal" patterns, even if never seen before.
- **Real-Time Dashboard** — Streamlit-based SOC command center with live charts, anomaly scores, and event logs.
- **REST API** — FastAPI backend exposes a `/scan-traffic` endpoint for programmatic integration.
- **Attack Simulator** — Built-in script to inject synthetic zero-day traffic for live demonstrations.
- **Feature Extraction** — Converts raw `.pcapng` captures into ML-ready flow features via `cicflowmeter`.

---

## 🏗 Architecture

<div align="center">

![Architecture Diagram](docs/architecture.png)

</div>

The pipeline processes network traffic through two sequential ML stages:

### Stage 1 — XGBoost Supervised Filter

| Aspect        | Detail                                                                 |
|---------------|------------------------------------------------------------------------|
| **Model**     | XGBoost binary classifier (`xgboost_stage1.pkl`)                       |
| **Purpose**   | Detect **known** attack categories learned from labeled training data   |
| **Output**    | `1` → Known attack → **Blocked** · `0` → Passed to Stage 2            |

### Stage 2 — Autoencoder Anomaly Detector

| Aspect        | Detail                                                                 |
|---------------|------------------------------------------------------------------------|
| **Model**     | Keras deep Autoencoder (`autoencoder_stage2.h5`)                       |
| **Purpose**   | Catch **unknown / zero-day** threats that bypassed Stage 1             |
| **Method**    | Measures reconstruction error (MAE) against a dynamic threshold        |
| **Threshold** | `0.1331` (stored in `ae_threshold.json`, tuned on validation data)     |
| **Output**    | MAE > threshold → **Blocked** (zero-day) · MAE ≤ threshold → **Allowed** |

### Decision Summary

```
                         ┌──────────────────────┐
    Network Traffic ───► │  Stage 1: XGBoost    │
                         └──────────┬───────────┘
                                    │
                        ┌───────────┴───────────┐
                        │                       │
                   Known Attack             Benign (0)
                   prediction = 1               │
                        │               ┌───────▼───────────┐
                        │               │ Stage 2: Autoenc.  │
                   🚨 BLOCKED           └───────┬───────────┘
                  (Known Attack)                │
                                    ┌───────────┴───────────┐
                                    │                       │
                              MAE > threshold         MAE ≤ threshold
                                    │                       │
                               💀 BLOCKED              ✅ ALLOWED
                            (Zero-Day Anomaly)      (Normal Traffic)
```

### Data Preprocessing

All features are scaled using a **RobustScaler** (`robust_scaler.pkl`) before being fed into either model, ensuring resilience to outliers in network traffic data.

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.12+**
- **[uv](https://docs.astral.sh/uv/)** (recommended) or `pip`

### 1. Clone the Repository

```bash
git clone https://github.com/divyansshu/AI-System-for-Detecting-Unknown-Cyber-Threats.git
cd AI-System-for-Detecting-Unknown-Cyber-Threats
```

### 2. Install Dependencies

Using **uv** (recommended):

```bash
uv sync
```

Or using **pip**:

```bash
pip install -e .
```

### 3. Extract Features (Optional)

If you have a raw `.pcapng` capture file and need to generate flow features:

```bash
python extract_features.py
```

> This produces `live_flows.csv` from `live_demo.pcapng` using `cicflowmeter`.

### 4. Start the API Server

```bash
cd api
uvicorn app:app --reload
```

The API will be available at `http://127.0.0.1:8000`. Visit the root endpoint to confirm:

```json
{ "message": "Hybrid SOC Pipeline is actively monitoring" }
```

### 5. Launch the Dashboard

In a separate terminal:

```bash
cd dashboard
streamlit run dashboard.py
```

The SOC Command Center will open at `http://localhost:8501`.

---

## 📖 Usage

### Running the Full Demo

1. Start the **FastAPI backend** (Terminal 1):
   ```bash
   cd api && uvicorn app:app --reload
   ```

2. Start the **Streamlit dashboard** (Terminal 2):
   ```bash
   cd dashboard && streamlit run dashboard.py
   ```

3. Click **▶ Start Monitoring** in the dashboard sidebar. The system will:
   - **Replay** existing packets from `live_flows.csv` (one per second)
   - Switch to **Listening Mode** once replay completes, watching for new packets

4. Inject a **simulated zero-day attack** (Terminal 3):
   ```bash
   python unknown_attack.py
   ```
   Watch the dashboard light up with 🚨 alerts as the Autoencoder catches the anomalies!

### API Reference

#### `POST /scan-traffic`

Classify a single network flow.

**Request Body:**

```json
{
  "features": [443.0, 120456.0, 15.0, 8420.0, "... (44 float values)"]
}
```

**Responses:**

| Scenario             | `action`   | `threat_type`              | `caught_by`          |
|----------------------|------------|----------------------------|----------------------|
| Known attack         | `Blocked`  | `Known Attack`             | `Stage 1 (XGBoost)` |
| Zero-day anomaly     | `Blocked`  | `Potential Zero-day Anomaly` | `Stage 2 (Autoencoder)` |
| Normal traffic       | `Allowed`  | `None`                     | `Passed Both stages` |

#### `GET /`

Health check endpoint.

```json
{ "message": "Hybrid SOC Pipeline is actively monitoring" }
```

### Interactive API Docs

FastAPI auto-generates interactive documentation:

- **Swagger UI** — `http://127.0.0.1:8000/docs`
- **ReDoc** — `http://127.0.0.1:8000/redoc`

---

## 📁 Project Structure

```
zero_day_detector/
│
├── api/
│   └── app.py                  # FastAPI backend — loads models, exposes /scan-traffic
│
├── dashboard/
│   ├── dashboard.py            # Streamlit SOC Command Center (real-time UI)
│   ├── live_flows.csv          # Flow data consumed by the dashboard
│   └── UNSW-NB15_1.csv         # Training/reference dataset
│
├── models/
│   ├── xgboost_stage1.pkl      # Stage 1 — trained XGBoost classifier
│   ├── autoencoder_stage2.h5   # Stage 2 — trained Keras Autoencoder
│   ├── robust_scaler.pkl       # RobustScaler for feature preprocessing
│   └── ae_threshold.json       # Dynamic anomaly threshold (0.1331)
│
├── notebooks/
│   ├── cyber_attack_prediction (XGBoost Classifier).ipynb
│   ├── cyber_attack_prediction_CIC-IOT2023.ipynb
│   ├── cyber_attack_prediction_with_CIC-IDS-2017.ipynb
│   └── draft_1/
│       ├── Data_Engineering_and_EDA.ipynb    # Data cleaning & exploration
│       ├── XGBoost_Classifier.ipynb          # Stage 1 model training
│       ├── AutoEncoder.ipynb                 # Stage 2 model training
│       └── Hybrid_Pipeline.ipynb             # Combined pipeline evaluation
│
├── extract_features.py         # PCAP → CSV feature extraction (cicflowmeter)
├── unknown_attack.py           # Zero-day attack simulator for demos
├── main.py                     # Project entry point
├── pyproject.toml              # Project config & dependencies
└── README.md
```

---

## 🧠 Model Training

The models were trained and evaluated in Jupyter notebooks (see `notebooks/`):

### Datasets Used

| Dataset         | Description                                              |
|-----------------|----------------------------------------------------------|
| **UNSW-NB15**   | Network intrusion dataset from UNSW Canberra (primary)   |
| **CIC-IDS-2017**| Canadian Institute for Cybersecurity IDS dataset          |
| **CIC-IOT-2023**| IoT-specific network traffic dataset                     |

### Training Pipeline (in `notebooks/draft_1/`)

1. **Data Engineering & EDA** — Cleaning, feature selection, handling class imbalance
2. **XGBoost Classifier** — Supervised training on labeled attack/benign data
3. **Autoencoder** — Unsupervised training on benign-only traffic to learn "normal" patterns
4. **Hybrid Pipeline** — End-to-end evaluation of the two-stage system

### Feature Set

The system uses **44 network flow features** extracted via CICFlowMeter, including:

- **Packet metrics** — sizes, counts, header lengths
- **Flow statistics** — duration, bytes/s, packets/s
- **Inter-arrival times** — mean, std, min, max (forward & backward)
- **TCP flags** — FIN, RST, PSH, ACK, URG counts
- **Window sizes** — initial forward/backward window bytes
- **Activity patterns** — active/idle time statistics

---

## 🔧 Tech Stack

| Component          | Technology                              |
|--------------------|-----------------------------------------|
| **ML (Stage 1)**   | XGBoost 3.2+                            |
| **ML (Stage 2)**   | TensorFlow / Keras 2.21+               |
| **Preprocessing**  | scikit-learn (RobustScaler)             |
| **API Backend**     | FastAPI + Uvicorn                       |
| **Dashboard**       | Streamlit + Plotly                      |
| **Feature Extraction** | CICFlowMeter                        |
| **Data Processing** | Pandas, NumPy                          |
| **Package Manager** | uv                                     |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).

---

<div align="center">

Built with 🧠 ML + 🛡️ Cybersecurity in mind

</div>
]]>
