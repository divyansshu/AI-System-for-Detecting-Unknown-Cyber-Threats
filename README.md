<div align="center">

# 🛡️ AI-Based Zero-Day Cyber Attack Predictor

### Enterprise Event-Driven AI System for Detecting Unknown Cyber Threats

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Apache Kafka](https://img.shields.io/badge/Apache_Kafka-231F20?style=for-the-badge&logo=apachekafka&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![TensorFlow](https://img.shields.io/badge/TensorFlow-FF6F00?style=for-the-badge&logo=tensorflow&logoColor=white)
![XGBoost](https://img.shields.io/badge/XGBoost-189FDD?style=for-the-badge&logo=xgboost&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2CA5E0?style=for-the-badge&logo=docker&logoColor=white)

A decoupled, event-driven intrusion detection system that combines a supervised XGBoost classifier with an unsupervised deep-learning Autoencoder to detect both known attack patterns and novel zero-day anomalies in real-time network traffic.

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [Usage](#-usage) · [Project Structure](#-project-structure)

</div>

---

## ✨ Features

- **Event-driven ingestion** using Apache Kafka in KRaft mode.
- **Two-stage ML pipeline** with XGBoost for known attacks and a Keras Autoencoder for zero-day anomalies.
- **Persistent threat logging** to PostgreSQL through SQLAlchemy.
- **Live SOC dashboard** with total flows, normal flows, alert counts, Stage-2 anomaly scores, event tables, and terminal-style alert output.
- **Alias-aware feature mapping** from `cicflowmeter` CSV columns into the exact 44-feature model order.
- **Fast demo replay controls** for limiting or sampling rows from `live_flows.csv`.
- **Manual API fallback** through FastAPI `/scan-traffic`.

---

## 🏗 Architecture

```text
data/live_demo.pcapng
        │
        ▼
capture/extract_features.py
        │
        ▼
data/live_flows.csv
        │
        ▼
kafka-scripts/produce_normal_traffic.py
        │  44-feature JSON payloads
        ▼
Apache Kafka topic: network-traffic
        │
        ▼
backend/app/main.py
        │  XGBoost -> Autoencoder
        ▼
PostgreSQL table: threat_alerts
        │
        ▼
frontend/dashboard.py
```

### Detection Flow

| Stage | Model | Purpose | Output |
|-------|-------|---------|--------|
| Stage 1 | XGBoost classifier | Detect known malicious mathematical signatures | `BLOCKED`, `Stage 1 (XGBoost)` |
| Stage 2 | Keras Autoencoder | Detect anomalous reconstruction error after Stage 1 passes a flow | `BLOCKED`, `Stage 2 (Autoencoder)` |
| Normal | XGBoost + Autoencoder | Flow passes both checks | `ALLOWED`, `Passed Both Stages` |

All incoming arrays must contain exactly 44 float features. The backend validates this for API requests and Kafka messages. The scaler is loaded from `models/robust_scaler.pkl`, and the Autoencoder threshold is loaded from `models/ae_threshold.json`.

---

## 🚀 Quick Start

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Docker Desktop
- PostgreSQL with a database named `soc_db`

The default `.env` values are:

```env
DB_URL=postgresql://postgres:postgres@localhost:5432/soc_db
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_TOPIC=network-traffic
```

### 1. Install Dependencies

```bash
uv sync
```

The project pins `scikit-learn==1.6.1` because the saved scaler artifact was trained with that version.

### 2. Start Kafka

```bash
docker compose up -d
```

Kafka is exposed on:

```text
localhost:9092
```

Kafka UI is available at:

```text
http://localhost:8080
```

Create the required Kafka topic:

```bash
uv run python kafka-scripts/create_topics.py
```

### 3. Start PostgreSQL

Create the database if it does not already exist:

```sql
CREATE DATABASE soc_db;
```

The backend creates the `threat_alerts` table automatically on startup.

### 4. Start the Backend

```bash
uv run uvicorn app.main:app --reload --app-dir backend
```

Health check:

```text
http://127.0.0.1:8000
```

Expected response:

```json
{ "message": "Hybrid SOC Pipeline is actively monitoring" }
```

### 5. Start the Dashboard

In a second terminal:

```bash
uv run streamlit run frontend/dashboard.py
```

Dashboard URL:

```text
http://localhost:8501
```

### 6. Replay Normal Traffic

In a third terminal:

```bash
uv run python kafka-scripts/produce_normal_traffic.py
```

By default, the producer streams only the first 200 rows for a faster demo.

Useful replay options:

```bash
uv run python kafka-scripts/produce_normal_traffic.py --limit 50 --delay 0
uv run python kafka-scripts/produce_normal_traffic.py --limit 100 --sample
uv run python kafka-scripts/produce_normal_traffic.py --limit 0
```

Option meanings:

| Option | Meaning |
|--------|---------|
| `--limit 50` | Stream only 50 rows |
| `--limit 0` | Stream every row from `live_flows.csv` |
| `--sample` | Randomly sample rows instead of taking the first N |
| `--delay 0` | Send rows with no artificial pause |

You can also set defaults in `.env`:

```env
NORMAL_TRAFFIC_LIMIT=100
NORMAL_TRAFFIC_DELAY=0.05
```

### 7. Inject Synthetic Zero-Day Traffic

```bash
uv run python kafka-scripts/produce_attack_traffic.py
```

This sends synthetic 44-feature anomaly payloads directly into Kafka. These are intentionally extreme, so Stage 2 anomaly scores can be much higher than normal traffic scores.

---

## 📖 Usage

### Extract Features from PCAP

```bash
uv run python capture/extract_features.py
```

This reads:

```text
data/live_demo.pcapng
```

and writes:

```text
data/live_flows.csv
```

The extractor avoids Scapy's offline BPF filter path so Windows users do not need `tcpdump` just to parse the bundled PCAP.

### Manual API Scan

`POST /scan-traffic`

Request body:

```json
{
  "features": [0.0, 0.0, 0.0, "... exactly 44 float values"]
}
```

Normal response:

```json
{
  "action": "ALLOWED",
  "threat_type": "None",
  "caught_by": "Passed Both Stages",
  "details": "Normal Traffic rhythm verified. Error: 0.0772"
}
```

Classification outcomes:

| Scenario | `action` | `threat_type` | `caught_by` |
|----------|----------|---------------|-------------|
| Known attack | `BLOCKED` | `Known Attack` | `Stage 1 (XGBoost)` |
| Zero-day anomaly | `BLOCKED` | `Potential Zero-day Anomaly` | `Stage 2 (Autoencoder)` |
| Normal traffic | `ALLOWED` | `None` | `Passed Both Stages` |

Interactive API docs:

- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

---

## 📊 Dashboard

The Streamlit dashboard reads from PostgreSQL, not directly from `live_flows.csv`.

It shows:

- **Total Flows**: all rows logged in `threat_alerts`
- **Normal Flows**: rows that passed both stages
- **Total Alerts**: Stage 1 + Stage 2 detections
- **Avg Stage-2 Score**: average Autoencoder MAE for recent Stage 2 anomalies
- **Recent Stage-2 Anomaly Scores** with the Autoencoder threshold line
- **Traffic Distribution** by normal, Stage 1, and Stage 2 categories
- **Recent Events** with an option to include normal traffic

If Stage 2 scores are very high after running `produce_attack_traffic.py`, that is expected. The attack producer deliberately sends out-of-distribution synthetic values to demonstrate Autoencoder blocking.

---

## 📁 Project Structure

```text
zero_day_detector/
│
├── backend/
│   ├── app/
│   │   └── main.py                  # FastAPI app, model loading, Kafka consumer
│   └── db/
│       ├── database.py              # SQLAlchemy PostgreSQL connection
│       └── models.py                # threat_alerts table model
│
├── capture/
│   └── extract_features.py          # PCAP -> live_flows.csv extraction
│
├── data/
│   ├── live_demo.pcapng             # Demo packet capture
│   └── live_flows.csv               # Extracted flow rows
│
├── frontend/
│   └── dashboard.py                 # Streamlit SOC dashboard
│
├── kafka-scripts/
│   ├── create_topics.py             # Creates network-traffic topic
│   ├── produce_normal_traffic.py    # Streams mapped CSV rows into Kafka
│   └── produce_attack_traffic.py    # Sends synthetic zero-day payloads
│
├── models/
│   ├── xgboost_stage1.pkl           # Stage 1 XGBoost model
│   ├── autoencoder_stage2.h5        # Stage 2 Autoencoder model
│   ├── robust_scaler.pkl            # Preprocessing scaler
│   └── ae_threshold.json            # Autoencoder threshold
│
├── notebooks/                       # Training and experimentation notebooks
├── tests/                           # FastAPI contract tests
├── docker-compose.yaml              # Kafka and Kafka UI
├── pyproject.toml                   # Project dependencies
├── uv.lock                          # Locked dependency graph
└── README.md
```

---

## 🧠 Model Notes

The trained model artifacts are stored in `models/`.

Important runtime detail:

- `robust_scaler.pkl` was trained with scikit-learn `1.6.1`.
- The project pins `scikit-learn==1.6.1` to avoid pickle compatibility warnings and possible inference drift.
- The normal traffic producer maps all 44 expected model features from the current `cicflowmeter` CSV output using explicit aliases.

Datasets used during experimentation:

| Dataset | Description |
|---------|-------------|
| UNSW-NB15 | Network intrusion dataset from UNSW Canberra |
| CIC-IDS-2017 | Canadian Institute for Cybersecurity IDS dataset |
| CIC-IOT-2023 | IoT-specific network traffic dataset |

---

## 🧪 Tests

Run:

```bash
uv run pytest
```

Current test coverage validates:

- FastAPI health endpoint
- Missing payload handling
- Invalid feature length handling
- Basic 44-feature inference contract

Expected result:

```text
4 passed
```

---

## 🛠 Troubleshooting

### `scapy.error.Scapy_Exception: tcpdump is not available`

Use the updated extractor:

```bash
uv run python capture/extract_features.py
```

The script avoids Scapy's offline BPF filter, which is what triggers the `tcpdump` requirement on Windows.

### Dashboard Shows Normal Traffic as Alerts

Older database rows may contain `Passed Both stages` with a lowercase `s`. The dashboard handles both old and new labels, but for a clean demo you can clear the table:

```sql
TRUNCATE TABLE threat_alerts RESTART IDENTITY;
```

Then replay traffic.

### Dashboard Shows No Data

Make sure all three pieces are running:

```bash
docker compose up -d
uv run uvicorn app.main:app --reload --app-dir backend
uv run python kafka-scripts/produce_normal_traffic.py --limit 50
```

### Kafka Topic Does Not Exist

```bash
uv run python kafka-scripts/create_topics.py
```

### Backend Cannot Connect to PostgreSQL

Confirm PostgreSQL is running, `soc_db` exists, and `DB_URL` in `.env` matches your local credentials.

