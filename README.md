# AI-Based Zero-Day Cyber Attack Predictor

An unsupervised machine learning system for detecting zero-day cyber attacks in network traffic using anomaly detection techniques.

## Overview

This project uses the **Isolation Forest** algorithm to identify anomalous network traffic patterns that may indicate previously unseen (zero-day) cyber attacks. By training exclusively on benign (normal) traffic, the model learns what "normal" looks like and flags deviations as potential threats — without requiring labeled attack data during training.

### Key Features

- **Unsupervised anomaly detection** — no attack labels required at training time
- **Handles zero-day threats** — detects novel attacks not seen during training
- **Feature engineering pipeline** — automatic removal of high-correlation and zero-variance features
- **Optimized decision threshold** — threshold tuned via Precision-Recall curve analysis to maximize F1 score
- **Robust scaling** — uses `RobustScaler` to handle outliers in network traffic data
- **Serializable model** — trained model and scaler exported with `joblib` for inference reuse

---

## Dataset

**CICIOT2023 (CIC IoT Dataset 2023)**

| Property | Value |
|---|---|
| Source | Canadian Institute for Cybersecurity |
| Records | 5,491,971 network traffic flows |
| Features | 47 network-level features |
| Attack types | 15+ (DDoS variants, Mirai worms, DoS, port scans, etc.) |
| Access | Google Drive (Google Colab environment) |

**Attack classes present in the dataset:**

- `DDoS-ICMP_Flood`, `DDoS-UDP_Flood`, `DDoS-TCP_Flood`, `DDoS-HTTP_Flood`
- `Mirai-greeth_flood`, `Mirai-greip_flood`, `Mirai-udpplain`
- `DoS-UDP_Flood`, `DoS-TCP_Flood`, `DoS-HTTP_Flood`, `DoS-SYN_Flood`
- `DDoS-RSTFIN_Flood`, `DDoS-SYN_Flood`, `DDoS-SlowLoris`
- `BenignTraffic` (normal)

---

## Tech Stack

| Component | Library / Tool |
|---|---|
| Language | Python 3 |
| Environment | Jupyter Notebook (Google Colab) |
| Data processing | `pandas`, `numpy` |
| Machine learning | `scikit-learn` |
| Visualization | `matplotlib`, `seaborn` |
| Model export | `joblib` |

---

## Project Structure

```
AI-Based-Zero-Day-Cyber-Attack-Predictor/
├── notebooks/
│   └── cyber_attack_prediction.ipynb   # Main ML pipeline notebook
├── README.md
```

> **Note:** The trained model artifacts (`isolation_model.pkl`, `scaler.pkl`) are generated locally when the notebook is run and are not tracked in the repository.

---

## ML Pipeline

### 1. Data Loading & Exploration
- Load training CSV from CICIOT2023 dataset (5.5M rows × 47 features)
- Inspect column types, null values, and label distribution

### 2. Feature Engineering
- **Correlation filtering** — drop 9 features with pairwise correlation > 0.95:
  `Srate`, `rst_flag_number`, `ack_count`, `LLC`, `Std`, `Number`, `Magnitude`, `Radius`, `Weight`
- **Zero-variance filtering** — drop 6 features with no variance:
  `ece_flag_number`, `cwr_flag_number`, `Telnet`, `SMTP`, `IRC`, `DHCP`
- **Result:** 47 → 38 → **32 features** used for modeling

### 3. Train / Test Split
| Split | Composition | Size |
|---|---|---|
| Training set | 80% of benign-only traffic | ~64,000 samples |
| Test set | 20% benign + 50,000 attack samples | ~75,900 samples |

### 4. Data Scaling
- `RobustScaler` fitted on the benign training set only (prevents data leakage)
- Applied to both training and test sets

### 5. Model Training — Isolation Forest
| Hyperparameter | Value |
|---|---|
| `n_estimators` | 300 |
| `contamination` | `'auto'` |
| `max_samples` | 256 |
| `n_jobs` | -1 (all CPU cores) |
| `random_state` | 42 |

### 6. Threshold Optimization
- Raw anomaly scores computed for all test samples
- Precision-Recall curve evaluated across all candidate thresholds
- **Optimal threshold:** `0.4686` (maximizes F1 score)

### 7. Model Serialization
- `isolation_model.pkl` — trained Isolation Forest model
- `scaler.pkl` — fitted RobustScaler

---

## Results

### Classification Performance on Test Set

| Class | Precision | Recall | F1-Score |
|---|---|---|---|
| Benign (0) | 0.96 | 0.81 | 0.88 |
| Attack (1) | 0.91 | 0.98 | 0.94 |
| **Overall Accuracy** | | | **92%** |

The model achieves **98% recall on attacks** (very few missed detections) while maintaining **96% precision on benign traffic** (low false-positive rate).

---

## Setup & Usage

### Prerequisites

```bash
pip install pandas numpy scikit-learn matplotlib seaborn joblib
```

### Running the Notebook

1. Open `notebooks/cyber_attack_prediction.ipynb` in Jupyter or Google Colab.
2. Mount your Google Drive and update the dataset path:
   ```python
   DATA_PATH = "/content/drive/MyDrive/CICIOT23/train/train.csv"
   ```
3. Run all cells sequentially. The notebook will:
   - Load and preprocess the data
   - Train the Isolation Forest model
   - Evaluate performance and display visualizations
   - Save `isolation_model.pkl` and `scaler.pkl`

### Running Inference on New Data

```python
import joblib, pandas as pd

model  = joblib.load("isolation_model.pkl")
scaler = joblib.load("scaler.pkl")

# new_data: DataFrame with the same 32 features used during training
scaled = scaler.transform(new_data)
scores = model.decision_function(scaled)
# Isolation Forest: lower (more negative) scores = more anomalous
# Flag samples below the optimized threshold as attacks
preds  = (scores < 0.4686).astype(int)   # 1 = attack / anomaly, 0 = benign
```

---

## Current Status

| Area | Status |
|---|---|
| Data loading & EDA | ✅ Complete |
| Feature engineering | ✅ Complete |
| Model training (Isolation Forest) | ✅ Complete |
| Threshold optimization | ✅ Complete |
| Evaluation & visualizations | ✅ Complete |
| Model serialization | ✅ Complete |
| Real-time inference pipeline | ⬜ Not started |
| REST API / deployment | ⬜ Not started |
| Unit tests | ⬜ Not started |
| Multi-algorithm comparison | ⬜ Not started |
| Hyperparameter tuning (grid/random search) | ⬜ Not started |
| Cross-validation | ⬜ Not started |

---

## Roadmap

- [ ] Extract notebook code into reusable Python modules (`data_loader.py`, `train.py`, `predict.py`)
- [ ] Add a `requirements.txt` / `environment.yml`
- [ ] Compare additional algorithms (One-Class SVM, Autoencoder, LOF)
- [ ] Hyperparameter search with cross-validation
- [ ] Build a REST API (FastAPI / Flask) for real-time prediction
- [ ] Containerize with Docker
- [ ] Add unit and integration tests

---

## Contributing

Contributions, issues, and feature requests are welcome. Please open an issue or submit a pull request.

---

## License

This project is open-source. See the repository for licensing details.
