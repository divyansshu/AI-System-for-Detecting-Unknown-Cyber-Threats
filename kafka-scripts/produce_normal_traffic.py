from confluent_kafka import Producer
import argparse
import json
import time
import pandas as pd
import numpy as np
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CSV_PATH = PROJECT_ROOT / "data" / "live_flows.csv"

TOPIC = os.getenv("KAFKA_TOPIC", "network-traffic")
KAFKA_SERVER = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
DEFAULT_LIMIT = int(os.getenv("NORMAL_TRAFFIC_LIMIT", "200"))
DEFAULT_DELAY = float(os.getenv("NORMAL_TRAFFIC_DELAY", "0.05"))

config = {
    'bootstrap.servers': KAFKA_SERVER
}

producer = Producer(config)


def delivery_callback(err, msg):
    if err:
        print(f'[ERROR] delivery failed - {err}')
    else:
        print(
            f'[OK] topic={msg.topic()} '
            f'offset={msg.offset()} '
            f'partition={msg.partition()} '
        )

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

FEATURE_ALIASES = {
    "Destination Port": ["Destination Port", "dst_port"],
    "Flow Duration": ["Flow Duration", "flow_duration"],
    "Total Fwd Packets": ["Total Fwd Packets", "tot_fwd_pkts", "subflow_fwd_pkts"],
    "Total Length of Fwd Packets": ["Total Length of Fwd Packets", "totlen_fwd_pkts", "subflow_fwd_byts"],
    "Fwd Packet Length Max": ["Fwd Packet Length Max", "fwd_pkt_len_max"],
    "Fwd Packet Length Min": ["Fwd Packet Length Min", "fwd_pkt_len_min"],
    "Fwd Packet Length Mean": ["Fwd Packet Length Mean", "fwd_pkt_len_mean"],
    "Bwd Packet Length Max": ["Bwd Packet Length Max", "bwd_pkt_len_max"],
    "Bwd Packet Length Min": ["Bwd Packet Length Min", "bwd_pkt_len_min"],
    "Flow Bytes/s": ["Flow Bytes/s", "flow_byts_s"],
    "Flow Packets/s": ["Flow Packets/s", "flow_pkts_s"],
    "Flow IAT Mean": ["Flow IAT Mean", "flow_iat_mean"],
    "Flow IAT Std": ["Flow IAT Std", "flow_iat_std"],
    "Flow IAT Max": ["Flow IAT Max", "flow_iat_max"],
    "Flow IAT Min": ["Flow IAT Min", "flow_iat_min"],
    "Fwd IAT Mean": ["Fwd IAT Mean", "fwd_iat_mean"],
    "Fwd IAT Std": ["Fwd IAT Std", "fwd_iat_std"],
    "Fwd IAT Min": ["Fwd IAT Min", "fwd_iat_min"],
    "Bwd IAT Total": ["Bwd IAT Total", "bwd_iat_tot"],
    "Bwd IAT Mean": ["Bwd IAT Mean", "bwd_iat_mean"],
    "Bwd IAT Std": ["Bwd IAT Std", "bwd_iat_std"],
    "Bwd IAT Max": ["Bwd IAT Max", "bwd_iat_max"],
    "Bwd IAT Min": ["Bwd IAT Min", "bwd_iat_min"],
    "Fwd PSH Flags": ["Fwd PSH Flags", "fwd_psh_flags"],
    "Fwd URG Flags": ["Fwd URG Flags", "fwd_urg_flags"],
    "Fwd Header Length": ["Fwd Header Length", "fwd_header_len"],
    "Bwd Packets/s": ["Bwd Packets/s", "bwd_pkts_s"],
    "Min Packet Length": ["Min Packet Length", "pkt_len_min"],
    "Packet Length Mean": ["Packet Length Mean", "pkt_len_mean"],
    "Packet Length Variance": ["Packet Length Variance", "pkt_len_var"],
    "FIN Flag Count": ["FIN Flag Count", "fin_flag_cnt"],
    "RST Flag Count": ["RST Flag Count", "rst_flag_cnt"],
    "PSH Flag Count": ["PSH Flag Count", "psh_flag_cnt"],
    "ACK Flag Count": ["ACK Flag Count", "ack_flag_cnt"],
    "URG Flag Count": ["URG Flag Count", "urg_flag_cnt"],
    "Down/Up Ratio": ["Down/Up Ratio", "down_up_ratio"],
    "Init_Win_bytes_forward": ["Init_Win_bytes_forward", "init_fwd_win_byts"],
    "Init_Win_bytes_backward": ["Init_Win_bytes_backward", "init_bwd_win_byts"],
    "act_data_pkt_fwd": ["act_data_pkt_fwd", "fwd_act_data_pkts"],
    "Active Mean": ["Active Mean", "active_mean"],
    "Active Std": ["Active Std", "active_std"],
    "Active Max": ["Active Max", "active_max"],
    "Active Min": ["Active Min", "active_min"],
    "Idle Std": ["Idle Std", "idle_std"],
}

def normalize(name):
    return str(name).lower().replace(" ", "").replace('_', '').replace('/', '')

def build_column_map(columns):
    normalized_columns = {normalize(col): col for col in columns}
    col_maps = {}
    missing = []

    for target in TARGET_FEATURES:
        aliases = FEATURE_ALIASES.get(target, [target])
        source = next((normalized_columns.get(normalize(alias)) for alias in aliases if normalize(alias) in normalized_columns), None)
        if source:
            col_maps[target] = source
        else:
            missing.append(target)

    return col_maps, missing

def parse_args():
    parser = argparse.ArgumentParser(description="Replay normal flow rows into Kafka.")
    parser.add_argument(
        "--csv",
        default=str(DEFAULT_CSV_PATH),
        help="Path to live_flows.csv.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="Maximum rows to send. Use 0 to send all rows.",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Randomly sample rows instead of taking the first N rows.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Delay between messages in seconds.",
    )
    return parser.parse_args()

def select_rows(df, limit, sample):
    if limit <= 0 or limit >= len(df):
        return df.reset_index(drop=True)
    if sample:
        return df.sample(n=limit, random_state=42).reset_index(drop=True)
    return df.head(limit).reset_index(drop=True)

def stream_traffic(csv_path=DEFAULT_CSV_PATH, limit=DEFAULT_LIMIT, sample=False, delay=DEFAULT_DELAY):
    print(f'loading {csv_path} and mapping columns...')
    df = pd.read_csv(csv_path)
    df = select_rows(df, limit, sample)
    print(f'streaming {len(df)} row(s) to topic={TOPIC} broker={KAFKA_SERVER}')

    # Map cicflowmeter CSV columns to the exact 44-feature order used by the trained scaler/model.
    col_maps, missing = build_column_map(df.columns)
    print(f'mapped {len(col_maps)}/{len(TARGET_FEATURES)} model features from CSV columns')
    if missing:
        print('[WARN] missing model features filled with 0.0:')
        for target in missing:
            print(f'  - {target}')

    mapped_data = []
    for target in TARGET_FEATURES:
        if target in col_maps:
            mapped_data.append(df[col_maps[target]])
        else:
            mapped_data.append(pd.Series([0.0] * len(df)))

    final_df = pd.concat(mapped_data, axis=1)
    final_df.columns = TARGET_FEATURES
    final_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    final_df.fillna(0, inplace=True)

    for index in range(len(final_df)):

        ip_address = str(df.iloc[index].get('src_ip', f'unknown_{index}'))
        key = ip_address.encode('utf-8')

        features_list = final_df.iloc[index].astype(float).tolist()

        # convert the 44 features in json payload
        payload = {'features': features_list}
        value = json.dumps(payload).encode('utf-8')

        # publish the payload to the kafka topic
        producer.produce(TOPIC, key=key, value=value, callback=delivery_callback)
        producer.poll(0)

        print(f'sent flow {index} (IP: {ip_address} to kafka...')
        if delay > 0:
            time.sleep(delay)
    producer.flush()
    print(f'[DONE] all flows sent')

if __name__ == '__main__':
    args = parse_args()
    stream_traffic(args.csv, args.limit, args.sample, args.delay)
