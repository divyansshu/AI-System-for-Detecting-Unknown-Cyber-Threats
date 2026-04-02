import pandas as pd
import numpy as np
import socket
import random
import time
import os

"""
Zero-Day Attack Simulator
Injects anomalous traffic patterns into live_flows.csv so the
dashboard + FastAPI pipeline can detect them in real-time.
"""

def find_csv():
    """Locate the live_flows.csv the dashboard is actually reading."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "dashboard", "live_flows.csv"),
        os.path.join(script_dir, "live_flows.csv"),
    ]
    for path in candidates:
        if os.path.exists(path) and os.path.getsize(path) > 0:
            return path
    return None


def generate_attack_row(columns, stats):
    """
    Create a single anomalous feature row.
    Values are deliberately pushed FAR outside normal ranges
    so the Autoencoder's reconstruction error will be very high.
    """
    row = {}
    for col in columns:
        norm = col.lower().replace(" ", "").replace("_", "")

        # Non-numeric metadata columns
        if col in ("src_ip", "dst_ip"):
            row[col] = "192.168.1.666"
            continue
        if col == "protocol":
            row[col] = 17  # UDP
            continue
        if col == "timestamp":
            row[col] = time.time()
            continue

        # --- Craft anomalous numeric values ---
        max_val = stats["max"].get(col, 1000)
        mean_val = stats["mean"].get(col, 100)

        if "port" in norm:
            # Suspicious ports commonly associated with backdoors
            row[col] = random.choice([31337, 4444, 6666, 9999, 1337, 5555])
        elif "duration" in norm:
            # Ultra-short burst (microsecond-level flood)
            row[col] = random.uniform(1, 50)
        elif "byts_s" in norm or "bytess" in norm:
            # Extreme bandwidth (10-50x normal max)
            row[col] = abs(max_val) * random.uniform(10, 50) if max_val else random.uniform(1e7, 1e9)
        elif "pkts_s" in norm or "pktss" in norm:
            # Extreme packet rate
            row[col] = abs(max_val) * random.uniform(10, 30) if max_val else random.uniform(1e5, 1e7)
        elif "tot" in norm and "pkt" in norm:
            # Very high packet counts
            row[col] = random.uniform(5000, 50000)
        elif "len" in norm and ("max" in norm or "mean" in norm):
            # Extreme packet sizes
            row[col] = random.uniform(10000, 65535)
        elif "len" in norm and "min" in norm:
            row[col] = random.uniform(800, 1500)
        elif "iat" in norm:
            # Near-zero inter-arrival times (flood behavior)
            row[col] = random.uniform(0, 5)
        elif "flag" in norm:
            # Unusual flag combinations
            row[col] = random.choice([0, 1, 1, 1])
        elif "win" in norm and "init" in norm:
            # Abnormal window sizes
            row[col] = random.choice([0, 1, 65535, 99999])
        elif "active" in norm or "idle" in norm:
            row[col] = random.uniform(0, 1)
        else:
            # Everything else: push 5-20x above normal max
            if max_val and abs(max_val) > 0:
                row[col] = abs(max_val) * random.uniform(5, 20)
            else:
                row[col] = random.uniform(1000, 100000)

    return row


def main():
    print("=" * 60)
    print("ZERO-DAY ATTACK SIMULATOR")
    print("  Injecting anomalous traffic into the SOC pipeline")
    print("=" * 60)

    csv_path = find_csv()
    if not csv_path:
        print("\nCould not find live_flows.csv!")
        print("   Make sure you've run extract_features.py first")
        print("   and the CSV is in the dashboard/ folder.")
        return

    print(f"\nTarget CSV : {csv_path}")

    # Read existing data to understand normal ranges
    existing_df = pd.read_csv(csv_path)
    print(f"Existing rows: {len(existing_df)}")

    numeric_cols = existing_df.select_dtypes(include=[np.number]).columns
    stats = {
        "max": existing_df[numeric_cols].max().to_dict(),
        "mean": existing_df[numeric_cols].mean().to_dict(),
    }
    columns = existing_df.columns.tolist()

    # --- Attack Configuration ---
    NUM_ATTACK_PACKETS = 3
    print(f"\nPreparing {NUM_ATTACK_PACKETS} anomalous packets...\n")

    # Also send real UDP flood for terminal drama
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for i in range(NUM_ATTACK_PACKETS):
        # 1) Generate & inject anomalous CSV row
        attack_row = generate_attack_row(columns, stats)
        df_row = pd.DataFrame([attack_row])
        df_row.to_csv(csv_path, mode="a", header=False, index=False)

        # 2) Also flood localhost with garbage UDP (visual effect)
        for _ in range(500):
            try:
                sock.sendto(random.randbytes(1024), ("127.0.0.1", 8080))
            except Exception:
                pass

        bar = "█" * (i + 1) + "░" * (NUM_ATTACK_PACKETS - i - 1)
        print(f" [{bar}] Packet {i+1}/{NUM_ATTACK_PACKETS} injected")
        time.sleep(1.0)  # Match the dashboard replay speed

    sock.close()
    print(f"\nAttack complete! {NUM_ATTACK_PACKETS} anomalous packets injected.")
    print("   ➡ Watch the dashboard — alerts should appear now!\n")


if __name__ == "__main__":
    main()