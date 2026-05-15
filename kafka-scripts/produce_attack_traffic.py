import random
import time
import json
import os
from dotenv import load_dotenv
from confluent_kafka import Producer

load_dotenv()
TOPIC = os.getenv('KAFKA_TOPIC')
KAFKA_SERVER = os.getenv('KAFKA_BOOTSTRAP_SERVERS')

producer = Producer({
    'bootstrap.servers': KAFKA_SERVER
})

def delivery_callback(error, msg):
    if error:
        print(f'[ERROR] Attack payload failed to deliver: {error}')
    else:
        print(f'ZERO-DAY INJECTED: partition={msg.partition()} offset={msg.offset()}')


def generate_zero_day_payload():
    """
        Generates an array of 44 features that represents a Zero-Day attack.
        Because this is synthetic, random noise, XGBoost (Stage 1) will NOT
        recognize it as a known signature and will pass it.
        The Autoencoder (Stage 2) will see the extreme mathematical variance
        and immediately block it.
        """
    features = []
    for i in range(44):
        # Inject extreme, out-of-bounds values to trigger the anomaly detector
        if i in [1, 2, 3]:  # Simulating massive Flow Duration and Packet Lengths
            features.append(random.uniform(500000.0, 999999.0))
        else:
            # Random statistical noise for the remaining features
            features.append(random.uniform(-50.0, 50.0))
    return features


def simulate_attack():
    print('Starting Zero-Day Attack Simulator')
    print(f'Targeting Kafka Broker: {KAFKA_SERVER}')
    print(f'Targeting TOPIC: {TOPIC}\n')

    # Fire 10 rapid zero-day packets into the network
    for i in range(1, 11):
        # Generate a fake rogue IP address
        rogue_ip = f"10.66.66.{random.randint(1, 255)}"
        key = rogue_ip.encode('utf-8')

        # Generate the 44-feature mathematical anomaly
        malicious_features = generate_zero_day_payload()
        payload = {'features': malicious_features}
        value = json.dumps(payload).encode('utf-8')

        producer.produce(
            TOPIC,
            key=key,
            value=value,
            callback=delivery_callback
        )
        producer.poll(0)

        print(f'Firing payload {i}/10 from {rogue_ip}..')
        time.sleep(0.3)

    producer.flush()
    print('Attack Sequence completed..')

if __name__ == "__main__":
    simulate_attack()


