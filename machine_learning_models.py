from sklearn.ensemble import IsolationForest
import numpy as np
from scapy.layers.inet import IP, TCP

def train_network_anomaly_detection_model():
    # Example training data (synthetic): [packet_length, src_port, dst_port]
    X_train = np.array([
        [60, 443, 8080],
        [58, 80, 5000],
        [70, 53, 6000],
        [55, 22, 7000],
        [65, 21, 9000]
    ])
    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(X_train)
    return model

# Model is trained once when the module is imported
model = train_network_anomaly_detection_model()

def detect_anomalies(packet):
    if IP in packet and TCP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        pkt_len = len(packet)
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        features = np.array([[pkt_len, src_port, dst_port]])
        prediction = model.predict(features)

        if prediction[0] == -1:
            return f"[ALERT] Anomaly detected: Possible malicious TCP connection from {src_ip} to {dst_ip}"
    return None

def train_ids_model(snort_alerts, zeek_logs):
    print("Training IDS model... (placeholder)")
    print(f"Snort alerts: {len(snort_alerts)}, Zeek logs: {len(zeek_logs)}")
    return "Trained IDS Model (placeholder)"
