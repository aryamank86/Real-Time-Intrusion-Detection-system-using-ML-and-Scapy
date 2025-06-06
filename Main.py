from scapy.all import sniff, IP, TCP
from sklearn.ensemble import IsolationForest
import random
import winsound
from GUI import update_gui_with_alert, update_gui_with_normal, update_gui_with_response

# Dummy Isolation Forest setup
model = IsolationForest(contamination=0.1)
X_dummy = [[random.random()] for _ in range(100)]
model.fit(X_dummy)

def is_anomalous(ip_pair):
    sample = [[hash(ip_pair) % 1000 / 1000.0]]
    return model.predict(sample)[0] == -1

def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ip_pair = f"{src_ip} to {dst_ip}"

        if is_anomalous(ip_pair):
            update_gui_with_alert(f"Possible malicious TCP connection from {ip_pair}")
            update_gui_with_response("Automated response triggered.")
            winsound.Beep(1000, 200)
        else:
            update_gui_with_normal(f"Normal TCP connection from {ip_pair}")

def start_sniffing():
    sniff(filter="tcp", prn=process_packet, store=False)
