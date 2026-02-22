from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import time

# Store data for the model
packet_data = []

def extract_features(packet):
    if IP in packet:
        features = {
            'timestamp': time.time(),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'packet_length': len(packet),
            'protocol': packet[IP].proto,
        }
        
        # Extract TCP specific features for DDoS detection
        if TCP in packet:
            features['tcp_flags'] = int(packet[TCP].flags)
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
        else:
            features['tcp_flags'] = 0
            
        packet_data.append(features)
        print(f"Captured: {features['src_ip']} -> {features['dst_ip']} | Length: {features['packet_length']}")

# Capture 50 packets to test the extractor
print("Starting Feature Extraction Test...")
sniff(prn=extract_features, count=50)

# Convert to DataFrame (The format Scikit-learn needs)
df = pd.DataFrame(packet_data)
df.to_csv("network_features.csv", index=False)
print("\nSuccess: Features saved to network_features.csv")