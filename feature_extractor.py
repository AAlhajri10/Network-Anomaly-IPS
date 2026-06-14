"""
Smart Network Traffic Analysis and Anomaly Detection System (SNTAADS)
----------------------------------------------------------------------
feature_extractor.py
Captures live packets and saves extracted features to a CSV file
for use in model training.

Author : Ammar Nasser Said Al-Hajri  (22F23369)
College: Middle East College, Knowledge Oasis Muscat
"""

from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import time
import os
import logging

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("SNTAADS.FeatureExtractor")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OUTPUT_CSV    = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "network_features.csv")
CAPTURE_COUNT = 200     # number of packets to capture per run

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
packet_records: list[dict] = []


def extract_features(packet) -> None:
    """
    Scapy callback: pull the relevant fields from each packet and
    append them to packet_records.
    """
    if IP not in packet:
        return

    record = {
        "timestamp":     time.time(),
        "src_ip":        packet[IP].src,
        "dst_ip":        packet[IP].dst,
        "packet_length": len(packet),
        "protocol":      packet[IP].proto,
        "tcp_flags":     0,
        "src_port":      0,
        "dst_port":      0,
    }

    if TCP in packet:
        record["tcp_flags"] = int(packet[TCP].flags)
        record["src_port"]  = packet[TCP].sport
        record["dst_port"]  = packet[TCP].dport
    elif UDP in packet:
        record["src_port"] = packet[UDP].sport
        record["dst_port"] = packet[UDP].dport

    packet_records.append(record)
    log.info(
        "Captured %s -> %s | len=%d proto=%d",
        record["src_ip"], record["dst_ip"],
        record["packet_length"], record["protocol"],
    )


def run_extraction(count: int = CAPTURE_COUNT) -> None:
    """Capture `count` packets, then export features to CSV."""
    log.info("SNTAADS Feature Extractor — capturing %d packets …", count)
    sniff(prn=extract_features, count=count, store=False)

    if not packet_records:
        log.warning("No IP packets captured. Check your network interface.")
        return

    df = pd.DataFrame(packet_records)

    # Ensure all required columns exist even if no TCP/UDP packets appeared
    for col in ("tcp_flags", "src_port", "dst_port"):
        if col not in df.columns:
            df[col] = 0

    df.to_csv(OUTPUT_CSV, index=False)
    log.info("Features saved to %s  (%d rows)", OUTPUT_CSV, len(df))
    print(f"\nPreview:\n{df.head(10).to_string(index=False)}")


if __name__ == "__main__":
    run_extraction()
