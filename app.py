from flask import Flask, render_template, jsonify
import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP  # Added ICMP
import threading
import time
import os
import sqlite3
from prometheus_client import start_http_server, Counter

app = Flask(__name__)

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "network_logs.db")
MODEL_PATH = os.path.join(BASE_DIR, "anomaly_detector_model.pkl")

# --- Technical Refinement: Whitelist ---
# Protects your gateway and loopback from being blocked
WHITELIST = ["127.0.0.1", "10.0.2.1", "10.0.2.2"] 

# --- Prometheus Metrics ---
ANOMALY_COUNT = Counter('total_anomalies_detected_total', 'Total detected anomalies')
PACKET_COUNT = Counter('total_packets_processed_total', 'Total packets analyzed')

# --- Windows IPS Logic with Cooldown ---
BANNED_IPS = set()

def unblock_ip(ip_address):
    time.sleep(60) 
    try:
        cmd = f'netsh advfirewall firewall delete rule name="BLOCK_ATTACKER_{ip_address}"'
        os.system(cmd)
        if ip_address in BANNED_IPS:
            BANNED_IPS.remove(ip_address)
        print(f"[---] IPS RESET: Unblocked IP: {ip_address}")
    except Exception as e:
        print(f"Unblock Error: {e}")

def block_attacker_windows(ip_address):
    # Added Whitelist check to prevent blocking critical infrastructure
    if ip_address not in BANNED_IPS and ip_address not in WHITELIST:
        try:
            cmd = f'netsh advfirewall firewall add rule name="BLOCK_ATTACKER_{ip_address}" dir=in action=block remoteip={ip_address}'
            os.system(cmd)
            BANNED_IPS.add(ip_address)
            print(f"[!!!] WINDOWS ACTIVE RESPONSE: Blocked Attacker IP: {ip_address}")
            threading.Thread(target=unblock_ip, args=(ip_address,), daemon=True).start()
        except Exception as e:
            print(f"Firewall Error: {e}")

# --- Database & ML Setup ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (timestamp TEXT, src_ip TEXT, dst_ip TEXT, status TEXT, risk TEXT)''')
    conn.commit()
    conn.close()

def log_to_db(data):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT INTO logs (timestamp, src_ip, dst_ip, status, risk) VALUES (?,?,?,?,?)", 
                  (data['time'], data['src'], data['dst'], data['status'], data['level']))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Logging Error: {e}")

try:
    model = joblib.load(MODEL_PATH)
except:
    model = None

def analyze_packet(packet):
    if IP in packet:
        PACKET_COUNT.inc()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        is_anomaly = False
        status_msg = "Normal Traffic"
        risk_level = "Low"

        try:
            # --- Refinement: ICMP Detection ---
            if ICMP in packet:
                # Type 8 is an Echo Request (Ping)
                if packet[ICMP].type == 8:
                    is_anomaly = True
                    status_msg = "ICMP Sweep Detected!"
                    risk_level = "High"

            # --- Existing TCP/UDP Logic ---
            elif TCP in packet or UDP in packet:
                p_len = len(packet)
                proto = packet[IP].proto
                flags = int(packet[TCP].flags) if TCP in packet else 0
                s_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
                d_port = packet[TCP].dport if TCP in packet else packet[UDP].dport

                feature_df = pd.DataFrame([[p_len, proto, flags, s_port, d_port]], 
                                         columns=['packet_length', 'protocol', 'tcp_flags', 'src_port', 'dst_port'])
                ml_prediction = model.predict(feature_df)[0] if model else 0

                if ml_prediction == 1 or (TCP in packet and flags == 2):
                    is_anomaly = True
                    status_msg = "Anomaly Detected!"
                    risk_level = "High"

            # Execute Response
            if is_anomaly:
                ANOMALY_COUNT.inc()
                block_attacker_windows(src_ip)
                log_to_db({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "src": src_ip, "dst": dst_ip, "status": status_msg, "level": risk_level})
            else:
                log_to_db({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "src": src_ip, "dst": dst_ip, "status": status_msg, "level": risk_level})
        except:
            pass

def start_sniffing():
    print(f"--- Security Sensor Active: Monitoring {DB_NAME} ---")
    os.system('netsh advfirewall firewall delete rule name=all')
    sniff(prn=analyze_packet, store=0)

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/alerts')
def get_alerts():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT timestamp, src_ip, dst_ip, status, risk FROM logs ORDER BY rowid DESC LIMIT 50")
        rows = c.fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e: return jsonify({"error": str(e)})

if __name__ == '__main__':
    init_db()
    start_http_server(8000)
    threading.Thread(target=start_sniffing, daemon=True).start()
    app.run(debug=False, port=5000, host='0.0.0.0')