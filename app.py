"""
Smart Network Traffic Analysis and Anomaly Detection System (SNTAADS)
----------------------------------------------------------------------
Main application entry point.
Author : Ammar Nasser Said Al-Hajri  (22F23369)
College: Middle East College, Knowledge Oasis Muscat

Prometheus metrics exposed on http://localhost:8000/metrics
Flask dashboard exposed on     http://localhost:5000
"""

from flask import Flask, render_template, jsonify
import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time
import os
import subprocess
import sqlite3
import logging
from collections import defaultdict

# Prometheus client
from prometheus_client import (
    start_http_server,
    Counter,
    Gauge,
    Histogram,
    Info,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("SNTAADS")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "sntaads_logs.db")
MODEL_PATH = os.path.join(BASE_DIR, "anomaly_detector_model.pkl")

WHITELIST = {
    # Loopback
    "127.0.0.1",
    "::1",
    # Windows Host-Only adapter — never block yourself
    "192.168.56.102",
    # VirtualBox gateways
    "10.0.2.1",
    "10.0.2.2",
    "10.0.2.3",
    # Common LAN gateways
    "192.168.1.1",
    "192.168.0.1",
    "192.168.56.100",  # VirtualBox DHCP server
    # NOTE: Kali (192.168.56.101) is intentionally NOT whitelisted
    #       so ICMP sweeps and SYN scans from Kali get detected
}
BLOCK_DURATION_SEC   = 60
ICMP_SWEEP_THRESHOLD  = 5     # lowered: 5 pings within the window = sweep
ICMP_SWEEP_WINDOW_SEC = 10    # widened: 10-second window to catch slower scans

# ---------------------------------------------------------------------------
# ── Prometheus Metrics ──────────────────────────────────────────────────────
#
#  METRIC                              GRAFANA USE
#  ─────────────────────────────────── ────────────────────────────────────────
#  sntaads_packets_total               Network Throughput  rate(…[1m])
#  sntaads_anomalies_total             Total Anomalies     raw counter / gauge
#  sntaads_ml_anomalies_total          Breakdown by type   pie / bar chart
#  sntaads_syn_flood_total             Breakdown by type
#  sntaads_icmp_sweep_total            Breakdown by type
#  sntaads_blocked_ips_total           IPS panel           raw counter
#  sntaads_active_blocks               IPS panel           current gauge
#  sntaads_threat_ratio                Threat Detection    gauge 0–1
#  sntaads_packet_size_bytes           Packet size dist.   histogram heatmap
#  sntaads_system_info                 System info panel   labels only
# ---------------------------------------------------------------------------

# Counters — strictly increasing, never reset
METRIC_PACKETS      = Counter(
    "sntaads_packets_total",
    "Total packets analysed by SNTAADS",
)
METRIC_ANOMALIES    = Counter(
    "sntaads_anomalies_total",
    "Total anomalies detected across all types",
)
METRIC_ML_ANOM      = Counter(
    "sntaads_ml_anomalies_total",
    "Anomalies flagged by the ML Random Forest model",
)
METRIC_SYN_FLOOD    = Counter(
    "sntaads_syn_flood_total",
    "SYN Flood events detected (TCP flag heuristic)",
)
METRIC_ICMP_SWEEP   = Counter(
    "sntaads_icmp_sweep_total",
    "ICMP sweep / ping-scan events detected",
)
METRIC_BLOCKED      = Counter(
    "sntaads_blocked_ips_total",
    "Cumulative number of IPs blocked by the IPS",
)

# Gauges — can go up and down
METRIC_ACTIVE_BLOCKS = Gauge(
    "sntaads_active_blocks",
    "Number of IPs currently blocked by the Windows Firewall",
)
METRIC_THREAT_RATIO  = Gauge(
    "sntaads_threat_ratio",
    "Ratio of anomalous packets to total packets (0.0 – 1.0)",
)

# Histogram — packet size distribution (useful for heatmap in Grafana)
METRIC_PKT_SIZE = Histogram(
    "sntaads_packet_size_bytes",
    "Distribution of analysed packet sizes in bytes",
    buckets=[64, 128, 256, 512, 1024, 1500, 3000, 9000],
)

# Info — static system metadata shown in Grafana info panels
METRIC_SYSTEM_INFO = Info(
    "sntaads_system",
    "SNTAADS system metadata",
)
METRIC_SYSTEM_INFO.info({
    "version":  "1.0.0",
    "author":   "Ammar Nasser Said Al-Hajri",
    "college":  "Middle East College",
    "student_id": "22F23369",
})

# ---------------------------------------------------------------------------
# Internal running totals (for threat ratio calculation)
# ---------------------------------------------------------------------------
_total_packets   = 0
_total_anomalies = 0
_ratio_lock      = threading.Lock()

# Well-known CDN/cloud prefixes — never block these
# Google: 142.250.x.x, 142.251.x.x, 74.125.x.x, 34.x.x.x
_CDN_PREFIXES = (
    "142.250.", "142.251.", "74.125.", "34.",
    "104.16.", "104.17.", "104.18.", "104.19.",
)

def _is_cdn_or_public(ip: str) -> bool:
    """Return True for well-known CDN/cloud IPs that should never be blocked."""
    return any(ip.startswith(p) for p in _CDN_PREFIXES)

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
_state_lock  = threading.Lock()
BANNED_IPS   = set()
ICMP_TRACKER = defaultdict(list)

app = Flask(__name__)


# ===========================================================================
# DATABASE
# ===========================================================================

def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            src_ip    TEXT    NOT NULL,
            dst_ip    TEXT    NOT NULL,
            status    TEXT    NOT NULL,
            risk      TEXT    NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    log.info("Database initialised at %s", DB_PATH)


def log_to_db(timestamp, src, dst, status, risk) -> None:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO logs (timestamp, src_ip, dst_ip, status, risk) "
            "VALUES (?,?,?,?,?)",
            (timestamp, src, dst, status, risk),
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as exc:
        log.error("DB write failed: %s", exc)


# ===========================================================================
# ML MODEL
# ===========================================================================

def load_model():
    if not os.path.exists(MODEL_PATH):
        log.warning("Model not found at %s — ML detection disabled.", MODEL_PATH)
        return None
    try:
        mdl = joblib.load(MODEL_PATH)
        log.info("Anomaly detection model loaded.")
        return mdl
    except Exception as exc:
        log.error("Model load failed: %s — ML detection disabled.", exc)
        return None


model = load_model()


# ===========================================================================
# IPS
# ===========================================================================

def _unblock_ip(ip_address: str) -> None:
    time.sleep(BLOCK_DURATION_SEC)
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name=SNTAADS_BLOCK_{ip_address}"],
            check=True, capture_output=True,
        )
        with _state_lock:
            BANNED_IPS.discard(ip_address)
            METRIC_ACTIVE_BLOCKS.set(len(BANNED_IPS))
        log.info("IPS: Auto-unblocked %s", ip_address)
    except subprocess.CalledProcessError as exc:
        log.error("IPS unblock failed for %s: %s", ip_address, exc)


def block_ip(ip_address: str) -> None:
    with _state_lock:
        if ip_address in WHITELIST or ip_address in BANNED_IPS:
            return
        if _is_cdn_or_public(ip_address):
            log.debug("Skipping block for CDN/public IP: %s", ip_address)
            return
        BANNED_IPS.add(ip_address)
        METRIC_ACTIVE_BLOCKS.set(len(BANNED_IPS))

    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=SNTAADS_BLOCK_{ip_address}",
             "dir=in", "action=block", f"remoteip={ip_address}"],
            check=True, capture_output=True,
        )
        METRIC_BLOCKED.inc()
        log.warning("IPS: Blocked %s", ip_address)
        threading.Thread(target=_unblock_ip, args=(ip_address,), daemon=True).start()
    except subprocess.CalledProcessError as exc:
        log.error("IPS block failed for %s: %s", ip_address, exc)
        with _state_lock:
            BANNED_IPS.discard(ip_address)
            METRIC_ACTIVE_BLOCKS.set(len(BANNED_IPS))


# ===========================================================================
# PACKET ANALYSIS
# ===========================================================================

def _is_icmp_sweep(src_ip: str) -> bool:
    now = time.time()
    with _state_lock:
        ts = ICMP_TRACKER[src_ip]
        ts[:] = [t for t in ts if now - t < ICMP_SWEEP_WINDOW_SEC]
        ts.append(now)
        return len(ts) >= ICMP_SWEEP_THRESHOLD


def _update_threat_ratio() -> None:
    """Recalculate and push the threat ratio gauge."""
    global _total_packets, _total_anomalies
    with _ratio_lock:
        ratio = (_total_anomalies / _total_packets) if _total_packets > 0 else 0.0
    METRIC_THREAT_RATIO.set(ratio)


def analyze_packet(packet) -> None:
    global _total_packets, _total_anomalies

    if IP not in packet:
        return

    # ── Update counters ──
    METRIC_PACKETS.inc()
    METRIC_PKT_SIZE.observe(len(packet))

    with _ratio_lock:
        _total_packets += 1

    src_ip    = packet[IP].src
    dst_ip    = packet[IP].dst
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    is_anomaly = False
    status     = "Normal Traffic"
    risk       = "Low"

    try:
        # ── ICMP sweep ──
        if ICMP in packet and packet[ICMP].type == 8:
            log.info("ICMP echo-request from %s (tracking for sweep)", src_ip)
            if _is_icmp_sweep(src_ip):
                is_anomaly = True
                status     = "ICMP Sweep Detected"
                risk       = "High"
                METRIC_ICMP_SWEEP.inc()
                log.warning("ICMP SWEEP DETECTED from %s", src_ip)

        # ── TCP / UDP ──
        elif TCP in packet or UDP in packet:
            p_len  = len(packet)
            proto  = packet[IP].proto
            flags  = int(packet[TCP].flags) if TCP in packet else 0
            s_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
            d_port = packet[TCP].dport if TCP in packet else packet[UDP].dport

            # ML prediction
            if model is not None:
                features = pd.DataFrame(
                    [[p_len, proto, flags, s_port, d_port]],
                    columns=["packet_length", "protocol", "tcp_flags",
                             "src_port", "dst_port"],
                )
                if model.predict(features)[0] == 1:
                    is_anomaly = True
                    status     = "ML Anomaly Detected"
                    risk       = "High"
                    METRIC_ML_ANOM.inc()

            # SYN-only fallback (TCP flags == SYN only)
            if not is_anomaly and TCP in packet and flags == 0x002:
                is_anomaly = True
                status     = "SYN Flood Suspected"
                risk       = "High"
                METRIC_SYN_FLOOD.inc()

        # ── Shared anomaly handling ──
        if is_anomaly:
            METRIC_ANOMALIES.inc()
            with _ratio_lock:
                _total_anomalies += 1
            block_ip(src_ip)

        _update_threat_ratio()
        log_to_db(timestamp, src_ip, dst_ip, status, risk)

    except Exception as exc:
        log.error("Packet analysis error (src=%s): %s", src_ip, exc)


def start_sniffing() -> None:
    """
    Auto-discover all non-loopback interfaces and sniff on all of them.
    Covers both the NAT adapter (10.0.2.x) and Host-Only (192.168.56.x)
    without any hardcoded GUIDs.
    """
    from scapy.all import get_if_list

    all_ifaces = get_if_list()
    ifaces     = [i for i in all_ifaces if "Loopback" not in i]

    if not ifaces:
        log.error("No sniffable interfaces found — check Npcap installation.")
        return

    log.info("SNTAADS sniffing on %d interface(s):", len(ifaces))
    for iface in ifaces:
        log.info("  → %s", iface)
    log.info("ICMP sweep threshold : %d pings in %ds",
             ICMP_SWEEP_THRESHOLD, ICMP_SWEEP_WINDOW_SEC)

    def sniff_icmp():
        log.info("ICMP sniffer thread started.")
        try:
            sniff(iface=ifaces, filter="icmp", prn=analyze_packet, store=False)
        except Exception as exc:
            log.error("ICMP sniffer crashed: %s", exc)

    def sniff_tcp_udp():
        log.info("TCP/UDP sniffer thread started.")
        try:
            sniff(iface=ifaces, filter="tcp or udp", prn=analyze_packet, store=False)
        except Exception as exc:
            log.error("TCP/UDP sniffer crashed: %s", exc)

    threading.Thread(target=sniff_icmp,    daemon=True).start()
    threading.Thread(target=sniff_tcp_udp, daemon=True).start()
    log.info("Both sniffer threads launched.")


# ===========================================================================
# FLASK ROUTES
# ===========================================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def get_alerts():
    """Return the 50 most recent log entries."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT timestamp, src_ip, dst_ip, status, risk "
            "FROM logs ORDER BY id DESC LIMIT 50"
        ).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except sqlite3.Error as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/stats")
def get_stats():
    """Return aggregate counts for the dashboard summary cards."""
    try:
        conn = sqlite3.connect(DB_PATH)
        total     = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        anomalies = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE risk = 'High'"
        ).fetchone()[0]
        conn.close()
        return jsonify({
            "total_packets":   total,
            "total_anomalies": anomalies,
        })
    except sqlite3.Error as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/metrics_summary")
def metrics_summary():
    """
    Return a JSON snapshot of all Prometheus counters.
    Useful for custom dashboards that don't use Grafana.
    """
    with _ratio_lock:
        pkts = _total_packets
        anom = _total_anomalies
    with _state_lock:
        active = len(BANNED_IPS)

    return jsonify({
        "packets_total":    pkts,
        "anomalies_total":  anom,
        "threat_ratio":     round(anom / pkts, 4) if pkts > 0 else 0,
        "active_blocks":    active,
    })


# ===========================================================================
# ENTRY POINT
# ===========================================================================

if __name__ == "__main__":
    init_db()
    start_http_server(8000)
    log.info("Prometheus metrics on http://0.0.0.0:8000/metrics")
    start_sniffing()   # launches ICMP + TCP/UDP threads internally
    time.sleep(1)      # give threads time to start and print their log lines
    log.info("SNTAADS dashboard on http://0.0.0.0:5000")
    app.run(debug=False, port=5000, host="0.0.0.0")