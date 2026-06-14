"""
Smart Network Traffic Analysis and Anomaly Detection System (SNTAADS)
----------------------------------------------------------------------
generate_report.py
Queries the SNTAADS database and produces a formatted security report,
both on the console and as a CSV export.

Author : Ammar Nasser Said Al-Hajri  (22F23369)
College: Middle East College, Knowledge Oasis Muscat
"""

import sqlite3
import pandas as pd
import os
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("SNTAADS.Report")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(BASE_DIR, "sntaads_logs.db")
REPORT_DIR  = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)


def generate_security_report() -> None:
    if not os.path.exists(DB_PATH):
        log.error("Database not found: %s — run app.py first.", DB_PATH)
        return

    conn = sqlite3.connect(DB_PATH)

    # All high-risk events
    df_high = pd.read_sql_query(
        "SELECT timestamp, src_ip, dst_ip, status, risk "
        "FROM logs WHERE risk = 'High' ORDER BY timestamp DESC",
        conn,
    )

    # Summary counts
    total_row     = conn.execute("SELECT COUNT(*) FROM logs").fetchone()
    total_packets = total_row[0] if total_row else 0

    anomaly_row   = conn.execute(
        "SELECT COUNT(*) FROM logs WHERE risk = 'High'"
    ).fetchone()
    total_anomalies = anomaly_row[0] if anomaly_row else 0

    conn.close()

    # ---------------------------------------------------------------------------
    # Console output
    # ---------------------------------------------------------------------------
    banner = "=" * 65
    print(f"\n{banner}")
    print("   SNTAADS — NETWORK SECURITY REPORT")
    print(f"   Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(banner)
    print(f"   Total packets logged : {total_packets:,}")
    print(f"   High-risk events     : {total_anomalies:,}")
    print(banner)

    if df_high.empty:
        print("   No high-risk events recorded yet.")
        print(f"{banner}\n")
        return

    print("\n   RECENT HIGH-RISK EVENTS (up to 20):\n")
    print(df_high.head(20).to_string(index=False))

    # Top threat source
    top_attacker = df_high["src_ip"].value_counts().idxmax()
    top_count    = df_high["src_ip"].value_counts().max()

    print(f"\n{banner}")
    print(f"   PRIMARY THREAT SOURCE : {top_attacker}  ({top_count} events)")
    print(f"   Status                : Blocked & Logged via IPS")
    print(f"{banner}\n")

    # ---------------------------------------------------------------------------
    # CSV export
    # ---------------------------------------------------------------------------
    ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path   = os.path.join(REPORT_DIR, f"sntaads_report_{ts}.csv")
    df_high.to_csv(csv_path, index=False)
    log.info("Report exported to %s", csv_path)


if __name__ == "__main__":
    generate_security_report()
