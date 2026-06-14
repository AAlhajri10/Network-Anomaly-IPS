"""
Smart Network Traffic Analysis and Anomaly Detection System (SNTAADS)
----------------------------------------------------------------------
check_db.py
Quick diagnostic utility — verifies the database is populated and
prints a summary of the most recent log entries.

Author : Ammar Nasser Said Al-Hajri  (22F23369)
College: Middle East College, Knowledge Oasis Muscat
"""

import sqlite3
import os
import logging

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("SNTAADS.CheckDB")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "sntaads_logs.db")


def verify_database(db_path: str = DB_PATH, recent_n: int = 10) -> None:
    if not os.path.exists(db_path):
        log.error("Database not found: %s", db_path)
        return

    try:
        conn = sqlite3.connect(db_path)

        total_packets = conn.execute(
            "SELECT COUNT(*) FROM logs"
        ).fetchone()[0]

        total_anomalies = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE risk = 'High'"
        ).fetchone()[0]

        normal_traffic = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE risk = 'Low'"
        ).fetchone()[0]

        recent_rows = conn.execute(
            f"SELECT timestamp, src_ip, dst_ip, status, risk "
            f"FROM logs ORDER BY id DESC LIMIT {recent_n}"
        ).fetchall()

        conn.close()

        sep = "-" * 65
        print(f"\n{sep}")
        print(f"  SNTAADS DATABASE VERIFICATION")
        print(f"  Path : {db_path}")
        print(sep)
        print(f"  Total packets logged : {total_packets:,}")
        print(f"  High-risk events     : {total_anomalies:,}")
        print(f"  Normal traffic       : {normal_traffic:,}")
        print(sep)
        print(f"\n  LAST {recent_n} LOG ENTRIES:\n")

        header = f"  {'Time':<21} {'Src IP':<16} {'Dst IP':<16} {'Status':<26} {'Risk'}"
        print(header)
        print(f"  {'-'*21} {'-'*15} {'-'*15} {'-'*25} {'-'*4}")
        for row in recent_rows:
            ts, src, dst, status, risk = row
            print(f"  {ts:<21} {src:<16} {dst:<16} {status:<26} {risk}")

        print(f"\n{sep}\n")

    except sqlite3.Error as exc:
        log.error("Database error: %s", exc)


if __name__ == "__main__":
    verify_database()
