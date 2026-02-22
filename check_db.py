import sqlite3
import os

DB_NAME = "network_logs.db"

def verify_data():
    if not os.path.exists(DB_NAME):
        print(f"Error: {DB_NAME} not found in this folder!")
        return

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # 1. Count Total Logs
        cursor.execute("SELECT COUNT(*) FROM logs")
        total = cursor.fetchone()[0]

        # 2. Count Anomalies
        cursor.execute("SELECT COUNT(*) FROM logs WHERE status LIKE '%Anomaly%'")
        anomalies = cursor.fetchone()[0]

        # 3. Get Last 10 Entries
        cursor.execute("SELECT * FROM logs ORDER BY rowid DESC LIMIT 10")
        rows = cursor.fetchall()

        print("-" * 50)
        print(f"DATABASE VERIFICATION: {DB_NAME}")
        print("-" * 50)
        print(f"Total packets logged: {total}")
        print(f"Anomalies detected:    {anomalies}")
        print("-" * 50)
        print("LAST 10 LOG ENTRIES:")
        for row in rows:
            print(f"Time: {row[0]} | IP: {row[1]} | Status: {row[3]}")
        print("-" * 50)

        conn.close()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    verify_data()