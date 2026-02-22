import sqlite3
import pandas as pd
import os

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "network_logs.db")

def generate_security_report():
    if not os.path.exists(DB_NAME):
        print(f"Error: Database {DB_NAME} not found.")
        return

    # Connect to the database
    conn = sqlite3.connect(DB_NAME)
    
    # Query all detected anomalies
    query = "SELECT timestamp, src_ip, dst_ip, status, risk FROM logs WHERE risk = 'High' ORDER BY timestamp DESC"
    df = pd.read_sql_query(query, conn)
    
    conn.close()

    if df.empty:
        print("No anomalies found in the database yet.")
        return

    print("\n" + "="*60)
    print("      NETWORK ANOMALY DETECTION SYSTEM: SECURITY REPORT")
    print("="*60)
    print(f"Total Anomalies Caught: {len(df)}")
    print("-"*60)
    
    # Display the most recent detections
    print(df.head(20).to_string(index=False))
    
    # Identify the top 'Attacker' IP
    top_attacker = df['src_ip'].value_counts().idxmax()
    print("\n" + "="*60)
    print(f"PRIMARY THREAT SOURCE: {top_attacker}")
    print(f"Status: Blocked & Logged via IPS Lifecycle")
    print("="*60 + "\n")

    # Export to CSV for your project report documentation
    df.to_csv("security_report.csv", index=False)
    print("Report exported successfully to 'security_report.csv'")

if __name__ == "__main__":
    generate_security_report()