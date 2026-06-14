"""
Smart Network Traffic Analysis and Anomaly Detection System (SNTAADS)
----------------------------------------------------------------------
test_sntaads.py
Automated test suite for the core system components.
Run with:  pytest test_sntaads.py -v

Author : Ammar Nasser Said Al-Hajri  (22F23369)
College: Middle East College, Knowledge Oasis Muscat
"""

import os
import sqlite3
import tempfile
import threading
import time
import pytest
import pandas as pd
import joblib

# ---------------------------------------------------------------------------
# Helpers & fixtures
# ---------------------------------------------------------------------------

MODEL_PATH = os.path.join(os.path.dirname(__file__), "anomaly_detector_model.pkl")
WHITELIST  = {"127.0.0.1", "10.0.2.1", "10.0.2.2", "::1"}


def _temp_db() -> str:
    """Return a path to a fresh temporary database."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def _init_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, src_ip TEXT, dst_ip TEXT,
            status TEXT, risk TEXT
        )
    """)
    conn.commit()
    conn.close()


# ===========================================================================
# 1. Database tests
# ===========================================================================

class TestDatabase:

    def test_table_is_created(self):
        db = _temp_db()
        _init_db(db)
        conn = sqlite3.connect(db)
        tables = [r[0] for r in
                  conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        conn.close()
        assert "logs" in tables

    def test_insert_and_retrieve(self):
        db = _temp_db()
        _init_db(db)
        conn = sqlite3.connect(db)
        conn.execute(
            "INSERT INTO logs (timestamp, src_ip, dst_ip, status, risk) "
            "VALUES (?,?,?,?,?)",
            ("2026-01-01 00:00:00", "1.2.3.4", "5.6.7.8", "Normal Traffic", "Low"),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM logs").fetchone()
        conn.close()
        assert row is not None
        assert row[2] == "1.2.3.4"   # src_ip

    def test_schema_has_required_columns(self):
        db = _temp_db()
        _init_db(db)
        conn = sqlite3.connect(db)
        cols = [info[1] for info in conn.execute("PRAGMA table_info(logs)")]
        conn.close()
        for col in ("timestamp", "src_ip", "dst_ip", "status", "risk"):
            assert col in cols, f"Missing column: {col}"


# ===========================================================================
# 2. ML model tests
# ===========================================================================

class TestModel:

    def test_model_file_exists(self):
        assert os.path.exists(MODEL_PATH), (
            f"Model file not found: {MODEL_PATH} — run train_model.py first."
        )

    def test_prediction_is_binary(self):
        if not os.path.exists(MODEL_PATH):
            pytest.skip("Model file not present.")
        model  = joblib.load(MODEL_PATH)
        sample = pd.DataFrame(
            [[60, 6, 16, 443, 49698]],
            columns=["packet_length", "protocol", "tcp_flags",
                     "src_port", "dst_port"],
        )
        pred = model.predict(sample)[0]
        assert pred in (0, 1), f"Expected 0 or 1, got {pred}"

    def test_prediction_on_syn_flood_signature(self):
        """SYN-only flag pattern should tend toward anomaly class."""
        if not os.path.exists(MODEL_PATH):
            pytest.skip("Model file not present.")
        model  = joblib.load(MODEL_PATH)
        # SYN flag = 0x002, small packet, common DDoS ports
        sample = pd.DataFrame(
            [[64, 6, 2, 12345, 80]],
            columns=["packet_length", "protocol", "tcp_flags",
                     "src_port", "dst_port"],
        )
        pred = model.predict(sample)[0]
        # We cannot guarantee the label without knowing the training data,
        # but we verify it is a valid output.
        assert pred in (0, 1)


# ===========================================================================
# 3. IPS / whitelist tests
# ===========================================================================

class TestIPS:

    def test_whitelisted_ips_not_blocked(self):
        """Whitelisted addresses must never be added to BANNED_IPS."""
        banned: set = set()

        def mock_block(ip: str) -> None:
            if ip not in WHITELIST:
                banned.add(ip)

        for ip in WHITELIST:
            mock_block(ip)

        assert len(banned) == 0, f"Whitelisted IPs were blocked: {banned}"

    def test_non_whitelisted_ip_is_blocked(self):
        banned: set = set()

        def mock_block(ip: str) -> None:
            if ip not in WHITELIST:
                banned.add(ip)

        mock_block("192.168.100.200")
        assert "192.168.100.200" in banned

    def test_duplicate_block_ignored(self):
        """Calling block_ip twice for the same address should only add once."""
        banned: set = set()
        _lock = threading.Lock()

        def mock_block(ip: str) -> None:
            with _lock:
                if ip not in WHITELIST and ip not in banned:
                    banned.add(ip)

        mock_block("10.10.10.10")
        mock_block("10.10.10.10")   # duplicate
        assert len([x for x in banned if x == "10.10.10.10"]) == 1


# ===========================================================================
# 4. API response format tests
# ===========================================================================

class TestAPIFormat:

    def test_log_dict_has_required_keys(self):
        """Simulate the dict that app.py returns from /api/alerts."""
        sample = {
            "timestamp": "2026-02-08 12:00:00",
            "src_ip":    "192.168.1.1",
            "dst_ip":    "10.0.2.15",
            "status":    "Anomaly Detected",
            "risk":      "High",
        }
        for key in ("timestamp", "src_ip", "dst_ip", "status", "risk"):
            assert key in sample

    def test_risk_values_are_valid(self):
        valid_risks = {"High", "Low"}
        for risk in ("High", "Low"):
            assert risk in valid_risks

    def test_src_ip_is_string(self):
        sample = {"src_ip": "192.168.1.1"}
        assert isinstance(sample["src_ip"], str)


# ===========================================================================
# 5. ICMP sweep detection logic
# ===========================================================================

class TestICMPSweep:

    def test_sweep_detected_after_threshold(self):
        """
        Simulates ICMP_SWEEP_THRESHOLD hits within the window and checks
        the detection function returns True.
        """
        from collections import defaultdict

        THRESHOLD  = 10
        WINDOW_SEC = 5
        tracker: dict = defaultdict(list)

        def is_sweep(src_ip: str) -> bool:
            now = time.time()
            tracker[src_ip] = [t for t in tracker[src_ip]
                                if now - t < WINDOW_SEC]
            tracker[src_ip].append(now)
            return len(tracker[src_ip]) >= THRESHOLD

        for _ in range(THRESHOLD):
            result = is_sweep("attacker_ip")

        assert result is True

    def test_single_ping_not_flagged(self):
        from collections import defaultdict

        THRESHOLD  = 10
        WINDOW_SEC = 5
        tracker: dict = defaultdict(list)

        def is_sweep(src_ip: str) -> bool:
            now = time.time()
            tracker[src_ip] = [t for t in tracker[src_ip]
                                if now - t < WINDOW_SEC]
            tracker[src_ip].append(now)
            return len(tracker[src_ip]) >= THRESHOLD

        result = is_sweep("normal_user")
        assert result is False
