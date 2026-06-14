"""
Smart Network Traffic Analysis and Anomaly Detection System (SNTAADS)
----------------------------------------------------------------------
train_model.py
Trains a Random Forest anomaly-detection classifier on labelled
packet-feature data and saves the model to disk.

Expected CSV columns (produced by feature_extractor.py + manual labelling):
    packet_length, protocol, tcp_flags, src_port, dst_port, label
    label: 0 = normal, 1 = anomaly

Author : Ammar Nasser Said Al-Hajri  (22F23369)
College: Middle East College, Knowledge Oasis Muscat
"""

import os
import logging
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("SNTAADS.TrainModel")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CSV_PATH    = os.path.join(BASE_DIR, "network_features.csv")
MODEL_PATH  = os.path.join(BASE_DIR, "anomaly_detector_model.pkl")

# Features used for training — must match what app.py feeds at inference time
FEATURE_COLS = ["packet_length", "protocol", "tcp_flags", "src_port", "dst_port"]


def load_and_validate(csv_path: str) -> pd.DataFrame:
    """Load CSV and verify all required columns are present."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Training data not found: {csv_path}")

    df = pd.read_csv(csv_path)
    required = FEATURE_COLS + ["label"]
    missing  = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns in CSV: {missing}")
    return df


def preprocess(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Clean data and return (features, labels)."""
    # Fill missing port values for non-TCP/UDP packets
    for col in ("src_port", "dst_port", "tcp_flags"):
        df[col] = df[col].fillna(0).astype(int)

    X = df[FEATURE_COLS]
    y = df["label"].astype(int)
    return X, y


def train(csv_path: str = CSV_PATH, model_path: str = MODEL_PATH) -> None:
    log.info("Loading training data from %s", csv_path)
    df = load_and_validate(csv_path)
    log.info("Dataset shape: %s  (anomalies: %d / normal: %d)",
             df.shape,
             (df["label"] == 1).sum(),
             (df["label"] == 0).sum())

    X, y = preprocess(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    log.info("Training Random Forest classifier …")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # Evaluation
    y_pred = clf.predict(X_test)
    print("\n--- Classification Report ---")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Anomaly"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    joblib.dump(clf, model_path)
    log.info("Model saved to %s", model_path)


if __name__ == "__main__":
    train()
