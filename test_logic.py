import pytest
import pandas as pd
import joblib
import os

# Load the model for testing
MODEL_PATH = "anomaly_detector_model.pkl"

def test_model_exists():
    """Check if the trained model file is present."""
    assert os.path.exists(MODEL_PATH)

def test_prediction_output():
    """Verify the model returns a binary 0 or 1 for sample data."""
    model = joblib.load(MODEL_PATH)
    
    # Create dummy packet data: [length, protocol, flags, src_port, dst_port]
    sample_data = pd.DataFrame([[60, 6, 16, 443, 49698]], 
                               columns=['packet_length', 'protocol', 'tcp_flags', 'src_port', 'dst_port'])
    
    prediction = model.predict(sample_data)[0]
    assert prediction in [0, 1]

def test_api_structure():
    """Verify that the data format matches what the Dashboard expects."""
    # Simulation of the 'res' dictionary created in app.py
    sample_res = {
        "time": "2026-02-08 12:00:00",
        "src": "192.168.1.1",
        "dst": "10.0.2.15",
        "status": "Anomaly Detected!",
        "level": "High"
    }
    assert isinstance(sample_res["src"], str)
    assert sample_res["level"] in ["High", "Low"]