# backend/predict.py

import numpy as np
import joblib
import pandas as pd
import os,sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.feature_list import FEATURE_LIST

# Load the trained Isolation Forest model
MODEL_PATH = "model/isolation_forest.pkl"
model = joblib.load(MODEL_PATH)


def predict_intrusion(input_data):
    """
    Predict whether the given input data represents a normal or anomalous connection.
    input_data: dict containing all feature values (as float or int)
    Returns: dict with prediction label and confidence score
    """

    try:
        # Ensure all features exist and are ordered as in FEATURE_LIST
        data = pd.DataFrame([[input_data[f] for f in FEATURE_LIST]], columns=FEATURE_LIST)

        # Predict using the trained model
        prediction = model.predict(data)[0]         # 1 → Normal, -1 → Anomaly
        score = model.decision_function(data)[0]    # Higher = more normal

        # Convert anomaly score to readable confidence (0–100 scale)
        # Using a sigmoid-like scaling for better interpretability
        confidence = round(float(100 / (1 + np.exp(-score))), 2)

        # Label mapping
        label = "Normal" if prediction == 1 else "Anomaly"

        return {
            "prediction": label,
            "confidence": confidence
        }

    except Exception as e:
        return {"error": str(e)}


# For quick standalone test
if __name__ == "__main__":
    # Example dummy input (replace with actual form data)
    sample_input = {
        "protocol_type": 1,
        "flag": 2,
        "destination_port": 80,
        "flow_duration": 500,
        "total_forward_packets": 10,
        "total_backward_packets": 8,
        "average_packet_size": 250,
        "flow_bytes_per_s": 1500,
        "fwd_iat_mean": 200,
        "bwd_iat_mean": 180
    }

    result = predict_intrusion(sample_input)
    print("\n[TEST] Sample Prediction Result:\n", result)
