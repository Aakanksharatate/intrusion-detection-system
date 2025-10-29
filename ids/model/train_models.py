# ==========================================================
# model/train_models.py — FINAL FIXED VERSION ✅
# ==========================================================
import pandas as pd
import numpy as np
import joblib
import os, sys
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, classification_report

# ---------------------------------------------------------
# Import shared feature list
# ---------------------------------------------------------
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.feature_list import FEATURE_LIST

# ---------------------------------------------------------
# Paths setup
# ---------------------------------------------------------
DATA_PATH = "Dataset"
MODEL_PATH = "model"

CIC_FILE = os.path.join(DATA_PATH, "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
NSL_TRAIN = os.path.join(DATA_PATH, "KDDTrain+.txt")
NSL_TEST = os.path.join(DATA_PATH, "KDDTest+.txt")

MODEL_FILE = os.path.join(MODEL_PATH, "isolation_forest.pkl")
SCALER_FILE = os.path.join(MODEL_PATH, "scaler.pkl")
ENCODER_FILE = os.path.join(MODEL_PATH, "encoders.pkl")

os.makedirs(MODEL_PATH, exist_ok=True)

# ---------------------------------------------------------
# Load datasets
# ---------------------------------------------------------
print("[INFO] Loading datasets...")
cic = pd.read_csv(CIC_FILE)
print(f"[INFO] CIC dataset shape: {cic.shape}")

nsl_train = pd.read_csv(NSL_TRAIN, header=None)
nsl_test = pd.read_csv(NSL_TEST, header=None)
nsl = pd.concat([nsl_train, nsl_test], ignore_index=True)
print(f"[INFO] NSL dataset shape: {nsl.shape}")

# ---------------------------------------------------------
# Clean column names + unify naming
# ---------------------------------------------------------
cic.columns = cic.columns.str.lower().str.strip().str.replace(" ", "_").str.replace("-", "_")

column_map = {
    "dst_port": "destination_port",
    "protocol": "protocol_type",
    "tot_fwd_pkts": "total_forward_packets",
    "tot_bwd_pkts": "total_backward_packets",
    "pkt_size_avg": "average_packet_size",
    "flow_bytes_s": "flow_bytes_per_s",
}
cic = cic.rename(columns={col: column_map.get(col, col) for col in cic.columns})

possible_labels = ["label", "attack_cat", "class", "target"]
label_col = next((col for col in possible_labels if col in cic.columns), None)
if label_col:
    print(f"[INFO] Detected label column: {label_col}")
else:
    print("[WARN] No label column found — training unsupervised.")

# ---------------------------------------------------------
# Ensure all required features exist
# ---------------------------------------------------------
for f in FEATURE_LIST:
    if f not in cic.columns:
        cic[f] = 0

cic = cic[FEATURE_LIST + ([label_col] if label_col else [])]

# ---------------------------------------------------------
# Prepare NSL-KDD numeric subset
# ---------------------------------------------------------
nsl.columns = [f"col_{i}" for i in range(nsl.shape[1])]
nsl_numeric = nsl.select_dtypes(include=[np.number]).apply(pd.to_numeric, errors="coerce").fillna(0)
nsl_numeric = nsl_numeric.iloc[:, :len(FEATURE_LIST)]
nsl_numeric.columns = FEATURE_LIST

# ---------------------------------------------------------
# Merge CIC + NSL
# ---------------------------------------------------------
combined = pd.concat([cic[FEATURE_LIST], nsl_numeric], ignore_index=True)
combined = combined.fillna(0)
print(f"[INFO] Combined dataset shape: {combined.shape}")

# ---------------------------------------------------------
# Encode categorical features
# ---------------------------------------------------------
label_encoders = {}
for col in FEATURE_LIST:
    if combined[col].dtype == "object" or col in ["protocol_type", "flag"]:
        le = LabelEncoder()
        combined[col] = le.fit_transform(combined[col].astype(str))
        label_encoders[col] = le

# ---------------------------------------------------------
# Scale features
# ---------------------------------------------------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(combined[FEATURE_LIST])
X_scaled_df = pd.DataFrame(X_scaled, columns=FEATURE_LIST)

# ---------------------------------------------------------
# Train Isolation Forest
# ---------------------------------------------------------
print("[INFO] Training Isolation Forest...")
model = IsolationForest(
    n_estimators=200,
    contamination=0.03,
    random_state=42
)
model.fit(X_scaled_df)
print("[INFO] Training complete ✅")

# ---------------------------------------------------------
# Optional Evaluation (if label exists)
# ---------------------------------------------------------
if label_col:
    y_true = np.where(cic[label_col].astype(str).str.contains("normal", case=False), 1, -1)
    X_eval = cic[FEATURE_LIST].copy()
    for col, le in label_encoders.items():
        if col in X_eval.columns:
            X_eval[col] = le.transform(X_eval[col].astype(str))
    y_pred = model.predict(scaler.transform(X_eval))
    print("\n[INFO] Evaluation on CIC dataset:")
    print(confusion_matrix(y_true, y_pred))
    print(classification_report(y_true, y_pred, target_names=["Attack", "Normal"]))

# ---------------------------------------------------------
# Save model + preprocessors
# ---------------------------------------------------------
joblib.dump(model, MODEL_FILE)
joblib.dump(scaler, SCALER_FILE)
joblib.dump(label_encoders, ENCODER_FILE)

print(f"[INFO] Model saved → {MODEL_FILE}")
print(f"[INFO] Scaler saved → {SCALER_FILE}")
print(f"[INFO] Encoders saved → {ENCODER_FILE}")

# ---------------------------------------------------------
# Prediction function
# ---------------------------------------------------------
def predict_from_input(feature_dict):
    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)
    encoders = joblib.load(ENCODER_FILE)

    df = pd.DataFrame([feature_dict])

    # Ensure all 10 features are present
    for f in FEATURE_LIST:
        if f not in df.columns:
            df[f] = 0

    # Encode categorical safely
    for col, le in encoders.items():
        if col in df.columns:
            df[col] = df[col].apply(lambda x: x if x in le.classes_ else le.classes_[0])
            df[col] = le.transform(df[col].astype(str))

    # Scale + predict
    X_scaled = scaler.transform(df[FEATURE_LIST])
    pred = model.predict(X_scaled)[0]
    score = model.decision_function(X_scaled)[0]
    confidence = round(float(100 / (1 + np.exp(-score))), 2)

    return {
        "prediction": "Normal" if pred == 1 else "Anomaly",
        "confidence": confidence
    }

# ---------------------------------------------------------
# Test run
# ---------------------------------------------------------
if __name__ == "__main__":
    print("\n[TEST] Sample input prediction:")
    sample = {
        "protocol_type": "tcp",
        "flag": "SF",
        "destination_port": 80,
        "flow_duration": 1000,
        "total_forward_packets": 10,
        "total_backward_packets": 8,
        "average_packet_size": 250,
        "flow_bytes_per_s": 5000,
        "fwd_iat_mean": 5,
        "bwd_iat_mean": 7
    }
    print(predict_from_input(sample))
