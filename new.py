import numpy as np
import pandas as pd
import os
from tensorflow.keras.models import load_model
from tensorflow.keras.losses import MeanSquaredError
from sklearn.preprocessing import StandardScaler

# Load trained RAE model
rae_model = load_model("rae_anomaly_detector.h5", custom_objects={'mse': MeanSquaredError()})

# Load test data
df_test = pd.read_csv("iot_traffic_advanced.csv")

# Select feature columns (excluding label)
feature_columns = [
    'packet_size', 'flow_duration', 'protocol_type', 'src_ip_entropy', 'dst_ip_entropy', 
    'packet_interarrival_time', 'tcp_flags', 'bytes_per_flow', 'flow_rate', 'jitter'
]

# Convert to NumPy array
X_test = df_test[feature_columns].values

# **Ensure test data has 11 features (if missing, add a placeholder feature)**
if X_test.shape[1] < 11:
    extra_feature = np.zeros((X_test.shape[0], 1))  # Add a zero column
    X_test = np.hstack((X_test, extra_feature))  # Ensure 11 features
    feature_columns.append("extra_feature")  # Update feature names list

# Normalize test data using StandardScaler
scaler = StandardScaler()
X_test_normalized = scaler.fit_transform(X_test)

# Generate a random test sample from dataset
random_index = np.random.randint(0, len(X_test))
test_sample = X_test[random_index].reshape(1, -1)

# Normalize the test sample
test_sample_normalized = scaler.transform(test_sample)

# **Fix the shape to match model input (batch_size=1, time_steps=10, features=11)**
test_sample_normalized = np.tile(test_sample_normalized, (1, 10, 1))  # Repeat across 10 time steps

# Verify the final shape before prediction
print(f"🔹 Final test sample shape: {test_sample_normalized.shape}")  # Should be (1, 10, 11)

# Predict reconstruction error for the sample
test_sample_pred = rae_model.predict(test_sample_normalized)
reconstruction_error = np.mean(np.abs(test_sample_pred - test_sample_normalized))

# Define anomaly detection threshold
THRESHOLD = 0.25

# Function to classify attack type
def classify_attack(sample):
    """
    Classifies the detected anomaly based on its feature values with more granularity.
    """
    packet_size, bytes_, duration, src_entropy, dst_entropy, interarrival, tcp_flags, flow_rate, icmp_type, ttl, entropy = sample
    protocol_type = sample[2]  # Extract protocol from sample

    # Dictionary-based rules for better differentiation
    attack_types = {
        "DDoS Attack": (flow_rate >= 150 and src_entropy >= 0.85 and bytes_ > 5000),
        "DoS Attack": (flow_rate >= 100 and bytes_ < 1000),
        "SYN Flood": (tcp_flags == 2 and flow_rate > 120),
        "UDP Flood": (protocol_type == 17 and bytes_ > 8000 and flow_rate > 200),  # ✅ Fixed this line
        "ICMP Flood": (icmp_type == 3 and flow_rate > 30),
        "Probe Attack": (dst_entropy > 0.75 and flow_rate < 50),
        "Data Exfiltration": (packet_size < 80 and bytes_ > 8000),
        "Spoofing Attack": (ttl < 10 and flow_rate > 100),
        "Keylogging/Botnet": (interarrival < 0.02 and entropy > 0.92),
        "Unauthorized Access (U2R)": (tcp_flags in [2, 4, 16] or (tcp_flags == 18 and ttl < 30)),
        "Unknown Anomaly": True  # Default case
    }

    # Identify and return the first matching attack type
    for attack, condition in attack_types.items():
        if condition:
            return attack

    return "Unknown Anomaly"

# Print real-time IoT traffic anomaly detection results
print("📌 Real-Time IoT Traffic Anomaly Detection\n")

# Display generated test sample
print("🔹 Generated Test Sample:")
print(f" packets  bytes  duration  src_port  dst_port  protocol  flow_rate  tcp_flags  icmp_type  ttl  entropy")
print(f"     {int(test_sample[0][0])}  {int(test_sample[0][7])}      {round(test_sample[0][1], 2)}     45678      8080        {int(test_sample[0][2])}       {round(test_sample[0][8], 1)}        {int(test_sample[0][6])}         10  128    {round(test_sample[0][3], 4)}\n")

# Display reconstruction error and threshold
print(f"🔹 Reconstruction Error (MSE): {round(reconstruction_error, 6)}")
print(f"🔹 Anomaly Detection Threshold: {THRESHOLD:.6f}\n")

# Detect anomaly and classify attack
if reconstruction_error > THRESHOLD:
    attack_type = classify_attack(test_sample[0])
    print(f"🚨 ALERT! Anomaly Detected in IoT Network Traffic - Attack Type: {attack_type} 🚨\n")
else:
    attack_type = "Normal"

# Save detailed results to CSV
output_file = "detailed_anomaly_result.csv"
df_results = pd.DataFrame({
    "Packet_Size": [test_sample[0][0]],
    "Bytes": [test_sample[0][7]],
    "Duration": [test_sample[0][1]],
    "Protocol": [test_sample[0][2]],
    "Flow_Rate": [test_sample[0][8]],
    "TCP_Flags": [test_sample[0][6]],
    "Entropy": [test_sample[0][3]],
    "Reconstruction_Error": [reconstruction_error],
    "Anomaly_Detected": ["Yes" if reconstruction_error > THRESHOLD else "No"],
    "Attack_Type": [attack_type]
})
df_results.to_csv(output_file, mode='a', index=False, header=not os.path.exists(output_file))

print(f"💾 Detailed results saved in '{output_file}'")
