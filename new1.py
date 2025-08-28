import numpy as np
import pandas as pd
import os
import smtplib
import ssl
from email.message import EmailMessage
from tensorflow.keras.models import load_model
from tensorflow.keras.losses import MeanSquaredError
from sklearn.preprocessing import StandardScaler
from datetime import datetime  # ⏰ Import for timestamp logging

# Load trained RAE model
rae_model = load_model("rae_anomaly_detector.h5", custom_objects={'mse': MeanSquaredError()})

# Load test data
df_test = pd.read_csv("iot_traffic_advanced.csv")

# Ensure correct feature selection
feature_columns = [
    'packet_size', 'flow_duration', 'protocol_type', 'src_ip_entropy', 'dst_ip_entropy', 
    'packet_interarrival_time', 'tcp_flags', 'bytes_per_flow', 'flow_rate', 'jitter'
]

X_test = df_test[feature_columns].values

# Ensure consistent feature count
EXPECTED_FEATURES = 11
if X_test.shape[1] < EXPECTED_FEATURES:
    extra_feature = np.zeros((X_test.shape[0], EXPECTED_FEATURES - X_test.shape[1]))  # Add missing features
    X_test = np.hstack((X_test, extra_feature))  
    feature_columns.extend(["extra_feature"] * (EXPECTED_FEATURES - len(feature_columns)))

# Normalize test data
scaler = StandardScaler()
X_test_normalized = scaler.fit_transform(X_test)

# Select a random test sample
random_index = np.random.randint(0, len(X_test))
test_sample = X_test[random_index].reshape(1, -1)

# Normalize sample
test_sample_normalized = scaler.transform(test_sample)

# Ensure correct shape for model input
test_sample_normalized = np.tile(test_sample_normalized, (1, 10, 1))

# Predict reconstruction error
test_sample_pred = rae_model.predict(test_sample_normalized)
reconstruction_error = np.mean(np.abs(test_sample_pred - test_sample_normalized))

# Adjusted threshold for anomaly detection
THRESHOLD = 0.12  # Dynamic threshold could be used here

# Function to classify attack
def classify_attack(sample):
    """
    Classifies the detected anomaly based on refined conditions.
    """
    packet_size, duration, protocol_type, src_entropy, dst_entropy, interarrival, tcp_flags, bytes_per_flow, flow_rate, jitter, _ = sample

    if flow_rate > 100:
        if src_entropy > 0.85 and bytes_per_flow > 5000:
            return "DDoS Attack"
        elif bytes_per_flow < 1000:
            return "DoS Attack"
        elif duration < 2 and jitter > 0.5:
            return "Flood Attack"

    if tcp_flags in [2, 4, 16] or (tcp_flags == 18 and duration < 1):
        return "Unauthorized Access (U2R)"

    if interarrival < 0.02 and src_entropy > 0.9:
        return "Keylogging or Botnet"

    if dst_entropy > 0.75 and flow_rate < 50:
        return "Probe Attack"

    if packet_size < 80 and bytes_per_flow > 8000:
        return "Data Exfiltration"

    if jitter > 0.5 and flow_rate > 40:
        return "Advanced Persistent Threat (APT)"

    return "Unknown Anomaly"

# Detect anomaly and classify attack
if reconstruction_error > THRESHOLD:
    attack_type = classify_attack(test_sample[0])
    anomaly_detected = "Yes"
    detection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_message = f"ALERT! Anomaly Detected in IoT Network Traffic - Attack Type: {attack_type} \nDetected at: {detection_time}\n"
    print(alert_message)
else:
    attack_type = "Normal"
    anomaly_detected = "No"
    detection_time = "N/A"
    alert_message = "No anomaly detected in network traffic."

# Save results
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
    "Anomaly_Detected": [anomaly_detected],
    "Attack_Type": [attack_type],
    "Detection_Time": [detection_time]
})
df_results.to_csv(output_file, mode='a', index=False, header=not os.path.exists(output_file))

print(f"Results saved in '{output_file}'")

### **📧 Email Alert Functionality**
def send_email_alert():
    sender_email = "prathinaarunachalam@gmail.com"
    receiver_email = "prathinaarunachalam@gmail.com"
    password = "hikh acmu onkh hjdv"  # ⚠️ Use App Passwords instead of main password!

    subject = "IoT Anomaly Detection Alert"
    body = f"""
    Anomaly Detection Report:

    - Detection Time: {detection_time}  
    - Reconstruction Error: {reconstruction_error:.6f}
    - Detection Threshold: {THRESHOLD:.6f}
    - Anomaly Detected: {anomaly_detected}
    - Attack Type: {attack_type}

    Regards,
    IoT Security System
    """

    msg = EmailMessage()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.set_content(body)

    # Attach CSV file
    with open(output_file, "rb") as f:
        msg.add_attachment(f.read(), maintype="application", subtype="csv", filename=output_file)

    # Send email
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, password)
            server.send_message(msg)
        print("📧 Email notification sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

# **Trigger email if anomaly detected**
if anomaly_detected == "Yes":
    send_email_alert()
