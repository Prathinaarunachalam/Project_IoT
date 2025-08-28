import numpy as np
import pandas as pd
import os
import smtplib
import ssl
from email.message import EmailMessage
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
    Classifies the detected anomaly based on its feature values.
    """
    packet_size, bytes_, duration, src_entropy, dst_entropy, interarrival, tcp_flags, flow_rate, icmp_type, ttl, entropy = sample

    # 🚀 Enhanced classification logic
    if flow_rate >= 100 and flow_rate <= 200:  # Expanded flow rate range for volumetric attack
        if src_entropy >= 0.85 and bytes_ > 5000:
            return "DDoS Attack"
        elif bytes_ < 1000:
            return "DoS Attack"
        elif bytes_ > 1000 and ttl < 50:
            return "Flood Attack"

    elif tcp_flags in [2, 4, 16] or (tcp_flags == 18 and ttl < 30):  # Including more flag combinations
        return "Unauthorized Access (U2R)"

    elif interarrival < 0.02 and entropy > 0.92:  # Fast traffic with high entropy
        return "Keylogging or Botnet"

    elif dst_entropy > 0.75 and flow_rate < 50:  # High destination entropy, low flow
        return "Probe Attack"

    elif packet_size < 80 and bytes_ > 8000:  # Large data in small packets
        return "Data Exfiltration"

    # Additional classification based on `icmp_type`
    if icmp_type == 3 and flow_rate > 30:
        return "ICMP Flood Attack"

    if ttl < 10 and flow_rate > 100:
        return "Spoofing or Routing Attack"

    return "Unknown Anomaly"  # Default case

# Detect anomaly and classify attack
if reconstruction_error > THRESHOLD:
    attack_type = classify_attack(test_sample[0])
    anomaly_detected = "Yes"
    alert_message = f"🚨 ALERT! Anomaly Detected in IoT Network Traffic - Attack Type: {attack_type} 🚨\n"
    print(alert_message)
else:
    attack_type = "Normal"
    anomaly_detected = "No"
    alert_message = "✅ No anomaly detected in network traffic."

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
    "Anomaly_Detected": [anomaly_detected],
    "Attack_Type": [attack_type]
})
df_results.to_csv(output_file, mode='a', index=False, header=not os.path.exists(output_file))

print(f"💾 Detailed results saved in '{output_file}'")


### **📧 Email Notification Functionality**
def send_email_alert():
    sender_email = "prathinaarunachalam@gmail.com"
    receiver_email = "prathinaarunachalam@gmail.com"
    password = "hikh acmu onkh hjdv"  # ⚠️ Use App Passwords instead of main password!

    subject = "🚨 IoT Anomaly Detection Alert 🚨"
    body = f"""
    Anomaly Detection Report:

    - Reconstruction Error: {reconstruction_error:.6f}
    - Detection Threshold: {THRESHOLD:.6f}
    - Anomaly Detected: {anomaly_detected}
    - Attack Type: {attack_type}

    Please find the attached anomaly detection report.

    Regards,
    IoT Security System
    """

    # Create email
    msg = EmailMessage()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.set_content(body)

    # Attach CSV file
    with open(output_file, "rb") as f:
        msg.add_attachment(f.read(), maintype="application", subtype="csv", filename=output_file)

    # Send email via SMTP (Gmail example)
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, password)
            server.send_message(msg)
        print("📧 Email notification sent successfully!")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")


# **Trigger email if an anomaly is detected**
if anomaly_detected == "Yes":
    send_email_alert()
