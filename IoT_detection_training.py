import numpy as np
import pandas as pd

# Function to generate simulated IoT network traffic with multiple attack types
def generate_traffic(num_samples=10000, attack_ratios=None, output_file="iot_traffic_advanced.csv"):
    np.random.seed(42)

    if attack_ratios is None:
        attack_ratios = {
            "normal": 0.75,
            "DoS": 0.08,
            "DDoS": 0.05,
            "Probe": 0.05,
            "Keylogging": 0.04,
            "U2R": 0.03
        }

    # Calculate sample counts for each category
    attack_counts = {k: int(num_samples * v) for k, v in attack_ratios.items()}
    
    # Generate normal traffic features
    packet_sizes = np.random.normal(loc=500, scale=200, size=num_samples)
    flow_durations = np.random.normal(loc=50, scale=10, size=num_samples)
    protocol_types = np.random.choice([0, 1], size=num_samples)  # 0 = TCP, 1 = UDP

    src_ip_entropy = np.random.uniform(0, 1, size=num_samples)  # Source IP randomness
    dst_ip_entropy = np.random.uniform(0, 1, size=num_samples)  # Destination IP randomness
    packet_interarrival_time = np.random.exponential(scale=0.1, size=num_samples)
    tcp_flags = np.random.choice([0, 1, 2, 4, 8, 16, 32, 64], size=num_samples)
    bytes_per_flow = np.random.normal(loc=10000, scale=3000, size=num_samples)
    flow_rate = bytes_per_flow / flow_durations
    jitter = np.random.normal(loc=5, scale=2, size=num_samples)

    # Assign labels
    labels = np.array(["normal"] * num_samples)

    # Introduce anomalies based on attack type
    def inject_attack(indices, attack_type):
        nonlocal src_ip_entropy, dst_ip_entropy, jitter, packet_sizes, flow_rate, labels
        
        if attack_type == "DoS":
            jitter[indices] *= np.random.uniform(4, 8, size=len(indices))
            flow_rate[indices] *= np.random.uniform(0.5, 2, size=len(indices))
            labels[indices] = "DoS"

        elif attack_type == "DDoS":
            src_ip_entropy[indices] += np.random.uniform(0.5, 1.0, size=len(indices))
            dst_ip_entropy[indices] += np.random.uniform(0.5, 1.0, size=len(indices))
            jitter[indices] *= np.random.uniform(5, 10, size=len(indices))
            packet_sizes[indices] *= np.random.uniform(1.5, 3, size=len(indices))
            labels[indices] = "DDoS"

        elif attack_type == "Probe":
            flow_rate[indices] *= np.random.uniform(0.2, 0.8, size=len(indices))
            src_ip_entropy[indices] += np.random.uniform(0.2, 0.5, size=len(indices))
            labels[indices] = "Probe"

        elif attack_type == "Keylogging":
            packet_interarrival_time[indices] *= np.random.uniform(0.01, 0.1, size=len(indices))
            labels[indices] = "Keylogging"

        elif attack_type == "U2R":
            tcp_flags[indices] = np.random.choice([2, 4, 16], size=len(indices))  # Unusual TCP flags
            jitter[indices] *= np.random.uniform(3, 6, size=len(indices))
            labels[indices] = "U2R"

    # Inject attacks into data
    start_index = 0
    for attack, count in attack_counts.items():
        if attack != "normal":
            attack_indices = np.random.choice(num_samples, count, replace=False)
            inject_attack(attack_indices, attack)

    # Save generated data to CSV
    df = pd.DataFrame({
        'packet_size': packet_sizes,
        'flow_duration': flow_durations,
        'protocol_type': protocol_types,
        'src_ip_entropy': src_ip_entropy,
        'dst_ip_entropy': dst_ip_entropy,
        'packet_interarrival_time': packet_interarrival_time,
        'tcp_flags': tcp_flags,
        'bytes_per_flow': bytes_per_flow,
        'flow_rate': flow_rate,
        'jitter': jitter,
        'label': labels
    })

    df.to_csv(output_file, index=False)
    print(f"✅ IoT traffic simulation completed. Data saved to '{output_file}'.")


# Run everything
if __name__ == "__main__":
    print("🚀 Running Advanced IoT Anomaly Detection Script...")

    # Generate synthetic IoT traffic with attack labels
    generate_traffic()

    print("🎯 All datasets processed successfully!")
