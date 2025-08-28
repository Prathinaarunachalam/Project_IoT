import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler

# Define file paths (Modify as needed)
bot_iot_file = "data_1.csv"
iot_simulated_file = "iot_traffic_advanced.csv"

def load_and_preprocess_train_data():
    print("🚀 Running Training Data Preprocessing...")

    # Load datasets
    bot_iot_data = pd.read_csv(bot_iot_file, low_memory=False)
    iot_simulated_data = pd.read_csv(iot_simulated_file, low_memory=False)
    print(f"✅ Loaded datasets: {bot_iot_file} and {iot_simulated_file}")

    # Convert non-numeric columns to numeric (ignoring errors)
    bot_iot_data = bot_iot_data.apply(pd.to_numeric, errors='coerce')
    iot_simulated_data = iot_simulated_data.apply(pd.to_numeric, errors='coerce')
    print("🔍 Converted non-numeric columns to numeric.")

    # Handle missing values using mean
    bot_iot_data.fillna(bot_iot_data.mean(numeric_only=True), inplace=True)
    iot_simulated_data.fillna(iot_simulated_data.mean(numeric_only=True), inplace=True)
    print("🔄 Filled missing values with mean.")

    # Drop irrelevant columns (ensure these columns exist before dropping)
    drop_columns = ["saddr", "daddr", "smac", "dmac", "soui", "doui", "flgs", "proto", "state"]
    bot_iot_data.drop(columns=[col for col in drop_columns if col in bot_iot_data.columns], errors='ignore', inplace=True)
    iot_simulated_data.drop(columns=[col for col in drop_columns if col in iot_simulated_data.columns], errors='ignore', inplace=True)
    print("🗑️ Dropped irrelevant columns.")

    # Reload labels separately
    iot_simulated_data["label"] = pd.read_csv(iot_simulated_file)["label"]

    # Find common features for alignment
    common_features = list(set(bot_iot_data.columns) & set(iot_simulated_data.columns) - {"label"})
    
    if not common_features:
        print("⚠️ No common features found! Skipping scaling.")
    else:
        # Keep only common columns and align the order
        bot_iot_data = bot_iot_data[common_features]
        iot_simulated_data = iot_simulated_data[common_features]

        # Apply MinMax Scaling
        scaler = MinMaxScaler()
        bot_iot_data[common_features] = scaler.fit_transform(bot_iot_data[common_features])
        iot_simulated_data[common_features] = scaler.transform(iot_simulated_data[common_features])
        print("📏 Applied MinMax Scaling.")

    # Save processed training data (including labels)
    iot_simulated_data["label"] = pd.read_csv(iot_simulated_file)["label"]  # Re-attach labels
    iot_simulated_data.to_csv("iot_traffic_train.csv", index=False)
    print("💾 Preprocessed training dataset saved as 'iot_traffic_train.csv' with labels.")

    return iot_simulated_data

# Run preprocessing
if __name__ == "__main__":
    X_train = load_and_preprocess_train_data()
