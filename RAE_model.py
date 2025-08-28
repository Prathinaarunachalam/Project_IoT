import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, LSTM, RepeatVector, TimeDistributed, Dense
from sklearn.preprocessing import MinMaxScaler

# ✅ Load preprocessed training data
train_file = "iot_traffic_train.csv"
df_train = pd.read_csv(train_file)

# ✅ Convert all values to numeric (fix dtype issue)
df_train = df_train.apply(pd.to_numeric, errors='coerce').fillna(0)

# ✅ Normalize data using MinMaxScaler
scaler = MinMaxScaler()
X_train = scaler.fit_transform(df_train.values)

# ✅ Create sequences for LSTM model
SEQ_LENGTH = 10  # Adjust sequence length as needed

def create_sequences(data, seq_length=SEQ_LENGTH):
    sequences = []
    for i in range(len(data) - seq_length):
        sequences.append(data[i : i + seq_length])
    return np.array(sequences, dtype=np.float32)  # Fix dtype issue

X_train_seq = create_sequences(X_train)

# ✅ Define Recurrent Autoencoder (RAE) Model
input_dim = X_train_seq.shape[2]  # Number of features

input_layer = Input(shape=(SEQ_LENGTH, input_dim))

# Encoder
encoded = LSTM(128, return_sequences=True)(input_layer)
encoded = LSTM(64, return_sequences=False)(encoded)

# Bottleneck
bottleneck = RepeatVector(SEQ_LENGTH)(encoded)

# Decoder
decoded = LSTM(64, return_sequences=True)(bottleneck)
decoded = LSTM(128, return_sequences=True)(decoded)
decoded = TimeDistributed(Dense(input_dim))(decoded)

# Build Model
rae_model = Model(inputs=input_layer, outputs=decoded)
rae_model.compile(optimizer="adam", loss="mse")

# ✅ Model Summary
rae_model.summary()

# ✅ Train the model
rae_model.fit(X_train_seq, X_train_seq, epochs=50, batch_size=32, validation_split=0.1, verbose=1)

# ✅ Save model & scaler
rae_model.save("rae_anomaly_detector.h5")
np.save("scaler.npy", scaler)

print("🎉 Training Complete! Model & Scaler Saved.")
