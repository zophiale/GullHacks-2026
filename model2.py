import numpy as np
import pandas as pd
import torch
import scapy.all as scp
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset
from collections import deque
import torch.nn as nn
import torch.optim as optim
import matplotlib.pyplot as plt

data = deque(scp.raw(scp.sniff()))
data_tensor = torch.tensor(data)

dataset = TensorDataset(data_tensor)
dataloader = DataLoader(dataset, batch_size=32, shuffle=True)

class Autoencoder(nn.Module):
    def __init__(self):
        super(Autoencoder, self).__init__()

        self.encoder = nn.Sequential(
            nn.Linear(1, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 2)
        )

        self.decoder = nn.Sequential(
            nn.Linear(2, 8),
            nn.ReLU(),
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 1)
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

model = Autoencoder()

criterion = nn.MSELoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)

epochs = 30
model.train()

for epoch in range(epochs):
    epoch_loss = 0
    for batch in dataloader:
        inputs = batch[0]

        optimizer.zero_grad()
        outputs = model(inputs)
        loss = criterion(outputs, inputs)
        loss.backward()
        optimizer.step()

        epoch_loss += loss.item()

    print(f"Epoch [{epoch+1}/{epochs}], Loss: {epoch_loss/len(dataloader):.6f}")

model.eval()
with torch.no_grad():
    reconstructed = model(data_tensor)
    reconstruction_error = torch.mean((data_tensor - reconstructed) ** 2, dim=1)

reconstruction_error = reconstruction_error.numpy()

threshold = np.percentile(reconstruction_error, 95)
anomaly_predictions = reconstruction_error > threshold

plt.figure(figsize=(10, 6))
plt.plot(data, label="Data")
plt.scatter(
    np.where(anomaly_predictions)[0],
    data[anomaly_predictions],
    color="red",
    label="Detected Anomalies"
)
plt.axhline(y=threshold, color='black', linestyle='--', label="Threshold")
plt.title("Anomaly Detection using PyTorch Autoencoder")
plt.xlabel("Time Steps")
plt.ylabel("Value")
plt.legend()
plt.show()