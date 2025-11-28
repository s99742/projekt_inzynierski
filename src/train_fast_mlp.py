#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import joblib
import numpy as np
import matplotlib.pyplot as plt
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score
from tqdm import tqdm

BASE = "/home/jakub-wasiewicz/Desktop/inzynierka/projekt_inzynierski"

NORMALIZED_DIR = os.path.join(BASE, "data", "normalized")
MODEL_DIR = os.path.join(BASE, "models")
SCALER_PATH = os.path.join(NORMALIZED_DIR, "scaler.pkl")
PLOT_PATH = os.path.join(MODEL_DIR, "MLP_training_plot.png")
LOG_FILE = os.path.join(MODEL_DIR, "MLP_training_log.csv")

# -----------------------------------------------------------
# 1. Load scaler
# -----------------------------------------------------------
print("Ładowanie scalera...")
scaler = joblib.load(SCALER_PATH)
print("Scaler załadowany.")

# -----------------------------------------------------------
# 2. Load chunks
# -----------------------------------------------------------
chunk_files = [
    os.path.join(NORMALIZED_DIR, f)
    for f in os.listdir(NORMALIZED_DIR)
    if f.endswith(".pkl") and f != "scaler.pkl"
]

X_list, y_list = [], []
print("Ładowanie chunków...")
for file in tqdm(chunk_files, desc="Chunk files"):
    Xc, yc = joblib.load(file)
    X_list.append(Xc)
    y_list.append(yc)

X = np.vstack(X_list)
y = np.hstack(y_list)

print("Kształt danych:", X.shape, y.shape)

# -----------------------------------------------------------
# 3. Normalize
# -----------------------------------------------------------
print("Normalizacja...")
X = scaler.transform(X)
print("OK")

# -----------------------------------------------------------
# 4. Prepare MLP (manual iterative training)
# -----------------------------------------------------------
mlp = MLPClassifier(
    hidden_layer_sizes=(48, 24),
    activation='relu',
    solver='adam',
    max_iter=1,               # będziemy iterować ręcznie
    warm_start=True,          # pozwala trenować etapami
    batch_size=512,
    learning_rate_init=0.001,
    validation_fraction=0.1,
    early_stopping=False,     # wyłączone, bo iterujemy ręcznie
    random_state=42,
    verbose=False
)

# -----------------------------------------------------------
# 5. Manual training loop with logging
# -----------------------------------------------------------
EPOCHS = 80  # około 20–25 minut na Twoim CPU

loss_history = []
val_loss_history = []
time_history = []

print("\n🚀 Start trenowania...")
start_total = time.time()

# Podział train/val (scikit-learn robi to sam przy `validation_fraction`,
# ale musimy to zrobić manualnie)
val_split = int(len(X) * 0.9)
X_train, X_val = X[:val_split], X[val_split:]
y_train, y_val = y[:val_split], y[val_split:]

# CSV header
with open(LOG_FILE, "w") as f:
    f.write("epoch,loss,val_loss,epoch_time\n")

for epoch in range(EPOCHS):
    t0 = time.time()

    mlp.fit(X_train, y_train)

    # Pobieranie loss
    train_loss = mlp.loss_

    # Walidacja
    y_val_pred_prob = mlp.predict_proba(X_val)
    val_loss = -np.mean(np.log(y_val_pred_prob[range(len(y_val)), y_val]))

    loss_history.append(train_loss)
    val_loss_history.append(val_loss)

    epoch_time = time.time() - t0
    time_history.append(epoch_time)

    # Log do pliku
    with open(LOG_FILE, "a") as f:
        f.write(f"{epoch+1},{train_loss},{val_loss},{epoch_time:.4f}\n")

    print(f"Epoka {epoch+1}/{EPOCHS} | loss={train_loss:.4f} | val_loss={val_loss:.4f} | czas={epoch_time:.2f}s")

total_time = time.time() - start_total
print(f"\nCałkowity czas trenowania: {total_time/60:.2f} min")

# -----------------------------------------------------------
# 6. Obliczenie accuracy
# -----------------------------------------------------------
y_pred = mlp.predict(X)
accuracy = accuracy_score(y, y_pred)
print(f"\nFinal accuracy: {accuracy:.4f}")

# -----------------------------------------------------------
# 7. Wykres loss/val_loss
# -----------------------------------------------------------
plt.figure(figsize=(10, 6))
plt.plot(loss_history, label="Train loss")
plt.plot(val_loss_history, label="Validation loss")
plt.xlabel("Epoka")
plt.ylabel("Loss")
plt.title("Przebieg treningu MLP")
plt.legend()
plt.grid()
plt.savefig(PLOT_PATH, dpi=200)
plt.close()

print(f"\n📊 Zapisano wykres: {PLOT_PATH}")
print(f"Log CSV zapisany jako: {LOG_FILE}")

# -----------------------------------------------------------
# 8. Save model
# -----------------------------------------------------------
output_path = os.path.join(MODEL_DIR, "MLP_fast_logged.pkl")
joblib.dump(mlp, output_path)

print(f"\nModel zapisany: {output_path}")
print("Gotowe!")
