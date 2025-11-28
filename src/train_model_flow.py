#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from joblib import load, dump
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from tqdm import tqdm

# -------------------------------
# Ścieżki
# -------------------------------
DATA_DIR = "/home/jakub-wasiewicz/Desktop/inzynierka/projekt_inzynierski/data/normalized"
MODEL_DIR = "/home/jakub-wasiewicz/Desktop/inzynierka/projekt_inzynierski/models"
SCALER_PATH = os.path.join(DATA_DIR, "scaler_norm.pkl")  # scaler może być pickle lub joblib

# -------------------------------
# Wczytaj scaler
# -------------------------------
scaler = None
if os.path.exists(SCALER_PATH):
    try:
        scaler = load(SCALER_PATH)  # używamy joblib
        print("Scaler wczytany.")
    except Exception as e:
        print(f"Nie udało się wczytać scalera: {e}")

# -------------------------------
# Znajdź wszystkie joblib chunk
# -------------------------------
chunk_files = [os.path.join(DATA_DIR, f) for f in os.listdir(DATA_DIR) if f.endswith(".pkl")]
print(f"Znaleziono {len(chunk_files)} chunków joblib.")

# -------------------------------
# Wczytaj chunk bez błędów
# -------------------------------
chunks = []
for file in tqdm(chunk_files, desc="Ładowanie chunków"):
    try:
        chunk = load(file)
        if isinstance(chunk, tuple) and len(chunk) == 2:
            chunks.append(chunk)
        else:
            print(f"Pomijam {file}: niepoprawna struktura ({type(chunk)})")
    except Exception as e:
        print(f"Nie udało się wczytać {file}: {e}")

if len(chunks) == 0:
    raise RuntimeError("Nie wczytano żadnego poprawnego chunku joblib!")

print(f"Wczytano {len(chunks)}/{len(chunk_files)} poprawnych chunków.")

# -------------------------------
# Połącz dane
# -------------------------------
X_list, y_list = [], []
for X_chunk, y_chunk in chunks:
    X_list.append(X_chunk)
    y_list.append(y_chunk)

X = np.vstack(X_list)
y = np.hstack(y_list)
print(f"Złączono dane: X={X.shape}, y={y.shape}")

# Skalowanie
if scaler is not None:
    X = scaler.transform(X)
    print("Dane zeskalowane.")

# -------------------------------
# Funkcja do trenowania i zapisywania modelu
# -------------------------------
def train_and_save_model(model, model_name):
    print(f"\nTrenowanie modelu: {model_name}")
    model.fit(X, y)
    path = os.path.join(MODEL_DIR, f"{model_name}.pkl")
    dump(model, path)  # używamy joblib
    print(f"Model {model_name} zapisany: {path}")

# -------------------------------
# Modele
# -------------------------------
models = {
    "RandomForest": RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42),
    "LogisticRegression": LogisticRegression(max_iter=1000, n_jobs=-1, random_state=42),
    "MLP": MLPClassifier(hidden_layer_sizes=(128,64), max_iter=300, random_state=42)
}

# -------------------------------
# Trenuj wszystkie modele
# -------------------------------
for name, model in models.items():
    train_and_save_model(model, name)

print("\nWszystkie modele wytrenowane i zapisane.")
