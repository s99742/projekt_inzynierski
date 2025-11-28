#!/usr/bin/env python3
"""
normalize_dataset.py - Normalizacja danych CICIDS2017 po chunkach.
Obsługuje duże pliki CSV i zapisuje znormalizowane dane do joblib.
"""

import os
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm
from config_and_db import DATA_DIR, CLEAN_DATA_DIR

CHUNK_SIZE = 50000  # liczba wierszy na chunk
NORMALIZED_DIR = os.path.join(DATA_DIR, "normalized")
os.makedirs(NORMALIZED_DIR, exist_ok=True)

def normalize_csv_files():
    scaler = StandardScaler()
    all_files = [os.path.join(CLEAN_DATA_DIR, f) for f in os.listdir(CLEAN_DATA_DIR) if f.endswith(".csv")]

    # --- FIT scaler ---
    print("Fitowanie Scalera po wszystkich chunkach...")
    for file_path in all_files:
        print(f"Przetwarzanie: {os.path.basename(file_path)}")
        for chunk in tqdm(pd.read_csv(file_path, chunksize=CHUNK_SIZE), desc="Chunks FIT", unit="chunk"):
            X = chunk.drop(columns=["Label"]).replace([float('inf'), -float('inf')], float('nan')).fillna(0)
            scaler.partial_fit(X)

    # Zapisz fitowany scaler do jednego pliku
    scaler_path = os.path.join(NORMALIZED_DIR, "scaler.pkl")
    joblib.dump(scaler, scaler_path)
    print(f"Zapisano fitowany scaler: {scaler_path}")

    # --- TRANSFORM i zapis do joblib ---
    print("Transformacja danych i zapis znormalizowanych chunków...")
    for file_path in all_files:
        basename = os.path.splitext(os.path.basename(file_path))[0]
        for i, chunk in enumerate(tqdm(pd.read_csv(file_path, chunksize=CHUNK_SIZE), desc=f"{basename}", unit="chunk")):
            X = chunk.drop(columns=["Label"]).replace([float('inf'), -float('inf')], float('nan')).fillna(0)
            X_scaled = scaler.transform(X)
            y = chunk["Label"].apply(lambda x: 0 if x == "BENIGN" else 1).values
            chunk_path = os.path.join(NORMALIZED_DIR, f"{basename}_chunk{i}.pkl")
            joblib.dump((X_scaled, y), chunk_path)
        print(f"Zapisano {i+1} chunków dla {basename}")

if __name__ == "__main__":
    normalize_csv_files()
