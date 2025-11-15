#!/usr/bin/env python3
"""
realtime_predict.py

Predykcja w czasie rzeczywistym dla pakietów przechwyconych w SQLite.
Wykorzystuje modele ML: RandomForest, LogisticRegression, HGB.
Zapisuje predykcje z powrotem do bazy (kolumna 'prediction').
"""

import os
import time
import joblib
import sqlite3
import pandas as pd
from prepare_live_data import fetch_new_packets, process_features

# --- KONFIGURACJA ---
DB_PATH = "../logs/project_logs.db"
MODEL_DIR = "../models/"
MODEL_FILES = {
    "rf": os.path.join(MODEL_DIR, "RandomForest_cicids.pkl"),
    "lr": os.path.join(MODEL_DIR, "LogisticRegression_cicids.pkl"),
    "hgb": os.path.join(MODEL_DIR, "HGB_cicids.pkl")
}
POLL_INTERVAL = 2  # sekundy pomiędzy sprawdzeniem nowych pakietów

# --- FUNKCJA ŁADUJĄCA MODELE ---
def load_models():
    models = {}
    for name, path in MODEL_FILES.items():
        if os.path.exists(path):
            models[name] = joblib.load(path)
            print(f"✅ Załadowano model: {name}")
        else:
            print(f"⚠️ Nie znaleziono modelu: {path}")
    return models

# --- FUNKCJA PREDYKCJI ---
def predict(models, X):
    """
    Zwraca słownik predykcji każdego modelu i predykcję ensemble (majority vote).
    """
    results = {}
    preds_list = []
    for name, model in models.items():
        pred = model.predict(X)
        results[name] = pred
        preds_list.append(pred)
    # Ensemble majority vote
    if preds_list:
        preds_stack = pd.DataFrame(preds_list).T
        ensemble = preds_stack.mode(axis=1)[0]
        results["ensemble"] = ensemble
    else:
        results["ensemble"] = pd.Series([None]*len(X))
    return results

# --- ZAPIS PREDYKCJI DO BAZY ---
def log_predictions(df_ids, predictions):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    for idx, row in enumerate(df_ids):
        pk_id = row
        ensemble_pred = int(predictions["ensemble"].iloc[idx])
        c.execute("""
            ALTER TABLE packets
            ADD COLUMN IF NOT EXISTS prediction INTEGER
        """)
        c.execute("""
            UPDATE packets
            SET prediction = ?
            WHERE id = ?
        """, (ensemble_pred, pk_id))
    conn.commit()
    conn.close()

# --- PĘTLA REALTIME ---
def main():
    models = load_models()
    if not models:
        print("❌ Brak modeli do predykcji. Zakończono.")
        return

    last_id = 0
    print("🌐 Uruchomiono realtime prediction...")
    try:
        while True:
            df_new, last_id = fetch_new_packets(last_id)
            if not df_new.empty:
                X = process_features(df_new)
                preds = predict(models, X)
                log_predictions(df_new["id"], preds)
                print(f"✅ Przetworzono {len(df_new)} pakietów, zapisano predykcje.")
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\n⏹ Zatrzymano realtime prediction.")

if __name__ == "__main__":
    main()
