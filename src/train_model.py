#!/usr/bin/env python3
"""
train_model.py
Trenowanie modeli ML dla projektu CICIDS2017.
Po zakończeniu treningu każdy model jest logowany w SQLite.
"""

import pandas as pd
import joblib
import os
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix

from log_db import log_run, create_db

# Ścieżki
DATA_DIR = "../data/"
MODEL_DIR = "../models/"
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "project_logs.db")
os.makedirs(MODEL_DIR, exist_ok=True)

def main():
    create_db(DB_PATH)  # upewnij się, że baza istnieje

    X_train = pd.read_csv(os.path.join(DATA_DIR, "X_train.csv"))
    y_train = pd.read_csv(os.path.join(DATA_DIR, "y_train.csv")).values.ravel()
    X_test = pd.read_csv(os.path.join(DATA_DIR, "X_test.csv"))
    y_test = pd.read_csv(os.path.join(DATA_DIR, "y_test.csv")).values.ravel()

    models = {
        "RandomForest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "LogisticRegression": LogisticRegression(max_iter=1000, n_jobs=-1),
        "HGB": HistGradientBoostingClassifier(max_iter=200)
    }

    for name, model in models.items():
        print(f"\n➡️ Trenowanie modelu: {name}")
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        acc = float(accuracy_score(y_test, y_pred))
        f1 = float(f1_score(y_test, y_pred, average="weighted"))

        print("✅ Wyniki dla {}:".format(name))
        print(f"Accuracy: {acc:.4f}")
        print(f"F1-score: {f1:.4f}\n")
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))

        # Zapis modelu
        filepath = os.path.join(MODEL_DIR, f"{name}_cicids.pkl")
        joblib.dump(model, filepath)
        print(f"🎉 Model zapisany: {filepath}")

        # Log do DB
        try:
            log_run(script="train_model",
                    n_rows=int(X_train.shape[0]),
                    models_used=name,
                    ensemble_used=False,
                    accuracy=acc,
                    f1_score=f1,
                    notes=None,
                    db_path=DB_PATH)
        except Exception as e:
            print(f"⚠️ Błąd podczas logowania treningu do DB: {e}")

if __name__ == "__main__":
    main()
