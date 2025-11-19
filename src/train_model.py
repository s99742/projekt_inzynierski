#!/usr/bin/env python3
"""
train_model.py - Trenuje modele ML dla CICIDS2017 w pipeline z scalerem.
Nie używa imblearn. Obsługuje nierównowagę klas przez class_weight='balanced'.
Zapisuje pipeline jako jeden plik .pkl dla realtime predykcji.
"""

import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score, f1_score, confusion_matrix
from log_db import log_run, create_db

DATA_DIR = "../data/"
MODEL_DIR = "../models/"
DB_PATH = "../logs/project_logs.db"
os.makedirs(MODEL_DIR, exist_ok=True)

def main():
    create_db(DB_PATH)

    # Wczytanie danych i scalera
    X_train = pd.read_pickle(os.path.join(DATA_DIR, "X_train.pkl"))
    X_test  = pd.read_pickle(os.path.join(DATA_DIR, "X_test.pkl"))
    y_train = pd.read_pickle(os.path.join(DATA_DIR, "y_train.pkl")).values.ravel()
    y_test  = pd.read_pickle(os.path.join(DATA_DIR, "y_test.pkl")).values.ravel()
    scaler  = joblib.load(os.path.join(DATA_DIR, "scaler.pkl"))

    # Modele z class_weight='balanced' tam gdzie możliwe
    models = {
        "RandomForest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced'),
        "LogisticRegression": LogisticRegression(max_iter=1000, n_jobs=-1, class_weight='balanced'),
        "HGB": HistGradientBoostingClassifier(max_iter=200)
    }

    for name, model in models.items():
        print(f"\n➡️ Trenowanie modelu: {name}")
        pipeline = Pipeline([
            ('scaler', scaler),
            ('clf', model)
        ])
        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average='weighted')

        print(f"✅ Wyniki dla {name}:")
        print(f"Accuracy: {acc:.4f}")
        print(f"F1-score: {f1:.4f}")
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))

        # Zapis pipeline
        filepath = os.path.join(MODEL_DIR, f"{name}_pipeline.pkl")
        joblib.dump(pipeline, filepath)
        print(f"🎉 Pipeline zapisany: {filepath}")

        # Log do bazy
        try:
            log_run(script="train_model",
                    n_rows=int(X_train.shape[0]),
                    models_used=name,
                    ensemble_used=False,
                    accuracy=acc,
                    f1_score=f1,
                    notes="Pipeline ML bez imblearn, class_weight='balanced'",
                    db_path=DB_PATH)
        except Exception as e:
            print(f"⚠️ Błąd logowania: {e}")

if __name__ == "__main__":
    main()
