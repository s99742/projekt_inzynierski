#!/usr/bin/env python3
"""
train_model_packet.py
Trenowanie modeli ML na packet-level feature extraction.
"""

import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, classification_report

MODEL_DIR = "../models/"
os.makedirs(MODEL_DIR, exist_ok=True)

def main():
    X = pd.read_csv("../data/X_packet.csv")
    y = pd.read_csv("../data/y_packet.csv").values.ravel()

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    models = {
        "RandomForest_packet": RandomForestClassifier(n_estimators=200, n_jobs=-1),
        "LogisticRegression_packet": LogisticRegression(max_iter=1000, n_jobs=-1),
        "HGB_packet": HistGradientBoostingClassifier(max_iter=350)
    }

    for name, model in models.items():
        print(f"\n➡️ Trenowanie modelu: {name}")
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average="weighted")

        print(f"Accuracy: {acc:.4f}")
        print(f"F1-score: {f1:.4f}")
        print("\nClassification report:")
        print(classification_report(y_test, y_pred))

        path = os.path.join(MODEL_DIR, f"{name}.pkl")
        joblib.dump(model, path)
        print(f"📦 Model zapisany: {path}")

if __name__ == "__main__":
    main()
