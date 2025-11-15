#!/usr/bin/env python3
"""
evaluate_ensemble.py

Ewaluacja predykcji ensemble:
- Accuracy
- F1-score
- Classification report
- Confusion matrix (zapis do reports/)

Obsługa brakujących wartości (NaN) w pred_ensemble.
"""

import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import os
import numpy as np

# Ścieżki
y_test_path = "../data/y_test.csv"
predictions_path = "../data/predictions.csv"
reports_dir = "../reports/"
os.makedirs(reports_dir, exist_ok=True)

# Wczytanie danych
y_true = pd.read_csv(y_test_path).values.ravel()
preds_df = pd.read_csv(predictions_path)

if "pred_ensemble" not in preds_df.columns:
    raise ValueError("Brak kolumny 'pred_ensemble' w predictions.csv. Upewnij się, że włączyłeś flagę --ensemble w predict_models.py")

# Usuń wiersze z NaN w pred_ensemble
y_pred = preds_df["pred_ensemble"].values
valid_mask = ~pd.isna(y_pred)
y_true_valid = y_true[valid_mask]
y_pred_valid = y_pred[valid_mask].astype(int)  # konwersja do int

print(f"Przetwarzanie {len(y_pred_valid)} wierszy (NaN odrzucone: {len(y_pred) - len(y_pred_valid)})\n")

# Metryki
acc = accuracy_score(y_true_valid, y_pred_valid)
f1 = f1_score(y_true_valid, y_pred_valid, average="weighted")

print(f"Accuracy ensemble: {acc:.4f}")
print(f"F1-score ensemble: {f1:.4f}\n")
print("Classification report:\n")
print(classification_report(y_true_valid, y_pred_valid))

# Confusion matrix
cm = confusion_matrix(y_true_valid, y_pred_valid)
plt.figure(figsize=(8,6))
sns.heatmap(cm, annot=True, fmt='d', cmap="Blues")
plt.xlabel("Predicted")
plt.ylabel("True")
plt.title("Confusion Matrix - Ensemble")
plt.tight_layout()
cm_path = os.path.join(reports_dir, "confusion_matrix_ensemble.png")
plt.savefig(cm_path)
print(f"\n🎉 Confusion matrix saved to: {cm_path}")
plt.close()
