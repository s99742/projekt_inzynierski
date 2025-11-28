import os
import joblib
from sklearn.metrics import accuracy_score
import numpy as np

BASE = "/home/jakub-wasiewicz/Desktop/inzynierka/projekt_inzynierski"
MODEL_PATH = BASE + "/models/MLP_pipeline.pkl"   # albo MLP_pipeline.pkl
SCALER_PATH = BASE + "/data/normalized/scaler.pkl"
DATA_DIR = BASE + "/data/normalized"

# wczytanie modelu i scalera
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# znajdź wszystkie pliki chunków
chunks = sorted([
    os.path.join(DATA_DIR, f)
    for f in os.listdir(DATA_DIR)
    if f.endswith(".pkl") and "chunk" in f
])

print("Znalezione chunki:")
for c in chunks:
    print(" •", c)

acc_list = []

print("\nStart testów...\n")

for chunk_path in chunks:
    X, y = joblib.load(chunk_path)

    # szybki podzbiór
    X_small = X[:2000]
    y_small = y[:2000]

    # skalowanie
    try:
        X_small = scaler.transform(X_small)
    except:
        print("Skaler nie pasuje do danych — pomijam ten chunk:", chunk_path)
        continue

    # predykcja
    y_pred = model.predict(X_small)
    acc = accuracy_score(y_small, y_pred)
    acc_list.append(acc)

    print(f"{os.path.basename(chunk_path)} → accuracy: {acc:.4f}")

# podsumowanie
if acc_list:
    print("\n====================================")
    print(f"Średnie accuracy: {np.mean(acc_list):.4f}")
    print("====================================\n")
else:
    print("Brak wyników — coś poszło nie tak.")
