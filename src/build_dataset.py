import pandas as pd
import numpy as np
import glob
import os
import gc
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# -------------------------------------------------------------
# Build_dataset.py - tworzy gotowe zbiory X_train / X_test / y_train / y_test
# z oczyszczonych plików CICIDS2017.
# Działa na próbce danych, aby uniknąć freezów.
# -------------------------------------------------------------

CLEAN_PATH = "../data/cleaned/"
OUT_PATH = "../data/"
SAMPLE_SIZE = 500_000  # liczba wierszy do użycia w próbce

# Znajdź wszystkie oczyszczone pliki
files = glob.glob(os.path.join(CLEAN_PATH, "*_clean.csv"))
print(f"Znaleziono {len(files)} oczyszczonych plików.\n")

# Wczytaj po kolei, przetwórz i dodaj do list
data_parts = []
for f in files:
    print(f"➡️  Wczytuję {os.path.basename(f)}")
    df = pd.read_csv(f, low_memory=False)
    # Usuń spacje z nazw kolumn
    df.columns = df.columns.str.strip()
    # Konwersja typów danych
    float_cols = df.select_dtypes(include=['float64']).columns
    int_cols = df.select_dtypes(include=['int64']).columns
    df[float_cols] = df[float_cols].astype('float32')
    df[int_cols] = df[int_cols].astype('int32')
    df['Label'] = df['Label'].astype('int8')
    data_parts.append(df)
    del df
    gc.collect()

# Połącz wszystkie pliki
data = pd.concat(data_parts, ignore_index=True)
del data_parts
gc.collect()

# Jeśli zbiór jest zbyt duży, weź próbkę
if data.shape[0] > SAMPLE_SIZE:
    data = data.sample(n=SAMPLE_SIZE, random_state=42)
    print(f"ℹ️  Używam próbki {SAMPLE_SIZE} wierszy z pełnego zbioru.\n")

print(f"✅ Dane gotowe: {data.shape[0]} wierszy, {data.shape[1]} kolumn")

# Podział na cechy i etykiety
X = data.drop(columns=['Label'])
y = data['Label']
del data
gc.collect()

# Podział na train/test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
del X, y
gc.collect()

print(f"🔹 X_train: {X_train.shape}, X_test: {X_test.shape}")

# Normalizacja cech
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
del X_train, X_test
gc.collect()

# Zapis gotowych zbiorów
pd.DataFrame(X_train_scaled).to_csv(os.path.join(OUT_PATH, "X_train.csv"), index=False)
pd.DataFrame(X_test_scaled).to_csv(os.path.join(OUT_PATH, "X_test.csv"), index=False)
pd.DataFrame(y_train).to_csv(os.path.join(OUT_PATH, "y_train.csv"), index=False)
pd.DataFrame(y_test).to_csv(os.path.join(OUT_PATH, "y_test.csv"), index=False)

print("🎉 Zapisano gotowe zbiory w folderze data/:")
print("   X_train.csv, X_test.csv, y_train.csv, y_test.csv")
