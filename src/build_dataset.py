#!/usr/bin/env python3
"""
build_dataset.py - Tworzy gotowe zbiory treningowe/testowe dla CICIDS2017.
Nie używa imblearn. Obsługuje nierównowagę klas przez class_weight w modelach.
Zapisuje X_train, X_test, y_train, y_test oraz scaler.pkl.
"""

import pandas as pd
import numpy as np
import glob
import os
import gc
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from config_and_db import CLEAN_DATA_DIR, DATA_DIR

SAMPLE_SIZE = 500_000  # Liczba wierszy do próbki

# Wczytaj wszystkie oczyszczone pliki
files = glob.glob(os.path.join(CLEAN_DATA_DIR, "*_clean.csv"))
print(f"Znaleziono {len(files)} oczyszczonych plików.\n")

data_parts = []
for f in files:
    print(f"➡️  Wczytuję {os.path.basename(f)}")
    df = pd.read_csv(f, low_memory=False)
    df.columns = df.columns.str.strip()

    float_cols = df.select_dtypes(include=['float64']).columns
    int_cols = df.select_dtypes(include=['int64']).columns
    df[float_cols] = df[float_cols].astype('float32')
    df[int_cols] = df[int_cols].astype('int32')
    df['Label'] = df['Label'].astype('int8')

    for col in ['Flow ID', 'Src IP', 'Dst IP', 'Timestamp']:
        if col in df.columns:
            df.drop(columns=[col], inplace=True)

    data_parts.append(df)
    del df
    gc.collect()

data = pd.concat(data_parts, ignore_index=True)
del data_parts
gc.collect()

if data.shape[0] > SAMPLE_SIZE:
    data = data.sample(n=SAMPLE_SIZE, random_state=42)
    print(f"ℹ️ Używam próbki {SAMPLE_SIZE} wierszy.\n")

print(f"✅ Dane gotowe: {data.shape[0]} wierszy, {data.shape[1]} kolumn")

X = data.drop(columns=['Label'])
y = data['Label']
del data
gc.collect()

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
del X, y
gc.collect()

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
del X_train, X_test
gc.collect()

os.makedirs(DATA_DIR, exist_ok=True)
pd.DataFrame(X_train_scaled).to_pickle(os.path.join(DATA_DIR, "X_train.pkl"))
pd.DataFrame(X_test_scaled).to_pickle(os.path.join(DATA_DIR, "X_test.pkl"))
pd.DataFrame(y_train).to_pickle(os.path.join(DATA_DIR, "y_train.pkl"))
pd.DataFrame(y_test).to_pickle(os.path.join(DATA_DIR, "y_test.pkl"))
import joblib
joblib.dump(scaler, os.path.join(DATA_DIR, "scaler.pkl"))

print("🎉 Zapisano gotowe zbiory i scaler w folderze data/:")
