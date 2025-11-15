import pandas as pd
import numpy as np
import glob
import os
import gc
from sklearn.preprocessing import LabelEncoder

# -------------------------------------------------------------
# Skrypt do wstępnego przetwarzania danych CICIDS2017
# Przetwarza każdy plik osobno, konwertuje typy danych i zwalnia pamięć.
# -------------------------------------------------------------

# Ścieżki
RAW_PATH = "../data/CICIDS2017/"  # oryginalne pliki CSV
CLEAN_PATH = "../data/cleaned/"  # docelowy folder dla oczyszczonych plików

# Utwórz folder docelowy, jeśli nie istnieje
os.makedirs(CLEAN_PATH, exist_ok=True)

# Znajdź wszystkie pliki CSV
files = glob.glob(os.path.join(RAW_PATH, "*.csv"))
print(f"Znaleziono {len(files)} plików do przetworzenia.\n")

# Inicjalizacja enkodera
le = LabelEncoder()

for f in files:
    print(f"➡️  Przetwarzanie pliku: {os.path.basename(f)}")

    try:
        # Wczytaj dane w trybie low_memory=True (szybciej, mniej RAM)
        chunk = pd.read_csv(f, low_memory=True)

        # Usuń spacje z nazw kolumn
        chunk.columns = chunk.columns.str.strip()

        # Zamień nieskończoności i usuń wiersze z brakami
        chunk = chunk.replace([np.inf, -np.inf], np.nan)
        chunk = chunk.dropna()

        # Jeśli nie ma etykiet, pomiń plik
        if 'Label' not in chunk.columns:
            print(f"⚠️  Brak kolumny 'Label' w {os.path.basename(f)} – pomijam.\n")
            continue

        # Konwersja typów danych (float64 → float32, int64 → int32)
        float_cols = chunk.select_dtypes(include=['float64']).columns
        int_cols = chunk.select_dtypes(include=['int64']).columns

        chunk[float_cols] = chunk[float_cols].astype('float32')
        chunk[int_cols] = chunk[int_cols].astype('int32')

        # Zakoduj kolumnę etykiety
        chunk['Label'] = le.fit_transform(chunk['Label'])

        # Zapisz oczyszczony plik
        clean_name = os.path.basename(f).replace(".csv", "_clean.csv")
        clean_path = os.path.join(CLEAN_PATH, clean_name)
        chunk.to_csv(clean_path, index=False)

        print(f"✅ Zapisano: {clean_name} ({chunk.shape[0]} wierszy)\n")

        # Zwolnij pamięć po każdym pliku
        del chunk
        gc.collect()

    except Exception as e:
        print(f"❌ Błąd przy przetwarzaniu {os.path.basename(f)}: {e}\n")
        gc.collect()

print("🎉 Przetwarzanie zakończone!")
print(f"Oczyszczone pliki zapisano w folderze: {CLEAN_PATH}")