#!/usr/bin/env python3
"""
prepare_cicids.py

Tworzy folder cleaned z CICIDS2017.
- Streaming, brak freeze
- Mapuje wszystkie attacky na 'ATTACK', zostawia 'BENIGN'
- Minimalne oczyszczanie (usunięcie brakujących Label)
"""

import os
import pandas as pd
from tqdm import tqdm
from config_and_db import DATA_DIR, CLEAN_DATA_DIR

RAW_DIR = os.path.join(DATA_DIR, "CICIDS2017")
os.makedirs(CLEAN_DATA_DIR, exist_ok=True)
CHUNKSIZE = 50_000

def clean_csv_file(input_path, output_path):
    chunks = pd.read_csv(input_path, chunksize=CHUNKSIZE, header=0)
    cleaned_chunks = []

    for chunk in chunks:
        # Usuń wiersze bez Label
        if 'Label' not in chunk.columns:
            # czasem kolumna może mieć spacje
            chunk.columns = [c.strip() for c in chunk.columns]

        if 'Label' not in chunk.columns:
            raise ValueError(f"❌ Brak kolumny Label w pliku: {input_path}")

        chunk = chunk.dropna(subset=['Label'])

        # Mapowanie wszystkich ataków na 'ATTACK'
        chunk['Label'] = chunk['Label'].apply(lambda x: 'BENIGN' if str(x).upper()=='BENIGN' else 'ATTACK')

        cleaned_chunks.append(chunk)

    if cleaned_chunks:
        df_cleaned = pd.concat(cleaned_chunks, ignore_index=True)
        df_cleaned.to_csv(output_path, index=False)

def main():
    csv_files = [f for f in os.listdir(RAW_DIR) if f.endswith(".csv")]
    print(f"📡 Przetwarzanie {len(csv_files)} plików z CICIDS2017...")

    for f in tqdm(csv_files, desc="Pliki CSV"):
        input_path = os.path.join(RAW_DIR, f)
        output_path = os.path.join(CLEAN_DATA_DIR, f.replace(".csv", "_clean.csv"))
        clean_csv_file(input_path, output_path)

    print(f"Czyszczenie zakończone. Pliki zapisane w {CLEAN_DATA_DIR}")

if __name__ == "__main__":
    main()
