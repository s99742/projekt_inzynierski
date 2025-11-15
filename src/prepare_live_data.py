#!/usr/bin/env python3
"""
prepare_live_data.py

Moduł do przetwarzania pakietów zapisanych w SQLite w czasie rzeczywistym.
Tworzy DataFrame gotowy do predykcji ML (cechy takie jak src/dst IP, porty, protokół, długość pakietu).
"""

import sqlite3
import pandas as pd
import os

DB_PATH = "../logs/project_logs.db"

# --- FUNKCJA POBIERANIA PAKIETÓW ---
def fetch_new_packets(last_id=0):
    """
    Pobiera pakiety z bazy SQLite większe niż last_id.
    Zwraca DataFrame oraz max id w pobranych rekordach.
    """
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"Baza nie istnieje: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    query = f"""
        SELECT * FROM packets
        WHERE id > {last_id}
        ORDER BY id ASC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()

    if df.empty:
        return pd.DataFrame(), last_id

    new_last_id = df["id"].max()
    return df, new_last_id

# --- FUNKCJA PRZYGOTOWUJĄCA CECHY ---
def process_features(df):
    """
    Zamienia surowe dane na cechy ML:
    - src_port, dst_port jako int
    - protocol jako int
    - długość pakietu
    - (opcjonalnie) kodowanie IP w prosty sposób
    """
    if df.empty:
        return df

    df_processed = pd.DataFrame()
    # Numery portów
    df_processed["src_port"] = df["src_port"].fillna(0).astype(int)
    df_processed["dst_port"] = df["dst_port"].fillna(0).astype(int)
    # Protokół jako int
    df_processed["protocol"] = df["protocol"].fillna(0).astype(int)
    # Długość pakietu
    df_processed["length"] = df["length"].astype(int)

    # Proste kodowanie IP (ostatni oktet)
    def ip_to_int(ip):
        try:
            return int(ip.split(".")[-1])
        except:
            return 0

    df_processed["src_ip_octet"] = df["src_ip"].apply(ip_to_int)
    df_processed["dst_ip_octet"] = df["dst_ip"].apply(ip_to_int)

    return df_processed

# --- DOPASOWANIE CECH DO MODELU ---
def ensure_features(input_df, features_csv):
    """
    Dopasuj kolumny input_df do listy cech z features_csv.
    - brakujące kolumny uzupełni 0
    - dodatkowe kolumny usunie
    - zwróci DataFrame z kolumnami w kolejności zgodnej z modelem
    """
    if not os.path.exists(features_csv):
        raise FileNotFoundError(f"Plik z cechami nie znaleziony: {features_csv}")

    feat_df = pd.read_csv(features_csv, nrows=0)
    required_cols = list(feat_df.columns)
    # Usuń kolumnę Label jeśli istnieje
    if "Label" in input_df.columns:
        input_df = input_df.drop(columns=["Label"])
    # Dodaj brakujące kolumny
    for c in required_cols:
        if c not in input_df.columns:
            input_df[c] = 0
    # Usuń dodatkowe kolumny
    extra = [c for c in input_df.columns if c not in required_cols]
    if extra:
        input_df = input_df.drop(columns=extra)
    # Uporządkuj kolumny według kolejności
    input_df = input_df[required_cols]
    return input_df



# --- PRZYKŁADOWE UŻYCIE ---
if __name__ == "__main__":
    last_id = 0
    print("Pobieranie nowych pakietów z bazy...")

    df_new, last_id = fetch_new_packets(last_id)
    if df_new.empty:
        print("Brak nowych pakietów.")
    else:
        features = process_features(df_new)
        print("Nowe pakiety przetworzone do cech ML:")
        print(features.head(10))
