#!/usr/bin/env python3
"""
config_and_db.py

Centralny plik konfiguracji i inicjalizacji bazy danych dla projektu:
- Definiuje ścieżki do danych, modeli, logów
- Tworzy bazy SQLite i potrzebne tabele
- Może być importowany we wszystkich skryptach projektu
"""

import os
import sqlite3

# -------------------------------------------------------------
# ŚCIEŻKI PROJEKTU
# -------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # katalog główny projektu

DATA_DIR       = os.path.join(BASE_DIR, "data")
RAW_DATA_DIR   = os.path.join(DATA_DIR, "CICIDS2017")
CLEAN_DATA_DIR = os.path.join(DATA_DIR, "cleaned")
MODEL_DIR      = os.path.join(BASE_DIR, "models")
REPORTS_DIR    = os.path.join(BASE_DIR, "reports")
LOGS_DIR       = os.path.join(BASE_DIR, "logs")

# Pliki pickle / csv
SCALER_PATH      = os.path.join(DATA_DIR, "scaler.pkl")
X_TRAIN_CSV      = os.path.join(DATA_DIR, "X_train.csv")
X_TRAIN_PKL      = os.path.join(DATA_DIR, "X_train.pkl")
X_TEST_PKL       = os.path.join(DATA_DIR, "X_test.pkl")
Y_TRAIN_PKL      = os.path.join(DATA_DIR, "y_train.pkl")
Y_TEST_PKL       = os.path.join(DATA_DIR, "y_test.pkl")
PREDICTIONS_PATH = os.path.join(DATA_DIR, "predictions.csv")

# Baza SQLite
DB_PATH = os.path.join(LOGS_DIR, "project_logs.db")

# Domyślny interfejs sieciowy
DEFAULT_INTERFACE = "wlp3s0"  # zmień w razie potrzeby

# -------------------------------------------------------------
# TWORZENIE KATALOGÓW
# -------------------------------------------------------------
for path in [DATA_DIR, CLEAN_DATA_DIR, MODEL_DIR, LOGS_DIR, REPORTS_DIR]:
    os.makedirs(path, exist_ok=True)

# -------------------------------------------------------------
# INICJALIZACJA BAZY DANYCH
# -------------------------------------------------------------
def init_db(db_path=DB_PATH):
    """Tworzy wszystkie potrzebne tabele w bazie SQLite jeśli nie istnieją"""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # --- tabela logs ---
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        script TEXT,
        n_rows INTEGER,
        models_used TEXT,
        ensemble_used INTEGER,
        accuracy REAL,
        f1_score REAL,
        notes TEXT
    )
    """)

    # --- tabela packets ---
    c.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT,
        length INTEGER
    )
    """)

    # --- tabela firewall_rules ---
    c.execute("""
    CREATE TABLE IF NOT EXISTS firewall_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        added_at TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol INTEGER,
        action TEXT,
        expiry TEXT,
        reason TEXT
    )
    """)

    conn.commit()
    conn.close()
    print(f"✅ Baza danych utworzona lub zaktualizowana: {db_path}")

# -------------------------------------------------------------
# AUTOMATYCZNE WYWOŁANIE PRZY URUCHOMIENIU PLIKU
# -------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    print("🌟 Wszystkie katalogi i tabele gotowe do użycia w projekcie")
