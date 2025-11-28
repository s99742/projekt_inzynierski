#!/usr/bin/env python3
"""
config_and_db.py

Centralny plik konfiguracji i inicjalizacji bazy danych dla projektu:
- Definiuje ścieżki do danych, modeli, logów
- Tworzy bazy SQLite i potrzebne tabele (w tym flow_logs)
- Automatycznie wykrywa aktywny interfejs sieciowy (fallback 'lo')
"""

import os
import sqlite3
import psutil
import socket

# -------------------------------------------------------------
# FUNKCJA AUTOMATYCZNEGO WYKRYWANIA INTERFEJSU
# -------------------------------------------------------------
def detect_active_interface():
    ignore = {"lo", "docker0", "virbr0"}
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception:
        return None
    for iface, iface_addrs in addrs.items():
        if iface in ignore:
            continue
        iface_stat = stats.get(iface)
        if not iface_stat or not iface_stat.isup:
            continue
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and addr.address and addr.address != "127.0.0.1":
                return iface
    return None

# -------------------------------------------------------------
# ŚCIEŻKI PROJEKTU
# -------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_DIR       = os.path.join(BASE_DIR, "data")
RAW_DATA_DIR   = os.path.join(DATA_DIR, "CICIDS2017")
CLEAN_DATA_DIR = os.path.join(DATA_DIR, "cleaned")
NORMALIZED_DATA_DIR = os.path.join(DATA_DIR, "normalized")   # folder z chunkami

MODEL_DIR      = os.path.join(BASE_DIR, "models")
REPORTS_DIR    = os.path.join(BASE_DIR, "reports")
LOGS_DIR       = os.path.join(BASE_DIR, "logs")
SRC_DIR        = os.path.join(BASE_DIR, "src")

# -------------------------------------------------------------
# Pickle i aliasy do znormalizowanych danych
# -------------------------------------------------------------
# Zamiast pojedynczych plików pickle, teraz foldery z chunkami
X_TRAIN_CHUNKS = os.path.join(NORMALIZED_DATA_DIR, "*_X_train_chunk*.pkl")
Y_TRAIN_CHUNKS = os.path.join(NORMALIZED_DATA_DIR, "*_y_train_chunk*.pkl")
X_TEST_CHUNKS  = os.path.join(NORMALIZED_DATA_DIR, "*_X_test_chunk*.pkl")
Y_TEST_CHUNKS  = os.path.join(NORMALIZED_DATA_DIR, "*_y_test_chunk*.pkl")
SCALER_NORM_PATH = os.path.join(NORMALIZED_DATA_DIR, "scaler.pkl")


# Testy
DDOS_CSV_PATH = os.path.join(CLEAN_DATA_DIR, "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX_clean.csv")
BENIGN_CSV_PATH = os.path.join(CLEAN_DATA_DIR, "Friday-WorkingHours-Morning.pcap_ISCX_clean.csv")

# Baza SQLite
DB_PATH = os.path.join(LOGS_DIR, "project_logs.db")

# -------------------------------------------------------------
# AUTOMATYCZNIE WYKRYTY INTERFEJS (fallback 'lo')
# -------------------------------------------------------------
_detected_iface = detect_active_interface()
DEFAULT_INTERFACE = detect_active_interface()
print(f"Wykryty interfejs sieciowy: {DEFAULT_INTERFACE}")

# -------------------------------------------------------------
# TWORZENIE KATALOGÓW
# -------------------------------------------------------------
for path in [DATA_DIR, CLEAN_DATA_DIR, NORMALIZED_DATA_DIR, MODEL_DIR, LOGS_DIR, REPORTS_DIR]:
    os.makedirs(path, exist_ok=True)

# -------------------------------------------------------------
# INICJALIZACJA BAZY DANYCH
# -------------------------------------------------------------
def init_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

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

    c.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol INTEGER,
        length INTEGER
    )
    """)

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

    c.execute("""
    CREATE TABLE IF NOT EXISTS flow_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol INTEGER,
        prediction TEXT,
        decision TEXT
    )
    """)

    conn.commit()
    conn.close()
    print(f"Baza danych utworzona lub zaktualizowana: {db_path}")

# -------------------------------------------------------------
# URUCHOMIE PRZY IMPORT/EXEC
# -------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    print("Wszystkie katalogi i tabele gotowe do użycia w projekcie")
