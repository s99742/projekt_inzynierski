#!/usr/bin/env python3
"""
log_db.py

Moduł pomocniczy do logowania uruchomień do SQLite.
Funkcje:
 - create_db(db_path)         : tworzy plik bazy i tabelę logs (jeśli nie istnieje)
 - log_run(...)               : zapisuje wpis logu
 - fetch_logs(limit=100)      : zwraca ostatnie wpisy (lista dict)
"""

import sqlite3
import os
from datetime import datetime
from typing import Optional, List, Dict

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "project_logs.db")

CREATE_TABLE_SQL = """
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
);
"""

def create_db(db_path: Optional[str] = None) -> str:
    """
    Tworzy katalog logs i plik bazy jeśli nie istnieje oraz tabelę logs.
    Zwraca ścieżkę do pliku bazy.
    """
    db_path = db_path or DEFAULT_DB_PATH
    logs_dir = os.path.dirname(db_path)
    os.makedirs(logs_dir, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        c = conn.cursor()
        c.execute(CREATE_TABLE_SQL)
        conn.commit()
    finally:
        conn.close()
    return db_path

def log_run(script: str,
            n_rows: Optional[int],
            models_used: str,
            ensemble_used: bool,
            accuracy: Optional[float] = None,
            f1_score: Optional[float] = None,
            notes: Optional[str] = None,
            db_path: Optional[str] = None) -> None:
    """
    Zapisuje uruchomienie/skrócony wynik do tabeli logs.
    - script: nazwa skryptu (predict_models, train_model, ...)
    - n_rows: liczba wczytanych wierszy wejściowych (może być None)
    - models_used: "rf,lr,hgb"
    - ensemble_used: True/False
    - accuracy, f1_score: wartości metryk (lub None)
    - notes: dowolny tekst (błędy, komentarze)
    """
    db_path = db_path or DEFAULT_DB_PATH
    # upewnij się, że baza jest dostępna
    create_db(db_path)

    conn = sqlite3.connect(db_path)
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO logs (timestamp, script, n_rows, models_used, ensemble_used, accuracy, f1_score, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), script, n_rows, models_used, int(bool(ensemble_used)), accuracy, f1_score, notes))
        conn.commit()
    finally:
        conn.close()

def fetch_logs(limit: int = 100, db_path: Optional[str] = None) -> List[Dict]:
    """
    Pobiera ostatnie wpisy z logs (domyślnie 100).
    Zwraca listę słowników.
    """
    db_path = db_path or DEFAULT_DB_PATH
    if not os.path.exists(db_path):
        return []

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
