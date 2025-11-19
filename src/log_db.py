import sqlite3
from datetime import datetime
from typing import Optional, List, Dict
from config_and_db import DB_PATH, init_db

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
    db_path = db_path or DB_PATH
    init_db()  # upewniamy się, że baza jest gotowa
    return db_path

def log_run(script: str,
            n_rows: Optional[int],
            models_used: str,
            ensemble_used: bool,
            accuracy: Optional[float] = None,
            f1_score: Optional[float] = None,
            notes: Optional[str] = None,
            db_path: Optional[str] = None) -> None:
    db_path = db_path or DB_PATH
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
    db_path = db_path or DB_PATH
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
