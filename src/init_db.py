#!/usr/bin/env python3
"""
init_db.py

Uruchom jednokrotnie, aby utworzyć bazę logs/project_logs.db i tabelę logs.
"""

import os
from log_db import create_db

if __name__ == "__main__":
    db_path = create_db()  # użyje DEFAULT_DB_PATH
    print(f"✅ Baza danych gotowa: {db_path}")
