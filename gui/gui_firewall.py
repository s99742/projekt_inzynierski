#!/usr/bin/env python3
"""
gui_firewall.py - GUI dla realtime firewall z flow-based predykcją
"""

import tkinter as tk
from tkinter import ttk
import threading
import sqlite3
import pandas as pd
from joblib import load
import time

# --- Import centralnej konfiguracji ---
from config_and_db import DB_PATH, MODEL_DIR, DEFAULT_INTERFACE, init_db

# --- Globalne flagi ---
running = False
models_loaded = {}

# --- Utwórz bazę jeśli nie istnieje ---
init_db()

# --- Załaduj modele ---
MODEL_FILES = {
    "rf": f"{MODEL_DIR}/RandomForest_cicids.pkl",
    "lr": f"{MODEL_DIR}/LogisticRegression_cicids.pkl",
    "hgb": f"{MODEL_DIR}/HGB_cicids.pkl"
}

for key, path in MODEL_FILES.items():
    try:
        models_loaded[key] = load(path)
        print(f"✅ Załadowano model: {key}")
    except Exception as e:
        print(f"⚠️ Nie udało się załadować modelu {key}: {e}")

# --- Import flow-based predykcji ---
from src.realtime_flow_predict import process_packet as flow_process_packet, models as global_models
global_models.update(models_loaded)

# --- Funkcje obsługi bazy danych ---
def fetch_latest_logs(limit=20):
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query(f"SELECT * FROM logs ORDER BY id DESC LIMIT {limit}", conn)
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    return df

# --- GUI ---
class FirewallGUI:
    def __init__(self, root):
        self.root = root
        root.title("Realtime Firewall GUI")

        # Modele
        self.rf_var = tk.BooleanVar(value=True)
        self.lr_var = tk.BooleanVar(value=True)
        self.hgb_var = tk.BooleanVar(value=True)

        frame_models = tk.LabelFrame(root, text="Włączone modele")
        frame_models.pack(fill="x", padx=5, pady=5)
        tk.Checkbutton(frame_models, text="RandomForest", variable=self.rf_var).pack(side="left")
        tk.Checkbutton(frame_models, text="LogisticRegression", variable=self.lr_var).pack(side="left")
        tk.Checkbutton(frame_models, text="HGB", variable=self.hgb_var).pack(side="left")

        # Start / Stop
        frame_buttons = tk.Frame(root)
        frame_buttons.pack(fill="x", padx=5, pady=5)
        self.start_btn = tk.Button(frame_buttons, text="Start Nasłuchu", command=self.start_sniff)
        self.start_btn.pack(side="left", padx=5)
        self.stop_btn = tk.Button(frame_buttons, text="Stop", command=self.stop_sniff, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        # Logi
        frame_logs = tk.LabelFrame(root, text="Ostatnie pakiety")
        frame_logs.pack(fill="both", expand=True, padx=5, pady=5)
        columns = ["id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "prediction", "decision"]
        self.tree = ttk.Treeview(frame_logs, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
        self.tree.pack(fill="both", expand=True)
        self.update_logs()

    def update_logs(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        df = fetch_latest_logs(20)
        for _, row in df.iterrows():
            self.tree.insert("", "end", values=(
                row.get("id"), row.get("timestamp"), row.get("src_ip"), row.get("dst_ip"),
                row.get("src_port"), row.get("dst_port"), row.get("protocol"),
                row.get("prediction"), row.get("decision")
            ))
        self.root.after(1000, self.update_logs)

    def start_sniff(self):
        global running
        if running:
            return
        running = True
        from scapy.all import sniff
        self.sniff_thread = threading.Thread(
            target=lambda: sniff(iface=DEFAULT_INTERFACE, prn=flow_process_packet, store=False),
            daemon=True
        )
        self.sniff_thread.start()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

    def stop_sniff(self):
        global running
        running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

# --- Uruchomienie GUI ---
if __name__ == "__main__":
    root = tk.Tk()
    gui = FirewallGUI(root)
    root.mainloop()
