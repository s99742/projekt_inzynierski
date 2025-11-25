#!/usr/bin/env python3
import os, sys, threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk
from joblib import load
import sqlite3
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from config_and_db import DB_PATH, MODEL_DIR, DEFAULT_INTERFACE, init_db
init_db()

from realtime_flow_predict import process_packet

running = False
models_loaded = {}

MODEL_FILES = {
    "rf": os.path.join(MODEL_DIR, "RandomForest_pipeline.pkl"),
    "lr": os.path.join(MODEL_DIR, "LogisticRegression_pipeline.pkl"),
    "mlp": os.path.join(MODEL_DIR, "MLP_pipeline.pkl")
}

for key, path in MODEL_FILES.items():
    try:
        models_loaded[key] = load(path)
        print(f"✅ Załadowano model: {key}")
    except Exception as e:
        print(f"❌ Nie udało się załadować modelu {key}: {e}")

# --- fetch logs ---
def fetch_latest_logs(limit=50):
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(f"SELECT * FROM flow_logs ORDER BY id DESC LIMIT {limit}", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

# --- GUI ---
class FirewallGUI:
    def __init__(self, root):
        self.root = root
        root.title("Realtime Firewall GUI")

        self.rf_var = tk.BooleanVar(value=True)
        self.lr_var = tk.BooleanVar(value=True)
        self.mlp_var = tk.BooleanVar(value=True)

        frame_models = tk.LabelFrame(root, text="Modele")
        frame_models.pack(fill="x", padx=5, pady=5)
        tk.Checkbutton(frame_models, text="RandomForest", variable=self.rf_var).pack(side="left")
        tk.Checkbutton(frame_models, text="LogisticRegression", variable=self.lr_var).pack(side="left")
        tk.Checkbutton(frame_models, text="MLP", variable=self.mlp_var).pack(side="left")

        frame_buttons = tk.Frame(root)
        frame_buttons.pack(fill="x", padx=5, pady=5)
        self.start_btn = tk.Button(frame_buttons, text="Start", command=self.start_sniff)
        self.start_btn.pack(side="left", padx=5)
        self.stop_btn = tk.Button(frame_buttons, text="Stop", command=self.stop_sniff, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        frame_logs = tk.LabelFrame(root, text="Flowy")
        frame_logs.pack(fill="both", expand=True, padx=5, pady=5)
        columns = ["timestamp","src_ip","dst_ip","src_port","dst_port","protocol","pkt_count","prediction","decision"]
        self.tree = ttk.Treeview(frame_logs, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
        self.tree.pack(fill="both", expand=True)
        self.update_logs_periodically()

    def add_flow_to_tree(self, flow_key, pkt_count, preds, decision):
        ts = datetime.now().isoformat()
        self.tree.insert("", 0, values=(
            ts,
            flow_key[0], flow_key[1], flow_key[2], flow_key[3], flow_key[4],
            pkt_count, str(preds), decision
        ))

    def update_logs_periodically(self):
        # zachowujemy wszystkie flowy, tylko dorzucamy nowe z DB
        df = fetch_latest_logs(50)
        existing_ids = set(self.tree.get_children())
        for _, row in df.iterrows():
            # unikamy duplikatów
            self.tree.insert("", "end", values=(
                row.get("timestamp"), row.get("src_ip"), row.get("dst_ip"),
                row.get("src_port"), row.get("dst_port"), row.get("protocol"),
                "-", row.get("prediction"), row.get("decision")
            ))
        self.root.after(2000, self.update_logs_periodically)

    def start_sniff(self):
        global running
        if running: return
        running = True
        enabled_models = {}
        if self.rf_var.get() and "rf" in models_loaded: enabled_models["rf"] = models_loaded["rf"]
        if self.lr_var.get() and "lr" in models_loaded: enabled_models["lr"] = models_loaded["lr"]
        if self.mlp_var.get() and "mlp" in models_loaded: enabled_models["mlp"] = models_loaded["mlp"]

        from scapy.all import sniff
        self.sniff_thread = threading.Thread(
            target=lambda: sniff(
                iface=DEFAULT_INTERFACE,
                prn=lambda pkt: process_packet(pkt, models=enabled_models, gui_callback=self.add_flow_to_tree),
                store=False
            ),
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


if __name__ == "__main__":
    root = tk.Tk()
    gui = FirewallGUI(root)
    root.mainloop()
