#!/usr/bin/env python3
import os
import sys
import threading
import queue
from datetime import datetime
import tkinter as tk
from tkinter import ttk
from joblib import load
import sqlite3
import pandas as pd
import numpy as np
import random

# --------------------------------------------------------------------
# ŚCIEŻKI
# --------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from config_and_db import DB_PATH, MODEL_DIR, DEFAULT_INTERFACE, init_db
from realtime_flow_predict import process_packet

# inicjalizacja DB
init_db()

# --------------------------------------------------------------------
# MODELE
# --------------------------------------------------------------------
models_loaded = {}
MODEL_FILES = {
    "rf": os.path.join(MODEL_DIR, "RandomForest_pipeline.pkl"),
    "lr": os.path.join(MODEL_DIR, "LogisticRegression_pipeline.pkl"),
    "mlp": os.path.join(MODEL_DIR, "MLP_pipeline.pkl")
}

for key, path in MODEL_FILES.items():
    try:
        models_loaded[key] = load(path)
        print(f"Załadowano model: {key} ({path})")
    except Exception as e:
        print(f"Nie udało się załadować modelu {key}: {e}")

# --------------------------------------------------------------------
# CSV do generatorów
# --------------------------------------------------------------------
DATA_DIR = os.path.join(PROJECT_ROOT, "data", "normalized")
ATTACK_CSV = os.path.join(DATA_DIR, "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX_clean.csv")
BENIGN_CSV = os.path.join(DATA_DIR, "Friday-WorkingHours-Morning.pcap_ISCX_clean.csv")

# --------------------------------------------------------------------
# Kolejka GUI
# --------------------------------------------------------------------
packet_queue = queue.Queue()
running = False

# --------------------------------------------------------------------
# Helpery
# --------------------------------------------------------------------
def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def random_port():
    return random.randint(1024, 65535)

# --------------------------------------------------------------------
# Predykcja pojedynczego modelu
# --------------------------------------------------------------------
def predict_single(features, model):
    X = np.array(features, dtype=float).reshape(1, -1)
    return int(model.predict(X)[0])

# --------------------------------------------------------------------
# Generator flow z CSV
# --------------------------------------------------------------------
def load_random_flow(csv_path):
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Błąd wczytywania CSV {csv_path}: {e}")
        return None

    df = df.sample(1)              # losowy wiersz
    if "Label" in df.columns:
        df = df.drop(columns=["Label"])

    features = df.values.flatten().astype(float).tolist()
    return features

# --------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------
class FirewallGUI:
    def __init__(self, root):
        self.root = root
        root.title("Realtime Firewall GUI")

        # MODELE WŁĄCZONE
        self.rf_var = tk.BooleanVar(value=True)
        self.lr_var = tk.BooleanVar(value=True)
        self.mlp_var = tk.BooleanVar(value=True)

        frame_models = tk.LabelFrame(root, text="Modele")
        frame_models.pack(fill="x", padx=5, pady=5)
        tk.Checkbutton(frame_models, text="RandomForest", variable=self.rf_var).pack(side="left")
        tk.Checkbutton(frame_models, text="LogisticRegression", variable=self.lr_var).pack(side="left")
        tk.Checkbutton(frame_models, text="MLP", variable=self.mlp_var).pack(side="left")

        # PRZYCISKI
        frame_buttons = tk.Frame(root)
        frame_buttons.pack(fill="x", padx=5, pady=5)

        self.start_btn = tk.Button(frame_buttons, text="Start Sniff", command=self.start_sniff)
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = tk.Button(frame_buttons, text="Stop Sniff", command=self.stop_sniff, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        self.gen_attack_btn = tk.Button(frame_buttons, text="Generate ATTACK flow", command=self.generate_attack_flow)
        self.gen_attack_btn.pack(side="left", padx=5)

        self.gen_benign_btn = tk.Button(frame_buttons, text="Generate BENIGN flow", command=self.generate_benign_flow)
        self.gen_benign_btn.pack(side="left", padx=5)

        # LOGI
        frame_logs = tk.LabelFrame(root, text="Flowy")
        frame_logs.pack(fill="both", expand=True, padx=5, pady=5)

        columns = ["timestamp","src_ip","dst_ip","src_port","dst_port","protocol","pkt_count","prediction","decision"]
        self.tree = ttk.Treeview(frame_logs, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor="w")

        self.tree.pack(fill="both", expand=True)

        self.update_gui_from_queue()

    # --------------------------------------------------------------------
    # Modele zaznaczone
    # --------------------------------------------------------------------
    def get_enabled_model(self):
        if self.rf_var.get() and "rf" in models_loaded:
            return "rf", models_loaded["rf"]
        if self.lr_var.get() and "lr" in models_loaded:
            return "lr", models_loaded["lr"]
        if self.mlp_var.get() and "mlp" in models_loaded:
            return "mlp", models_loaded["mlp"]
        return None, None

    # --------------------------------------------------------------------
    # Dodawanie flow do GUI
    # --------------------------------------------------------------------
    def add_flow_to_tree(self, flow_key, pkt_count, pred, decision):
        ts = datetime.now().isoformat()

        self.tree.insert("", 0, values=(
            ts,
            flow_key[0],
            flow_key[1],
            flow_key[2],
            flow_key[3],
            flow_key[4],
            pkt_count,
            pred,
            decision
        ))

    def update_gui_from_queue(self):
        while not packet_queue.empty():
            flow_key, pkt_count, pred, decision = packet_queue.get()
            self.add_flow_to_tree(flow_key, pkt_count, pred, decision)
        self.root.after(200, self.update_gui_from_queue)

    # --------------------------------------------------------------------
    # Generate flows from CSV
    # --------------------------------------------------------------------
    def generate_attack_flow(self):
        model_name, model = self.get_enabled_model()
        if model is None:
            print("Brak włączonego modelu.")
            return

        features = load_random_flow(ATTACK_CSV)
        if features is None:
            print("Nie udało się wygenerować attack flow.")
            return

        pred = predict_single(features, model)
        decision = "DROP" if pred == 1 else "ACCEPT"

        flow_key = (random_ip(), random_ip(), random_port(), random_port(), 6)
        pkt_count = int(features[15]) if len(features) > 15 else 1

        packet_queue.put((flow_key, pkt_count, pred, decision))
        print(f"ATTACK → pred={pred}, decision={decision}")

    def generate_benign_flow(self):
        model_name, model = self.get_enabled_model()
        if model is None:
            print("Brak włączonego modelu.")
            return

        features = load_random_flow(BENIGN_CSV)
        if features is None:
            print("Nie udało się wygenerować benign flow.")
            return

        pred = predict_single(features, model)
        decision = "DROP" if pred == 1 else "ACCEPT"

        flow_key = (random_ip(), random_ip(), random_port(), random_port(), 6)
        pkt_count = int(features[15]) if len(features) > 15 else 1

        packet_queue.put((flow_key, pkt_count, pred, decision))
        print(f"BENIGN → pred={pred}, decision={decision}")

    # --------------------------------------------------------------------
    # Sniffing
    # --------------------------------------------------------------------
    def start_sniff(self):
        global running
        if running:
            return
        running = True

        model_name, model = self.get_enabled_model()

        def packet_callback(pkt):
            result = process_packet(pkt)

            if result is None:
                return

            flow_key, pkt_count, features = result
            pred = predict_single(features, model)
            decision = "DROP" if pred == 1 else "ACCEPT"

            packet_queue.put((flow_key, pkt_count, pred, decision))

        from scapy.all import sniff
        self.sniff_thread = threading.Thread(
            target=lambda: sniff(iface=DEFAULT_INTERFACE, prn=packet_callback, store=False),
            daemon=True
        )
        self.sniff_thread.start()

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        print(f"Sniffing started on {DEFAULT_INTERFACE}")

    def stop_sniff(self):
        global running
        running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        print("Sniffing stopped.")


# --------------------------------------------------------------------
# Start GUI
# --------------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    gui = FirewallGUI(root)
    root.mainloop()
