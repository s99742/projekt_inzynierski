#!/usr/bin/env python3
"""
gui_firewall.py - GUI dla realtime firewall z flow-based predykcją
"""

import os
import sys
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk
import sqlite3
import pandas as pd
from joblib import load

# -------------------------------------------------------------
# Ścieżki
# -------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from config_and_db import DB_PATH, MODEL_DIR, DEFAULT_INTERFACE, init_db
init_db()  # upewniamy się, że baza istnieje

# -------------------------------------------------------------
# Globalne zmienne
# -------------------------------------------------------------
running = False
models_loaded = {}

# -------------------------------------------------------------
# Załaduj modele
# -------------------------------------------------------------
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
        print(f"Nie udało się załadować modelu {key}: {e}")

# -------------------------------------------------------------
# Import funkcji flow
# -------------------------------------------------------------
sys.path.append(os.path.join(BASE_DIR, "src"))
from realtime_flow_predict import flows, extract_flow_features

# -------------------------------------------------------------
# Funkcje obsługi bazy danych
# -------------------------------------------------------------
def log_flow_to_db(flow_key, preds, decision):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        ts = datetime.now().isoformat()
        c.execute("""
            INSERT INTO logs(timestamp, src_ip, dst_ip, src_port, dst_port, protocol, prediction, decision)
            VALUES(?,?,?,?,?,?,?,?)
        """, (
            ts,
            flow_key[0],
            flow_key[1],
            flow_key[2],
            flow_key[3],
            flow_key[4],
            str(preds),
            decision
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print("❌ Błąd przy zapisie do DB:", e)

def fetch_latest_logs(limit=20):
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(f"SELECT * FROM logs ORDER BY id DESC LIMIT {limit}", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

# -------------------------------------------------------------
# Funkcja przetwarzania pakietu (flow-based)
# -------------------------------------------------------------
def process_packet(pkt, enabled_models):
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether

    if not (IP in pkt or pkt.haslayer(Ether)):
        return

    src_ip = pkt[IP].src if IP in pkt else "0.0.0.0"
    dst_ip = pkt[IP].dst if IP in pkt else "0.0.0.0"
    proto = pkt[IP].proto if IP in pkt else 0
    src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
    dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)

    flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
    ts = time.time()
    flow = flows[flow_key]
    if flow["start_time"] is None:
        flow["start_time"] = ts

    # forward/backward
    if (src_ip, src_port) == (flow_key[0], flow_key[2]):
        flow["fwd_lengths"].append(len(pkt))
        if TCP in pkt:
            for flag in ["FIN","SYN","RST","PSH","ACK","URG"]:
                if getattr(pkt[TCP], flag, 0):
                    flow["fwd_flags"][flag] += 1
    else:
        flow["bwd_lengths"].append(len(pkt))
        if TCP in pkt:
            for flag in ["FIN","SYN","RST","PSH","ACK","URG"]:
                if getattr(pkt[TCP], flag, 0):
                    flow["bwd_flags"][flag] += 1

    flow["timestamps"].append(ts)

    # timeout 10s
    if ts - flow["start_time"] > 10:
        features = extract_flow_features(flow_key, flow)
        preds = {}
        decision = "ACCEPT"

        for name, model in enabled_models.items():
            try:
                pred = model.predict([features])[0]
                preds[name] = int(pred)
                if pred != 0:
                    decision = "DROP"
            except Exception as e:
                preds[name] = "error"
                print(f"Błąd predykcji {name}: {e}")

        print(f"{datetime.now().isoformat()} | Flow: {flow_key} | Features: {features} | Preds: {preds} | Decision: {decision}")
        log_flow_to_db(flow_key, preds, decision)
        try:
            del flows[flow_key]
        except KeyError:
            pass

# -------------------------------------------------------------
# GUI
# -------------------------------------------------------------
class FirewallGUI:
    def __init__(self, root):
        self.root = root
        root.title("Realtime Firewall GUI")

        # modele
        self.rf_var = tk.BooleanVar(value=True)
        self.lr_var = tk.BooleanVar(value=True)
        self.mlp_var = tk.BooleanVar(value=True)

        frame_models = tk.LabelFrame(root, text="Włączone modele")
        frame_models.pack(fill="x", padx=5, pady=5)
        tk.Checkbutton(frame_models, text="RandomForest", variable=self.rf_var).pack(side="left")
        tk.Checkbutton(frame_models, text="LogisticRegression", variable=self.lr_var).pack(side="left")
        tk.Checkbutton(frame_models, text="MLP", variable=self.mlp_var).pack(side="left")

        # przyciski
        frame_buttons = tk.Frame(root)
        frame_buttons.pack(fill="x", padx=5, pady=5)
        self.start_btn = tk.Button(frame_buttons, text="Start Nasłuchu", command=self.start_sniff)
        self.start_btn.pack(side="left", padx=5)
        self.stop_btn = tk.Button(frame_buttons, text="Stop", command=self.stop_sniff, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        # logi
        frame_logs = tk.LabelFrame(root, text="Ostatnie pakiety")
        frame_logs.pack(fill="both", expand=True, padx=5, pady=5)
        columns = ["id","timestamp","src_ip","dst_ip","src_port","dst_port","protocol","prediction","decision"]
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
        enabled_models = {}
        if self.rf_var.get() and "rf" in models_loaded: enabled_models["rf"] = models_loaded["rf"]
        if self.lr_var.get() and "lr" in models_loaded: enabled_models["lr"] = models_loaded["lr"]
        if self.mlp_var.get() and "mlp" in models_loaded: enabled_models["mlp"] = models_loaded["mlp"]

        from scapy.all import sniff
        self.sniff_thread = threading.Thread(
            target=lambda: sniff(iface=DEFAULT_INTERFACE, prn=lambda pkt: process_packet(pkt, enabled_models), store=False),
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

# -------------------------------------------------------------
# Uruchomienie GUI
# -------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    gui = FirewallGUI(root)
    root.mainloop()

