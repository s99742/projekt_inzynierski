#!/usr/bin/env python3
"""
realtime_flow_predict.py

Flow-based live predykcja dla CICIDS2017:
- Buforowanie flow (5-tuples)
- Obliczanie 78 cech dla flow
- Predykcja RF, LR, HGB
- Zapis wyników do SQLite
"""

import time
import sqlite3
from collections import defaultdict
from datetime import datetime
from scapy.all import IP, TCP, UDP

# --- Konfiguracja ---
DB_PATH = "../logs/project_logs.db"
FLOW_TIMEOUT = 10  # sekundy, po których flow jest przetwarzany

# Globalne modele (załaduj w GUI/main)
models = {}

# Bufor flow: key = (src_ip, dst_ip, src_port, dst_port, proto)
flows = defaultdict(lambda: {
    "packets": [],
    "timestamps": [],
    "fwd_lengths": [],
    "bwd_lengths": [],
    "fwd_flags": defaultdict(int),
    "bwd_flags": defaultdict(int),
    "start_time": None
})

# --- Funkcje statystyk ---
def calc_iat(timestamps):
    """Oblicza interarrival times dla listy timestampów"""
    if len(timestamps) < 2:
        return [0]
    return [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]

def extract_flow_features(flow_key, flow_data):
    """Tworzy wektor 78 cech zgodny z modelem CICIDS2017"""
    fwd = flow_data["fwd_lengths"]
    bwd = flow_data["bwd_lengths"]
    ts = flow_data["timestamps"]
    start_time = flow_data["start_time"]
    end_time = ts[-1] if ts else start_time

    # Statystyki pakietów
    total_fwd_pkts = len(fwd)
    total_bwd_pkts = len(bwd)
    total_len_fwd = sum(fwd)
    total_len_bwd = sum(bwd)
    fwd_max = max(fwd) if fwd else 0
    fwd_min = min(fwd) if fwd else 0
    fwd_mean = sum(fwd)/len(fwd) if fwd else 0
    fwd_std = (sum([(x-fwd_mean)**2 for x in fwd])/len(fwd))**0.5 if len(fwd)>0 else 0

    bwd_max = max(bwd) if bwd else 0
    bwd_min = min(bwd) if bwd else 0
    bwd_mean = sum(bwd)/len(bwd) if bwd else 0
    bwd_std = (sum([(x-bwd_mean)**2 for x in bwd])/len(bwd))**0.5 if len(bwd)>0 else 0

    flow_iat = calc_iat(ts)
    flow_iat_mean = sum(flow_iat)/len(flow_iat) if flow_iat else 0
    flow_iat_std = (sum([(x-flow_iat_mean)**2 for x in flow_iat])/len(flow_iat))**0.5 if flow_iat else 0
    flow_iat_max = max(flow_iat) if flow_iat else 0
    flow_iat_min = min(flow_iat) if flow_iat else 0

    # TCP Flags
    fwd_flags = flow_data["fwd_flags"]
    bwd_flags = flow_data["bwd_flags"]

    # --- Tworzymy wektor 78 cech ---
    features = [0]*78
    try:
        # Podstawowe cechy
        features[0] = flow_key[3]               # Destination Port
        features[1] = end_time - start_time     # Flow Duration
        features[2] = total_fwd_pkts
        features[3] = total_bwd_pkts
        features[4] = total_len_fwd
        features[5] = total_len_bwd
        features[6] = fwd_max
        features[7] = fwd_min
        features[8] = fwd_mean
        features[9] = fwd_std
        features[10] = bwd_max
        features[11] = bwd_min
        features[12] = bwd_mean
        features[13] = bwd_std
        features[16] = flow_iat_mean
        features[17] = flow_iat_std
        features[18] = flow_iat_max
        features[19] = flow_iat_min

        # TCP Flags
        features[42] = fwd_flags.get("FIN",0)
        features[43] = fwd_flags.get("SYN",0)
        features[44] = fwd_flags.get("RST",0)
        features[45] = fwd_flags.get("PSH",0)
        features[46] = fwd_flags.get("ACK",0)
        features[47] = fwd_flags.get("URG",0)
    except:
        pass

    # Pozostałe cechy zostają 0 (można rozbudować później)
    return features

# --- Funkcja przetwarzania pakietu ---
def process_packet(pkt):
    print(f"Przetworzono pakiet: {pkt.summary()}")
    if not (IP in pkt):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    proto = pkt[IP].proto
    src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
    dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)

    flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
    ts = time.time()

    flow = flows[flow_key]
    if flow["start_time"] is None:
        flow["start_time"] = ts

    # Forward/backward
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

    # Timeout
    if ts - flow["start_time"] > FLOW_TIMEOUT:
        features = extract_flow_features(flow_key, flow)
        preds = {}
        decision = "ACCEPT"

        for name, model in models.items():
            try:
                pred = model.predict([features])[0]
                preds[name] = pred
                if pred != 0:
                    decision = "DROP"
            except:
                preds[name] = "error"


        # Zapis do bazy
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                INSERT INTO logs(timestamp, src_ip, dst_ip, src_port, dst_port, protocol, prediction, decision)
                VALUES(?,?,?,?,?,?,?,?)
            """, (
                datetime.now().isoformat(), src_ip, dst_ip, src_port, dst_port, proto, str(preds), decision
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print("❌ Błąd przy zapisie do DB:", e)

        # Usuń flow
        del flows[flow_key]
