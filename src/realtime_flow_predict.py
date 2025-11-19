#!/usr/bin/env python3
"""
realtime_flow_predict.py

Flow-based live predykcja dla CICIDS2017:
- Buforowanie flow (5-tuples)
- Obliczanie wszystkich 78 cech dla flow
- Predykcja RF, LR, HGB
- Soft voting (średnia ważona) z wagami RF=0.5, LR=0.5, HGB=0.25
- HGB ignoruje jednostronne flow
- Zapis wyników do SQLite
"""

import time
import sqlite3
from collections import defaultdict
from datetime import datetime
from scapy.all import IP, TCP, UDP

from config_and_db import DB_PATH  # ścieżka do bazy

# --- Konfiguracja ---
FLOW_TIMEOUT = 10  # sekundy, po których flow jest przetwarzany

# Globalne modele (załaduj w GUI/main)
models = {}

# Bufor flow: key = (src_ip, dst_ip, src_port, dst_port, proto)
flows = defaultdict(lambda: {
    "timestamps": [],
    "fwd_lengths": [],
    "bwd_lengths": [],
    "fwd_flags": defaultdict(int),
    "bwd_flags": defaultdict(int),
    "start_time": None
})

# --- Funkcje statystyk ---
def calc_iat(timestamps):
    if len(timestamps) < 2:
        return []
    return [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]

def safe_stats(arr):
    if not arr:
        return 1e-6, 1e-6, 1e-6, 1e-6
    n = len(arr)
    mean = sum(arr)/n
    std = (sum((x-mean)**2 for x in arr)/n)**0.5
    return mean, std, min(arr), max(arr)

# --- Funkcja ekstrakcji cech 78 ---
def extract_flow_features(flow_key, flow_data):
    fwd = flow_data["fwd_lengths"] or [1e-6]
    bwd = flow_data["bwd_lengths"] or [1e-6]
    ts  = flow_data["timestamps"] or [time.time()]
    start_time = flow_data["start_time"] or ts[0]
    end_time   = ts[-1]

    total_fwd_pkts = len(fwd)
    total_bwd_pkts = len(bwd)
    total_len_fwd  = sum(fwd)
    total_len_bwd  = sum(bwd)

    fwd_mean, fwd_std, fwd_min, fwd_max = safe_stats(fwd)
    bwd_mean, bwd_std, bwd_min, bwd_max = safe_stats(bwd)
    iat = calc_iat(ts)
    iat_mean, iat_std, iat_min, iat_max = safe_stats(iat)

    fwd_flags = flow_data["fwd_flags"]
    bwd_flags = flow_data["bwd_flags"]

    features = [0.0]*78

    # 0-19: podstawowe statystyki
    features[0]  = flow_key[3]  # dst_port
    duration = max(end_time - start_time, 1e-6)
    features[1]  = duration
    features[2]  = total_fwd_pkts
    features[3]  = total_bwd_pkts
    features[4]  = total_len_fwd
    features[5]  = total_len_bwd
    features[6]  = fwd_max
    features[7]  = fwd_min
    features[8]  = fwd_mean
    features[9]  = fwd_std
    features[10] = bwd_max
    features[11] = bwd_min
    features[12] = bwd_mean
    features[13] = bwd_std
    features[14] = total_len_fwd + total_len_bwd
    features[15] = total_fwd_pkts + total_bwd_pkts
    features[16] = iat_mean
    features[17] = iat_std
    features[18] = iat_max
    features[19] = iat_min

    # 20-53: TCP Flags
    features[42] = fwd_flags.get("FIN",0)
    features[43] = fwd_flags.get("SYN",0)
    features[44] = fwd_flags.get("RST",0)
    features[45] = fwd_flags.get("PSH",0)
    features[46] = fwd_flags.get("ACK",0)
    features[47] = fwd_flags.get("URG",0)
    features[48] = bwd_flags.get("FIN",0)
    features[49] = bwd_flags.get("SYN",0)
    features[50] = bwd_flags.get("RST",0)
    features[51] = bwd_flags.get("PSH",0)
    features[52] = bwd_flags.get("ACK",0)
    features[53] = bwd_flags.get("URG",0)

    # 54-71: dodatkowe statystyki
    features[54] = fwd_min
    features[55] = fwd_max
    features[56] = fwd_mean
    features[57] = fwd_std
    features[58] = bwd_min
    features[59] = bwd_max
    features[60] = bwd_mean
    features[61] = bwd_std
    features[62] = total_len_fwd
    features[63] = total_len_bwd
    features[64] = total_len_fwd + total_len_bwd
    features[65] = total_fwd_pkts
    features[66] = total_bwd_pkts
    features[67] = total_fwd_pkts + total_bwd_pkts
    features[68] = iat_min
    features[69] = iat_max
    features[70] = iat_mean
    features[71] = iat_std

    # 72-77: przepustowość i pkts/sec
    features[72] = total_len_fwd / duration
    features[73] = total_len_bwd / duration
    features[74] = total_fwd_pkts / duration
    features[75] = total_bwd_pkts / duration
    features[76] = (total_len_fwd + total_len_bwd) / duration
    features[77] = (total_fwd_pkts + total_bwd_pkts) / duration

    return features

# --- Przetwarzanie pakietu ---
def process_packet(pkt):
    if not (IP in pkt):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    proto  = pkt[IP].proto
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

    # timeout
    if ts - flow["start_time"] > FLOW_TIMEOUT:
        features = extract_flow_features(flow_key, flow)

        preds = {}
        decision = "ACCEPT"  # domyślnie

        # wagi modeli
        model_weights = {"rf": 0.5, "lr": 0.5, "hgb": 0.25}

        weighted_sum = 0.0
        total_weight = 0.0

        for name, model in models.items():
            weight = model_weights.get(name.lower(), 0.33)
            try:
                # HGB ignoruje jednostronne flow
                if name.lower() == "hgb" and (len(flow["fwd_lengths"]) == 0 or len(flow["bwd_lengths"]) == 0):
                    pred = 0
                else:
                    pred = model.predict([features])[0]

                preds[name] = int(pred)
                weighted_sum += (1.0 if pred != 0 else 0.0) * weight
                total_weight += weight
            except Exception:
                preds[name] = -1
                total_weight += weight

        # decyzja wg średniej ważonej
        if total_weight > 0:
            score = weighted_sum / total_weight
            decision = "DROP" if score >= 0.5 else "ACCEPT"

        # zapis do bazy
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

        flows.pop(flow_key, None)
