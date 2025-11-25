#!/usr/bin/env python3
import time
from collections import defaultdict
from datetime import datetime
import sqlite3
import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from config_and_db import DB_PATH
from firewall_rules import take_mitigation_action

FLOW_TIMEOUT = 10  # sekundy, po których flow jest przetwarzany

# --- Globalny buffer flow ---
flows = defaultdict(lambda: {
    "timestamps": [],
    "fwd_lengths": [],
    "bwd_lengths": [],
    "fwd_flags": defaultdict(int),
    "bwd_flags": defaultdict(int),
    "start_time": None,
    "src_ip": None,
    "dst_ip": None,
    "src_port": None,
    "dst_port": None,
    "proto": None
})

# --- Funkcje statystyczne ---
def calc_iat(timestamps):
    if len(timestamps) < 2:
        return [0]
    return [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]

def safe_stats(arr):
    if not arr:
        return 1e-6, 1e-6, 1e-6, 1e-6
    n = len(arr)
    mean = sum(arr)/n
    std = (sum([(x-mean)**2 for x in arr])/n)**0.5
    return mean, std, min(arr), max(arr)

# --- Ekstrakcja cech ---
def extract_flow_features(flow_key, flow_data):
    fwd = flow_data["fwd_lengths"]
    bwd = flow_data["bwd_lengths"]
    ts  = flow_data["timestamps"]
    start_time = flow_data["start_time"]
    end_time   = ts[-1] if ts else start_time

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

    features = [0]*78
    features[0]  = flow_data["dst_port"]
    features[1]  = end_time - start_time
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
    features[54:78] = [fwd_min, fwd_max, fwd_mean, fwd_std,
                       bwd_min, bwd_max, bwd_mean, bwd_std,
                       total_len_fwd, total_len_bwd, total_len_fwd+total_len_bwd,
                       total_fwd_pkts, total_bwd_pkts, total_fwd_pkts+total_bwd_pkts,
                       iat_min, iat_max, iat_mean, iat_std, 0,0,0,0,0,0]
    return features

# --- Logowanie do bazy ---
def log_flow_to_db(flow_key, pkt_count, preds, decision):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        ts = datetime.now().isoformat()
        c.execute("""
            INSERT INTO flow_logs(timestamp, src_ip, dst_ip, src_port, dst_port, protocol, prediction, decision)
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

# --- Proces pakietu (jedyna funkcja) ---
def process_packet(pkt, models=None, gui_callback=None):
    if not (IP in pkt):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    proto  = pkt[IP].proto
    src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
    dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)

    key = (src_ip, dst_ip, src_port, dst_port, proto)

    flow = flows[key]
    if flow["start_time"] is None:
        flow["start_time"] = time.time()
        flow["src_ip"] = src_ip
        flow["dst_ip"] = dst_ip
        flow["src_port"] = src_port
        flow["dst_port"] = dst_port
        flow["proto"] = proto

    ts = time.time()
    if (src_ip, src_port) == (flow["src_ip"], flow["src_port"]):
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

    # --- timeout ---
    if ts - flow["start_time"] > FLOW_TIMEOUT:
        features = extract_flow_features(key, flow)
        pkt_count = len(flow["timestamps"])
        preds = {}
        decision = "ACCEPT"

        if models:
            try:
                X = np.array(features).reshape(1, -1)
                for name, model in models.items():
                    pred = model.predict(X)[0]
                    preds[name] = int(pred)
                    if pred != 0:
                        decision = "DROP"
            except Exception as e:
                preds = {k: -1 for k in models.keys()}
                print("❌ Błąd predykcji:", e)

        log_flow_to_db(key, pkt_count, preds, decision)

        # firewall
        if decision == "DROP":
            try:
                take_mitigation_action(src_ip, ttl_seconds=600, reason="auto-detect")
            except Exception as e:
                print("❌ Błąd firewall_rules:", e)

        # GUI callback
        if gui_callback:
            try:
                from tkinter import _default_root
                gui_callback_safe = lambda k=key, pc=pkt_count, p=preds, d=decision: gui_callback(k, pc, p, d)
                if _default_root:
                    _default_root.after(0, gui_callback_safe)
                else:
                    gui_callback_safe()
            except Exception:
                gui_callback_safe()

        flows.pop(key, None)
