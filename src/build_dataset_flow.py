#!/usr/bin/env python3
"""
build_dataset_flow.py - Streamingowe przetwarzanie CICIDS2017 (clean CSV)
- Chunkowe wczytywanie (50k wierszy)
- Sampling max 500k flow
- Wyświetla progres w konsoli
- Tworzy X_train/X_test/y_train/y_test + scaler.pkl
"""

import pandas as pd
import numpy as np
import os
import gc
from collections import defaultdict
from tqdm import tqdm
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from config_and_db import DATA_DIR, CLEAN_DATA_DIR

FLOW_TIMEOUT = 10        # max czas flow w sekundach
MAX_FLOWS   = 500_000    # maksymalna liczba flow w zbiorze
CHUNK_SIZE  = 50_000     # liczba wierszy na raz

def calc_iat(timestamps):
    if len(timestamps) < 2:
        return [0]
    return [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]

def safe_stats(arr):
    if not arr:
        return 1e-6, 1e-6, 1e-6, 1e-6
    n = len(arr)
    mean = sum(arr)/n
    std = (sum((x-mean)**2 for x in arr)/n)**0.5
    return mean, std, min(arr), max(arr)

def extract_flow_features(f):
    fwd = f["fwd_lengths"]
    bwd = f["bwd_lengths"]
    ts  = f["timestamps"]
    start_time = f["start_time"]
    end_time   = ts[-1] if ts else start_time

    total_fwd_pkts = len(fwd)
    total_bwd_pkts = len(bwd)
    total_len_fwd  = sum(fwd)
    total_len_bwd  = sum(bwd)

    fwd_mean, fwd_std, fwd_min, fwd_max = safe_stats(fwd)
    bwd_mean, bwd_std, bwd_min, bwd_max = safe_stats(bwd)
    iat_mean, iat_std, iat_min, iat_max = safe_stats(calc_iat(ts))

    fwd_flags = f["fwd_flags"]
    bwd_flags = f["bwd_flags"]

    features = [0]*78
    features[0]  = f["dst_port"]
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

    # TCP flags
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

    # redundant block
    features[54:78] = [
        fwd_min, fwd_max, fwd_mean, fwd_std,
        bwd_min, bwd_max, bwd_mean, bwd_std,
        total_len_fwd, total_len_bwd, total_len_fwd+total_len_bwd,
        total_fwd_pkts, total_bwd_pkts, total_fwd_pkts+total_bwd_pkts,
        iat_min, iat_max, iat_mean, iat_std,
        0,0,0,0,0,0
    ]
    return features

def build_dataset(csv_folder=CLEAN_DATA_DIR, max_flows=MAX_FLOWS):
    all_files = [f for f in os.listdir(csv_folder) if f.endswith(".csv")]
    flows = defaultdict(lambda: {
        "timestamps": [], "fwd_lengths": [], "bwd_lengths": [],
        "fwd_flags": defaultdict(int), "bwd_flags": defaultdict(int),
        "start_time": None, "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None, "proto": None, "label": None
    })

    dataset = []
    benign_count = 0
    attack_count = 0

    print("Start przetwarzania CICIDS2017 (streaming, no-freeze)\n")

    for file in tqdm(all_files, desc="CSV files"):
        csv_path = os.path.join(csv_folder, file)
        # Wczytaj nagłówki, znajdź kolumnę z label
        sample_df = pd.read_csv(csv_path, nrows=1)
        label_col_candidates = [c for c in sample_df.columns if "label" in c.lower()]
        if not label_col_candidates:
            raise ValueError(f"❌ Nie znaleziono kolumny label w pliku {file}")
        label_col = label_col_candidates[0]

        for chunk in pd.read_csv(csv_path, chunksize=CHUNK_SIZE):
            for _, row in chunk.iterrows():
                # Flow key
                src_ip = row.get("Source IP","0.0.0.0")
                dst_ip = row.get("Destination IP","0.0.0.0")
                src_port = int(row.get("Source Port",0))
                dst_port = int(row.get("Destination Port",0))
                proto = 6 if row.get("Protocol",6)==6 else 17
                length = row.get("Total Length of Fwd Packets",0)
                timestamp = float(row.get("Timestamp",0))
                label = str(row.get(label_col,"BENIGN")).strip()

                key = (src_ip,dst_ip,src_port,dst_port,proto)
                f = flows[key]

                if f["start_time"] is None:
                    f.update({
                        "start_time": timestamp,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "proto": proto,
                        "label": label
                    })

                if src_ip==f["src_ip"]:
                    f["fwd_lengths"].append(length)
                else:
                    f["bwd_lengths"].append(length)

                f["timestamps"].append(timestamp)

                # timeout
                if timestamp - f["start_time"] > FLOW_TIMEOUT:
                    features = extract_flow_features(f)
                    dataset.append(features + [label])
                    flows.pop(key)

            del chunk
            gc.collect()

            # jeśli przekroczono max_flows
            if len(dataset) >= max_flows:
                dataset = dataset[:max_flows]
                break
        if len(dataset) >= max_flows:
            break

    # Podsumowanie
    for lbl in [row[-1] for row in dataset]:
        if "BENIGN" in str(lbl).upper():
            benign_count += 1
        else:
            attack_count += 1

    print(f"\nZebrano:\n  BENIGN: {benign_count}\n  ATTACK: {attack_count}")

    if benign_count==0 or attack_count==0:
        raise ValueError("BRAK dwóch klas! Sprawdź pliki CSV (muszą zawierać BENIGN i ATTACK).")

    # Split dataset
    df = pd.DataFrame(dataset, columns=[f"f{i}" for i in range(78)]+["label"])
    X = df.drop(columns=["label"]).values
    y_raw = df["label"].values
    y = np.array([0 if "BENIGN" in str(lbl).upper() else 1 for lbl in y_raw])

    X_train,X_test,y_train,y_test = train_test_split(X,y,test_size=0.2,stratify=y,random_state=42)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # Save pickle
    pd.DataFrame(X_train).to_pickle(os.path.join(DATA_DIR,"X_train.pkl"))
    pd.DataFrame(X_test).to_pickle(os.path.join(DATA_DIR,"X_test.pkl"))
    pd.DataFrame(y_train).to_pickle(os.path.join(DATA_DIR,"y_train.pkl"))
    pd.DataFrame(y_test).to_pickle(os.path.join(DATA_DIR,"y_test.pkl"))
    import joblib
    joblib.dump(scaler, os.path.join(DATA_DIR,"scaler.pkl"))

    print("\nBuild complete. Pickles saved in data/")

if __name__=="__main__":
    build_dataset()
