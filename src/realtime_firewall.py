#!/usr/bin/env python3
"""
realtime_firewall.py

Moduł do przechwytywania pakietów w czasie rzeczywistym,
predykcji ML oraz blokowania podejrzanych IP.

API:
- start_sniffing()    -> uruchamia wątek sniffingu (jeśli nie jest uruchomiony)
- stop_sniffing()     -> zatrzymuje sniffing
- get_new_packets()   -> zwraca listę nowo przetworzonych pakietów (i czyści wewnętrzną kolejkę)
- get_blocked_ips()   -> zwraca zbiór zablokowanych IP
"""

import threading
import time
from datetime import datetime
import subprocess
import os
from queue import Queue, Empty

import pandas as pd
import joblib
from scapy.all import sniff, IP, IPv6, TCP, UDP

from prepare_live_data import process_features, ensure_features

# --- Ścieżki (zakładamy strukturę projektu jak w tree) ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # projekt root
MODEL_DIR = os.path.join(BASE_DIR, "models")
FEATURES_CSV = os.path.join(BASE_DIR, "data", "X_train.csv")

RF_PATH = os.path.join(MODEL_DIR, "RandomForest_cicids.pkl")
LR_PATH = os.path.join(MODEL_DIR, "LogisticRegression_cicids.pkl")
HGB_PATH = os.path.join(MODEL_DIR, "HGB_cicids.pkl")

# --- Globalne obiekty ---
_sniff_thread = None
_running_flag = threading.Event()
_packet_queue = Queue()        # pakiety gotowe dla GUI
_blocked_ips = set()           # zablokowane IP

# --- Załaduj modele bez przerywania jeśli ich brak ---
_models = {}
for name, path in (("rf", RF_PATH), ("lr", LR_PATH), ("hgb", HGB_PATH)):
    try:
        _models[name] = joblib.load(path)
        print(f"✅ Załadowano model: {name} ({path})")
    except Exception as e:
        _models[name] = None
        print(f"⚠️ Nie załadowano modelu {name}: {e}")

# --- Funkcja bezpiecznego blokowania IP (IPv4/IPv6) ---
def block_ip(ip: str):
    """
    Blokuje adres IP. Dla IPv4 używa iptables, dla IPv6 - ip6tables.
    Nie próbuje blokować pustych stringów.
    Dodaje IP do _blocked_ips tylko jeśli blokada powiodła się.
    """
    if not ip or str(ip).strip() == "":
        print("⚠️ Pomijam blokowanie pustego IP")
        return False

    if ip in _blocked_ips:
        # już zablokowany
        return True

    # wybierz narzędzie
    if ":" in ip:
        cmd = ["sudo", "ip6tables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    else:
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _blocked_ips.add(ip)
        print(f"✅ Zablokowano IP: {ip}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Błąd przy blokowaniu IP ({ip}): {e}")
        return False
    except FileNotFoundError as e:
        print(f"❌ Nie znaleziono narzędzia iptables/ip6tables: {e}")
        return False

# --- Analiza pojedynczego pakietu ---
def analyze_packet(pkt) -> dict | None:
    """
    Przetwarza pakiet scapy -> słownik z kluczami:
    id,timestamp,src_ip,dst_ip,src_port,dst_port,protocol,length,prediction,decision
    Zwraca None jeśli pakiet nie jest analizowany.
    """
    # wymuś tylko IP/IPv6/TCP/UDP - ignoruj inne
    if not (IP in pkt or IPv6 in pkt):
        return None

    # pobierz podstawowe pola (bez wyrzucania wyjątków)
    src_ip = pkt[IP].src if IP in pkt else (pkt[IPv6].src if IPv6 in pkt else "")
    dst_ip = pkt[IP].dst if IP in pkt else (pkt[IPv6].dst if IPv6 in pkt else "")
    # porty: scapy trzyma .sport/.dport na warstwie TCP/UDP
    src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
    dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
    protocol = pkt[IP].proto if IP in pkt else (pkt[IPv6].nh if IPv6 in pkt else 0)
    length = len(pkt)

    # przygotuj słownik wejściowy do process_features (ten plik oczekuje kolumn takich jak length, src_ip itd.)
    pkt_row = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "protocol": int(protocol),
        "length": int(length)
    }

    # DataFrame -> process_features -> ensure_features
    try:
        df = pd.DataFrame([pkt_row])
        df = process_features(df)                     # normalizacje/kodowania
        df = ensure_features(df, FEATURES_CSV)        # dopasuj kolumny do X_train.csv
    except Exception as e:
        print(f"❌ Błąd podczas przygotowywania cech: {e}")
        # mimo błędu zwróć widoczne info (bez predykcji)
        return {
            "id": int(time.time() * 1e6),
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "protocol": int(protocol),
            "length": int(length),
            "prediction": "{}",
            "decision": "ALLOW"
        }

    # --- Predykcje modeli (jeśli załadowane) ---
    preds = {}
    try:
        for nm, mdl in _models.items():
            if mdl is not None:
                # mdl może żądać DataFrame z nazwami kolumn - ensure_features zapewnia kolumny
                p = mdl.predict(df)[0]
                preds[nm] = int(p)
            else:
                preds[nm] = None
    except Exception as e:
        print(f"❌ Błąd predykcji: {e}")
        preds = {k: None for k in (_models.keys())}

    # decyzja: DROP jeśli **co najmniej jeden** model przewiduje != 0 (możesz tu zmienić regułę!)
    decision = "ALLOW"
    try:
        # jeśli którykolwiek model zwraca int>0 traktujemy jako atak
        for v in preds.values():
            if v is not None and int(v) != 0:
                decision = "DROP"
                break
    except Exception:
        decision = "ALLOW"

    # próbuj blokować tylko jeśli mamy SRC IP i decyzja DROP
    if decision == "DROP" and src_ip:
        block_ip(src_ip)

    # przygotuj słownik wynikowy
    pkt_dict = {
        "id": int(time.time() * 1e6),
        "timestamp": datetime.now().isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "protocol": int(protocol),
        "length": int(length),
        "prediction": str(preds),
        "decision": decision
    }

    return pkt_dict

# --- Pętla sniffująca w tle ---
def _sniff_loop():
    """
    W pętli wywołujemy sniff z timeout, żeby móc reagować na flagę stop.
    Wyniki analiz wrzucamy do _packet_queue.
    """
    while _running_flag.is_set():
        try:
            # sniff kilka pakietów lub timeout
            sniff(count=10, prn=lambda p: _packet_queue.put(analyze_packet(p)) if analyze_packet(p) else None, timeout=1)
        except Exception as e:
            # nie przerywamy pętli dla pojedynczych wyjątków
            print(f"❌ Błąd w sniff: {e}")
            time.sleep(0.5)

# --- Public API ---
def start_sniffing():
    """
    Uruchamia wątek sniffingu (jeśli nie jest uruchomiony).
    """
    global _sniff_thread
    if _running_flag.is_set():
        return
    _running_flag.set()
    _sniff_thread = threading.Thread(target=_sniff_loop, daemon=True)
    _sniff_thread.start()
    print("🔹 Sniffing uruchomiony")

def stop_sniffing():
    """
    Zatrzymuje sniffing.
    """
    _running_flag.clear()
    print("🔹 Sniffing zatrzymany")
    # nie blokujemy join tutaj (GUI zrobi to gdy trzeba)

def get_new_packets(max_items=100):
    """
    Pobiera z kolejki do `max_items` nowych pakietów i zwraca listę (oczyści kolejkę).
    Każdy element to słownik opisany w analyze_packet (albo None jeśli analyze_packet zwróciło None).
    """
    packets = []
    for _ in range(max_items):
        try:
            item = _packet_queue.get_nowait()
            if item is None:
                continue
            packets.append(item)
        except Empty:
            break
    return packets

def get_blocked_ips():
    return set(_blocked_ips)
