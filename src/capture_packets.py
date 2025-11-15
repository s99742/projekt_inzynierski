#!/usr/bin/env python3
"""
capture_packets.py

Przechwytywanie pakietów w czasie rzeczywistym i zapis do SQLite.
Automatyczne wykrywanie interfejsu sieciowego (Wi-Fi/Ethernet).
"""

import os
import sqlite3
import time
from datetime import datetime
from scapy.all import sniff
import netifaces

# --- KONFIGURACJA ---
DB_PATH = "../logs/project_logs.db"

def get_default_iface():
    """
    Zwraca domyślny interfejs z aktywnym ruchem (Wi-Fi lub Ethernet), pomija loopback.
    """
    ifaces = netifaces.interfaces()
    for iface in ifaces:
        if iface == "lo":
            continue
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:  # ma przypisany IPv4
            return iface
    raise RuntimeError("Nie znaleziono aktywnego interfejsu sieciowego")

INTERFACE = get_default_iface()
print(f"🌐 Nasłuch na interfejsie: {INTERFACE}")

# --- TWORZENIE BAZY I TABELI ---
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute("""
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    length INTEGER
)
""")
conn.commit()
conn.close()
print(f"✅ Baza gotowa: {DB_PATH}")

# --- FUNKCJA PRZETWARZAJĄCA PAKIET ---
def process_packet(pkt):
    timestamp = datetime.now().isoformat()
    src_ip = pkt[0][1].src if pkt.haslayer("IP") else None
    dst_ip = pkt[0][1].dst if pkt.haslayer("IP") else None
    src_port = pkt.sport if hasattr(pkt, "sport") else None
    dst_port = pkt.dport if hasattr(pkt, "dport") else None
    proto = pkt[0][1].proto if pkt.haslayer("IP") else None
    length = len(pkt)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, src_ip, dst_ip, src_port, dst_port, proto, length))
    conn.commit()
    conn.close()

# --- PĘTLA NASŁUCHU ---
def main():
    try:
        sniff(iface=INTERFACE, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n⏹ Zatrzymano przechwytywanie pakietów.")

if __name__ == "__main__":
    main()
