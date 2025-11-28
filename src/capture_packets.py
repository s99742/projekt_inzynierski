#!/usr/bin/env python3
"""
capture_packets.py
Przechwytywanie pakietów w czasie rzeczywistym i zapis do SQLite.
Poprawki:
- użycie DEFAULT_INTERFACE z config_and_db
- bezpieczne pobieranie pól pakietu
"""

import os
import sqlite3
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
from config_and_db import DB_PATH, DEFAULT_INTERFACE, init_db

# Upewnij się, że baza i tabele istnieją
init_db()

INTERFACE = DEFAULT_INTERFACE
print(f"Nasłuch na interfejsie: {INTERFACE}")

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def process_packet(pkt):
    try:
        timestamp = datetime.now().isoformat()
        src_ip = pkt[IP].src if IP in pkt else None
        dst_ip = pkt[IP].dst if IP in pkt else None
        src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
        dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
        proto = int(pkt[IP].proto) if IP in pkt and pkt[IP].proto is not None else None
        length = len(pkt)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, src_ip, dst_ip, src_port, dst_port, proto, length))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Błąd process_packet:", e)

def main():
    try:
        sniff(iface=INTERFACE, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nZatrzymano przechwytywanie pakietów.")
    except Exception as e:
        print("Błąd sniff:", e)

if __name__ == "__main__":
    main()
