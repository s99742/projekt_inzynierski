#!/usr/bin/env python3

from scapy.layers.inet import IP, TCP, UDP, ICMP
#!/usr/bin/env python3

from scapy.all import *
#!/usr/bin/env python3
"""
Test podejrzanych flowów TCP (np. DoS) dla GUI Firewall.
Pakiety wysyłane szybko, modele powinny przewidywać DROP.
"""

import time

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8000  # port monitorowany przez GUI

for i in range(50):
    pkt = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, sport=2000+i, flags="S")/"Attack"
    send(pkt, verbose=False)
    print(f"Wysłano podejrzany pakiet {i+1}")
    time.sleep(0.05)  # bardzo szybki ruch → większe prawdopodobieństwo DROP
