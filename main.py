#!/usr/bin/env python3
"""
BEZPIECZNY TEST DDoS – SYN + UDP flood
Niewielkie natężenie, nie zawiesi systemu.
"""

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import send
import random
import time
#!/usr/bin/env python3
"""
Test ruchu dla firewalla – działa na interfejsie LOOPBACK (lo).
Generuje: TCP SYN, UDP, ICMP ping.
Bezpieczny, mała intensywność.
"""
TARGET_IP = "127.0.0.1"
TARGET_PORT = 80
INTERFACE = "lo"

# Bardzo agresywne parametry - gwarantuje DROP
PACKETS = 500         # dużo pakietów -> duży wolumen
SLEEP = 0.0005        # prawie zero IAT -> cecha ataku CICIDS


def force_drop_test():
    print("\nSTART: Force-DROP test (TCP SYN Flood)\n")

    for i in range(PACKETS):
        sport = random.randint(1024, 65535)
        pkt = IP(dst=TARGET_IP) / TCP(sport=sport, dport=TARGET_PORT, flags="S")

        send(pkt, iface=INTERFACE, verbose=False)

        # ekstremalnie mały odstęp = pewny trigger modeli CICIDS
        time.sleep(SLEEP)

    print("\nKONIEC TESTU — firewall powinien wykonać DROP.\n")


if __name__ == "__main__":
    force_drop_test()
