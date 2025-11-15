import subprocess
import time
import threading
import ipaddress
import sqlite3
import os
from datetime import datetime, timedelta

# ścieżka do DB (możesz użyć tej samej co w GUI)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "logs/project_logs.db")

# tabela rules (jeśli chcesz logować reguły)
def init_rules_table():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS firewall_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        added_at TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol INTEGER,
        action TEXT,
        expiry TEXT,
        reason TEXT
    )
    """)
    conn.commit()
    conn.close()

init_rules_table()

# walidacja IP (raise ValueError jeśli niepoprawny)
def validate_ip(ip_str):
    try:
        return str(ipaddress.ip_address(ip_str))
    except Exception:
        raise ValueError(f"Invalid IP: {ip_str}")

# dodaje regułę blokującą źródło IP w łańcuchu INPUT (DROP)
def block_ip(src_ip, ttl_seconds=600, reason=None):
    src_ip = validate_ip(src_ip)
    # komenda bez shell, bez interpolation --> bezpieczne
    cmd = ["iptables", "-I", "INPUT", "-s", src_ip, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to add iptables rule: {e}")

    expiry = (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat() if ttl_seconds else None
    # zapisz regułę do bazy
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO firewall_rules(added_at, src_ip, dst_ip, src_port, dst_port, protocol, action, expiry, reason)
        VALUES(?,?,?,?,?,?,?,?,?)
    """, (datetime.utcnow().isoformat(), src_ip, None, None, None, None, "DROP", expiry, reason))
    conn.commit()
    conn.close()

    # zaplanuj usunięcie jeśli TTL ustawione
    if ttl_seconds:
        t = threading.Timer(ttl_seconds, unblock_ip, args=(src_ip,))
        t.daemon = True
        t.start()

    return True

# usuwa regułę DROP dla danego src_ip (usuwa wszystkie pasujące reguły INPUT -s ip -j DROP)
def unblock_ip(src_ip):
    try:
        src_ip = validate_ip(src_ip)
    except ValueError:
        return False

    # Komenda: -D zamiast -I — usuwa pierwsze dopasowanie; powtarzamy w pętli aż nie będzie już pasującej reguły
    while True:
        cmd = ["iptables", "-D", "INPUT", "-s", src_ip, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"]
        res = subprocess.run(cmd)
        if res.returncode != 0:
            break

    # zaktualizuj wpis w DB: ustaw expiry na teraz
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE firewall_rules SET expiry = ? WHERE src_ip = ? AND expiry IS NOT NULL", (datetime.utcnow().isoformat(), src_ip))
    conn.commit()
    conn.close()
    return True

# lekkie API: blokuj po source ip + zapisz powód i TTL
def take_mitigation_action(src_ip, ttl_seconds=600, reason="auto-detect"):
    try:
        return block_ip(src_ip, ttl_seconds=ttl_seconds, reason=reason)
    except Exception as e:
        # loguj / zwróć False
        print("❌ firewall action failed:", e)
        return False
