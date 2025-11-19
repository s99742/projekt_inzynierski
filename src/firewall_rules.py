import subprocess
import threading
import ipaddress
import sqlite3
from datetime import datetime, timedelta
from config_and_db import DB_PATH

def init_rules_table():
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

def validate_ip(ip_str):
    try:
        return str(ipaddress.ip_address(ip_str))
    except Exception:
        raise ValueError(f"Invalid IP: {ip_str}")

def block_ip(src_ip, ttl_seconds=600, reason=None):
    src_ip = validate_ip(src_ip)
    cmd = ["iptables", "-I", "INPUT", "-s", src_ip, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"]
    subprocess.run(cmd, check=True)
    expiry = (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat() if ttl_seconds else None

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO firewall_rules(added_at, src_ip, dst_ip, src_port, dst_port, protocol, action, expiry, reason)
        VALUES(?,?,?,?,?,?,?,?,?)
    """, (datetime.utcnow().isoformat(), src_ip, None, None, None, None, "DROP", expiry, reason))
    conn.commit()
    conn.close()

    if ttl_seconds:
        t = threading.Timer(ttl_seconds, unblock_ip, args=(src_ip,))
        t.daemon = True
        t.start()

    return True

def unblock_ip(src_ip):
    src_ip = validate_ip(src_ip)
    while True:
        cmd = ["iptables", "-D", "INPUT", "-s", src_ip, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"]
        res = subprocess.run(cmd)
        if res.returncode != 0:
            break

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE firewall_rules SET expiry = ? WHERE src_ip = ? AND expiry IS NOT NULL",
              (datetime.utcnow().isoformat(), src_ip))
    conn.commit()
    conn.close()
    return True

def take_mitigation_action(src_ip, ttl_seconds=600, reason="auto-detect"):
    try:
        return block_ip(src_ip, ttl_seconds=ttl_seconds, reason=reason)
    except Exception as e:
        print("❌ firewall action failed:", e)
        return False
