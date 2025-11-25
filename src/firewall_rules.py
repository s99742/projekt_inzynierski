#!/usr/bin/env python3
"""
firewall_rules.py

Funkcje dodawania/usuwania reguł firewall (iptables/nftables fallback).
Zapis informacji o regułach do SQLite.
Uwaga: wykonywanie poleceń wymaga uprawnień roota.
"""

import subprocess
import threading
import ipaddress
import sqlite3
import shutil
import os
from datetime import datetime, timedelta
from config_and_db import DB_PATH, init_db

# Upewnij się, że tabela istnieje
init_db()

def validate_ip(ip_str):
    try:
        return str(ipaddress.ip_address(ip_str))
    except Exception:
        raise ValueError(f"Invalid IP: {ip_str}")

def _run_cmd(cmd):
    """Uruchamia polecenie i zwraca (returncode, stdout, stderr)."""
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return 1, "", str(e)

def _has_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows fallback (nie wspierane)
        return False

def _iptables_block_cmd(src_ip):
    return ["iptables", "-I", "INPUT", "-s", src_ip, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"]

def _iptables_unblock_cmd(src_ip):
    return ["iptables", "-D", "INPUT", "-s", src_ip, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"]

def _nft_block_cmd(src_ip):
    # nft rule dla inet table filter chain input
    return ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", src_ip, "drop"]

def _nft_unblock_cmd(src_ip):
    # usunięcie reguły - bezpośrednie usuwanie wymaga znajomości handle; spróbujemy użyć 'delete rule' przez match
    return ["nft", "delete", "rule", "inet", "filter", "input", "ip", "saddr", src_ip, "drop"]

def _insert_rule_db(src_ip, expiry, reason):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO firewall_rules(added_at, src_ip, dst_ip, src_port, dst_port, protocol, action, expiry, reason)
        VALUES(?,?,?,?,?,?,?,?,?)
    """, (datetime.utcnow().isoformat(), src_ip, None, None, None, None, "DROP", expiry, reason))
    conn.commit()
    conn.close()

def _update_rule_expiry_db(src_ip):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE firewall_rules SET expiry = ? WHERE src_ip = ? AND expiry IS NOT NULL", (datetime.utcnow().isoformat(), src_ip))
    conn.commit()
    conn.close()

def block_ip(src_ip, ttl_seconds=600, reason=None):
    """
    Dodaje regułę blokującą dla src_ip na ttl_seconds (None => permanentny).
    Zwraca True jeśli dodanie się powiodło (albo reguła zapisana w DB).
    """
    src_ip = validate_ip(src_ip)
    expiry = (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat() if ttl_seconds else None

    # spróbuj dodać regułę iptables -> nft fallback
    if not _has_root():
        # nadal zapisujemy w DB informację, ale nie modyfikujemy iptables
        _insert_rule_db(src_ip, expiry, reason or "blocked (no-root)")
        raise PermissionError("blocking requires root privileges (run as root)")

    # try iptables
    rc, out, err = _run_cmd(_iptables_block_cmd(src_ip))
    if rc != 0:
        # spróbuj nft
        rc2, out2, err2 = _run_cmd(_nft_block_cmd(src_ip))
        if rc2 != 0:
            # obie metody nie powiodły się
            raise RuntimeError(f"Failed to add block rule: iptables err='{err}' nft err='{err2}'")
    # zapis do DB
    _insert_rule_db(src_ip, expiry, reason or "auto-detect")

    # planowane usunięcie
    if ttl_seconds:
        t = threading.Timer(ttl_seconds, unblock_ip, args=(src_ip,))
        t.daemon = True
        t.start()

    return True

def unblock_ip(src_ip):
    """
    Usuwa regułę blokującą src_ip — próbuje iptables a potem nft.
    """
    src_ip = validate_ip(src_ip)

    if not _has_root():
        _update_rule_expiry_db(src_ip)
        raise PermissionError("unblocking requires root privileges (run as root)")

    # spróbuj usunąć iptables (może być kilka kopii) - max kilka prób
    for _ in range(5):
        rc, out, err = _run_cmd(_iptables_unblock_cmd(src_ip))
        if rc != 0:
            break

    # spróbuj nft (może nie istnieć)
    rc2, out2, err2 = _run_cmd(_nft_unblock_cmd(src_ip))
    # zaktualizuj DB
    _update_rule_expiry_db(src_ip)
    return True

def take_mitigation_action(src_ip, ttl_seconds=600, reason="auto-detect"):
    try:
        return block_ip(src_ip, ttl_seconds=ttl_seconds, reason=reason)
    except PermissionError as e:
        # jeśli brak uprawnień — wypisz info i zapisz do DB bez zmiany iptables
        try:
            _insert_rule_db(src_ip, (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat() if ttl_seconds else None, f"{reason} (no-root)")
        except Exception:
            pass
        print("❌ firewall action (permission):", e)
        return False
    except Exception as e:
        print("❌ firewall action failed:", e)
        return False
