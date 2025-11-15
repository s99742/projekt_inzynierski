# firewall_tab_tk.py
import sqlite3
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
import os

# Absolutna ścieżka do DB
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "logs/project_logs.db")


class FirewallTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        title = tk.Label(self, text="Zablokowane adresy IP", font=("Arial", 14, "bold"))
        title.pack(pady=5)

        # -------- TABELA --------
        self.tree = ttk.Treeview(
            self,
            columns=("ip", "prediction"),
            show="headings",
            height=20
        )
        self.tree.heading("ip", text="Źródło IP")
        self.tree.heading("prediction", text="Predykcja")
        self.tree.column("ip", width=150)
        self.tree.column("prediction", width=200)
        self.tree.pack(fill="both", expand=True, pady=5)

        # -------- PANEL DODAWANIA / USUWANIA IP --------
        frame = tk.Frame(self)
        frame.pack(fill="x", pady=5)

        tk.Label(frame, text="IP:").pack(side="left")
        self.ip_entry = tk.Entry(frame)
        self.ip_entry.pack(side="left", padx=5)

        tk.Button(frame, text="Zablokuj IP", command=self.block_manual).pack(side="left", padx=5)
        tk.Button(frame, text="Odblokuj IP", command=self.unblock_manual).pack(side="left", padx=5)
        tk.Button(frame, text="Odśwież", command=self.load_data).pack(side="left", padx=5)

        # Pierwsze wczytanie danych
        self.load_data()

    # ---------------------------------------------------
    # ŁADOWANIE LISTY BLOKOWANYCH IP Z BAZY
    # ---------------------------------------------------
    def load_data(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                SELECT src_ip, prediction
                FROM logs
                WHERE decision='DROP'
                ORDER BY id DESC LIMIT 100
            """)
            rows = c.fetchall()
            conn.close()
        except Exception as e:
            messagebox.showerror("Błąd DB", str(e))
            return

        for ip, pred in rows:
            self.tree.insert("", "end", values=(ip, pred))

    # ---------------------------------------------------
    # BLOKOWANIE IP PRZEZ IPTABLES
    # ---------------------------------------------------
    def block_ip(self, ip):
        try:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )
            return True
        except Exception as e:
            messagebox.showerror("Błąd iptables", str(e))
            return False

    def unblock_ip(self, ip):
        try:
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )
            return True
        except Exception as e:
            messagebox.showerror("Błąd iptables", str(e))
            return False

    # ---------------------------------------------------
    # PRZYCISKI RĘCZNEGO BLOKOWANIA
    # ---------------------------------------------------
    def block_manual(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            return messagebox.showwarning("Uwaga", "Podaj IP.")
        if self.block_ip(ip):
            messagebox.showinfo("OK", f"Zablokowano IP: {ip}")
            self.load_data()

    def unblock_manual(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            return messagebox.showwarning("Uwaga", "Podaj IP.")
        if self.unblock_ip(ip):
            messagebox.showinfo("OK", f"Odblokowano IP: {ip}")
            self.load_data()
