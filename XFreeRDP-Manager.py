#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Tuple

# ── optional extras ───────────────────────────────────────────
try:
    import pyotp
except ModuleNotFoundError:
    pyotp = None

try:
    import psutil
except ModuleNotFoundError:
    psutil = None

try:
    import qrcode
    from PIL import Image, ImageTk
    QR_AVAILABLE = True
except ModuleNotFoundError:
    QR_AVAILABLE = False

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tkinter import filedialog, messagebox, simpledialog

import ttkbootstrap as ttk
from ttkbootstrap.constants import LEFT

try:
    from argon2.low_level import hash_secret_raw, Type as ArgonType

    ARGON2_AVAILABLE = True
except ModuleNotFoundError:
    ARGON2_AVAILABLE = False

__version__ = "0.5.1"

# ───────────────────────── logging ────────────────────────────
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
)

# ─────────────────────── paths / constants ────────────────────
CFG_DIR = Path.home() / ".rdp_gui"
CFG_DIR.mkdir(exist_ok=True)
CFG_DIR.chmod(0o700)

CFG_FILE = CFG_DIR / "rdp_connections.json"
MAC_FILE = CFG_DIR / "rdp_connections.mac"
PW_FILE = CFG_DIR / "master.hash"
TOTP_FILE = CFG_DIR / "totp.enc"
MAC_SALT_FILE = CFG_DIR / "mac.salt"

PBKDF2_ITERATIONS = 600_000
BACKUP_ITER = 600_000 
ARGON2_PARAMS: Tuple[int, int, int] = (19 * 1024, 2, 1)

# ────────────────── helper: locate xfreerdp ───────────────────
def _find_rdp_binary() -> str:
    for candidate in ("xfreerdp3", "xfreerdp"):
        path = shutil.which(candidate)
        if path:
            return path
    messagebox.showerror("xfreerdp", "Neither xfreerdp3 nor xfreerdp found in $PATH")
    sys.exit(1)


RDP_BIN = _find_rdp_binary()

# ──────────────── KDF / crypto primitives ─────────────────────
def _pbkdf2(pw: str, salt: bytes, iterations: int, length: int = 32) -> bytes:
    return PBKDF2HMAC(hashes.SHA256(), length, salt, iterations).derive(pw.encode())


def _argon2(pw: str, salt: bytes) -> bytes:
    m_cost, t_cost, lanes = ARGON2_PARAMS
    return hash_secret_raw(
        pw.encode(),
        salt,
        time_cost=t_cost,
        memory_cost=m_cost,
        parallelism=lanes,
        hash_len=32,
        type=ArgonType.ID,
    )


def _derive_key(pw: str, salt: bytes, iterations: int | None) -> Tuple[bytes, str]:
    if iterations is None and ARGON2_AVAILABLE:
        return _argon2(pw, salt), "a2"
    if iterations is None:
        iterations = PBKDF2_ITERATIONS
    return _pbkdf2(pw, salt, iterations), f"pbkdf2:{iterations}"


def _ensure_perms(path: Path, mode: int) -> None:
    if path.exists() and (path.stat().st_mode & 0o777) != mode:
        messagebox.showerror("Security", f"{path} permissions must be {oct(mode)}.")
        sys.exit(1)

# ────────────── Encryption / HMAC managers ────────────────────
class EncryptionManager:
    """Symmetric encryption + HMAC key derivation."""

    def __init__(self, master_pw: str):
        self.master_pw = master_pw

    # — Fernet with header —
    def enc(self, plaintext: str) -> str:
        salt = os.urandom(16)
        key, tag = _derive_key(self.master_pw, salt, None)
        tok = Fernet(base64.urlsafe_b64encode(key)).encrypt(plaintext.encode()).decode()
        return f"{tag}${base64.b64encode(salt).decode()}${tok}"

    def dec(self, blob: str) -> str:
        tag, salt_b64, tok = blob.split("$", 2)
        salt = base64.b64decode(salt_b64)
        if tag == "a2":
            if not ARGON2_AVAILABLE:
                raise RuntimeError("Argon2 unavailable")
            key = _argon2(self.master_pw, salt)
        else:
            _, it = tag.split(":")
            key = _pbkdf2(self.master_pw, salt, int(it))
        return Fernet(base64.urlsafe_b64encode(key)).decrypt(tok.encode()).decode()

    # — HMAC key (fixed salt) —
    def mac_key(self) -> bytes:
        if not MAC_SALT_FILE.exists():
            MAC_SALT_FILE.write_bytes(os.urandom(16))
            MAC_SALT_FILE.chmod(0o600)
        salt = MAC_SALT_FILE.read_bytes()
        return _pbkdf2(self.master_pw, salt, PBKDF2_ITERATIONS)


def _mac(data: str, key: bytes) -> str:
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()

# ─────────── TOTP helpers ───────────
def _setup_totp(enc: EncryptionManager, parent: tk.Widget) -> None:
    """Create a new TOTP secret and show a QR if possible."""
    if pyotp is None:
        messagebox.showerror("TOTP", "pyotp not installed; cannot enable 2‑factor.", parent=parent)
        sys.exit(1)

    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri("xfreerdp‑GUI", issuer_name="Local")

    TOTP_FILE.write_text(enc.enc(secret))
    TOTP_FILE.chmod(0o600)

    # ── display window ──
    win = tk.Toplevel(parent)
    win.title("2‑Factor Authentication")
    win.resizable(False, False)
    frm = ttk.Frame(win, padding=15)
    frm.pack(fill="both", expand=True)

    ttk.Label(
        frm,
        text="Scan this QR (or enter the secret) in Google Authenticator:",
        font=("TkDefaultFont", 10, "bold"),
    ).pack(anchor="w", pady=(0, 8))

    if QR_AVAILABLE:
        qr_img = qrcode.make(uri)
        buf = io.BytesIO()
        qr_img.save(buf, format="PNG")
        buf.seek(0)
        tk_img = ImageTk.PhotoImage(Image.open(buf))
        ttk.Label(frm, image=tk_img).pack()
        win.qr_ref = tk_img  
    else:
        ttk.Label(
            frm,
            text="(Install the 'qrcode' and 'pillow' packages to get a QR code automatically)\n",
            foreground="red",
        ).pack()

    ttk.Label(frm, text=f"URI:\n{uri}", wraplength=320, justify="left").pack(anchor="w", pady=(8, 4))
    ttk.Label(frm, text=f"Secret:\n{secret}", wraplength=320, justify="left").pack(anchor="w")

    ttk.Button(frm, text="OK", command=win.destroy).pack(pady=10)
    win.wait_window()


def _verify_totp(enc: EncryptionManager, parent: tk.Widget) -> None:
    if pyotp is None:
        return  # 2FA disabled
    if not TOTP_FILE.exists():
        _setup_totp(enc, parent)
        return
    try:
        secret = enc.dec(TOTP_FILE.read_text())
    except Exception as e:
        messagebox.showerror("TOTP", f"Cannot read TOTP secret: {e}", parent=parent)
        sys.exit(1)
    for _ in range(3):
        code = simpledialog.askstring(
            "Two‑Factor Authentication", "Enter 6‑digit code:", show="*", parent=parent
        )
        if code is None:
            sys.exit(0)
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            return
        messagebox.showerror("Error", "Invalid code", parent=parent)
    sys.exit(1)

# ─────────── master password helpers ────────────
def _hash_pw(pw: str) -> str:
    salt = os.urandom(16)
    if ARGON2_AVAILABLE:
        key, tag = _argon2(pw, salt), "a2"
    else:
        key, tag = _pbkdf2(pw, salt, PBKDF2_ITERATIONS), f"pbkdf2:{PBKDF2_ITERATIONS}"
    return f"{tag}${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"


def _verify_pw(stored: str, pw: str) -> bool:
    tag, salt_b64, key_b64 = stored.split("$", 2)
    salt, stored_key = base64.b64decode(salt_b64), base64.b64decode(key_b64)
    if tag == "a2":
        if not ARGON2_AVAILABLE:
            return False
        calc = _argon2(pw, salt)
    else:
        _, it = tag.split(":")
        calc = _pbkdf2(pw, salt, int(it))
    return hmac.compare_digest(calc, stored_key)


def _prompt_pw(parent: tk.Widget, title: str, prompt: str) -> str | None:
    return simpledialog.askstring(title, prompt, show="*", parent=parent)

def _get_master() -> str:
    temp_root = tk.Tk()
    temp_root.withdraw()

    _ensure_perms(CFG_DIR, 0o700)
    if not PW_FILE.exists():
        while True:
            p1 = _prompt_pw(temp_root, "Set Master Password", "Create a strong master password:")
            if p1 is None:
                temp_root.destroy()
                sys.exit(0)
            p2 = _prompt_pw(temp_root, "Confirm", "Re‑enter master password:")
            if p1 != p2:
                messagebox.showerror("Mismatch", "Passwords do not match", parent=temp_root)
                continue
            PW_FILE.write_text(_hash_pw(p1)); PW_FILE.chmod(0o600)
            enc = EncryptionManager(p1)
            _setup_totp(enc, parent=temp_root)
            temp_root.destroy()
            return p1
    for _ in range(5):
        pw = _prompt_pw(temp_root, "Master Password", "Enter master password:")
        if pw and _verify_pw(PW_FILE.read_text(), pw):
            enc = EncryptionManager(pw)
            _verify_totp(enc, parent=temp_root)
            temp_root.destroy()
            return pw
        messagebox.showerror("Error", "Invalid password", parent=temp_root)
    temp_root.destroy()
    sys.exit(1)

# ───────────── config manager (with MAC) ─────────────
class ConfigManager:
    def __init__(self, path: Path, mac_path: Path, mac_key: bytes):
        self.path, self.mac_path, self.mac_key = path, mac_path, mac_key
        self.connections: Dict[str, Dict[str, Any]] = self._load()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        if not self.path.exists():
            return {}
        try:
            raw = self.path.read_text()
            stored_mac = self.mac_path.read_text()
            if not hmac.compare_digest(stored_mac, _mac(raw, self.mac_key)):
                raise ValueError("Config file MAC mismatch – wrong password or tamper.")
        except FileNotFoundError:
            messagebox.showerror("Integrity", "MAC file missing – aborting.")
            sys.exit(1)
        except Exception as e:
            messagebox.showerror("Integrity", str(e)); sys.exit(1)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            messagebox.showerror("Corrupt", f"Config corrupt: {e}"); sys.exit(1)

    def _atomic_write(self, data: str) -> None:
        tmp_fd, tmp_name = tempfile.mkstemp(dir=str(self.path.parent))
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as tmp:
            tmp.write(data); tmp.flush(); os.fsync(tmp.fileno())
        os.replace(tmp_name, self.path)
        self.mac_path.write_text(_mac(data, self.mac_key)); self.mac_path.chmod(0o600)

    def save(self) -> None:
        self._atomic_write(json.dumps(self.connections, indent=4))

    # helpers
    def add(self, name: str, data: Dict[str, Any]) -> None:
        self.connections[name] = data; self.save()

    def delete(self, name: str) -> None:
        self.connections.pop(name, None); self.save()

# ─────────── encrypted backup helpers ────────────
def _enc_backup(json_payload: str, pw: str) -> str:
    salt = os.urandom(16)
    key = _pbkdf2(pw, salt, BACKUP_ITER)
    tok = Fernet(base64.urlsafe_b64encode(key)).encrypt(json_payload.encode()).decode()
    return f"bak:{BACKUP_ITER}${base64.b64encode(salt).decode()}${tok}"

def _dec_backup(blob: str, pw: str) -> str:
    hdr, salt_b64, tok = blob.split("$", 2)
    if not hdr.startswith("bak:"):
        raise ValueError("Not a backup file")
    salt, iterations = base64.b64decode(salt_b64), int(hdr.split(":")[1])
    key = _pbkdf2(pw, salt, iterations)
    return Fernet(base64.urlsafe_b64encode(key)).decrypt(tok.encode()).decode()

# ──────────────────────── GUI class ───────────────────────────
class RDPApp(ttk.Window):
    def __init__(self, enc: EncryptionManager, cfg: ConfigManager):
        super().__init__(themename="darkly")
        self.enc, self.cfg = enc, cfg
        self.active: Dict[str, subprocess.Popen] = {}
        self.sess_ctr = 1

        self._define_vars()
        self._build_ui()
        self._refresh_tree()

        self.title("Advanced xfreerdp GUI")
        self.geometry("800x500")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._scan_orphans()

    # ── orphan processes (optional) ──
    def _scan_orphans(self):
        if psutil is None:
            return
        orphans = [
            p for p in psutil.process_iter(["pid", "cmdline"])
            if p.info["cmdline"]
            and p.info["cmdline"][0].endswith("xfreerdp")
            and "/from-stdin" in p.info["cmdline"]
        ]
        if orphans and messagebox.askyesno(
            "Orphan sessions", f"Terminate {len(orphans)} stray xfreerdp processes?", parent=self
        ):
            for p in orphans:
                try: os.killpg(p.pid, signal.SIGTERM)
                except Exception: pass

    # ── Tk variables ──
    def _define_vars(self):
        self.profile_entry = ttk.Entry()
        self.group_entry = ttk.Entry()
        self.server_entry = ttk.Entry()
        self.user_entry = ttk.Entry()
        self.password_entry = ttk.Entry()
        self.domain_entry = ttk.Entry()
        self.resolution_var = tk.StringVar(value="1920x1080")
        self.dynamic_resolution_var = tk.BooleanVar()

        # advanced
        self.clipboard_var = tk.BooleanVar()
        self.ignore_cert_var = tk.BooleanVar()
        self.sec_protocol_var = tk.StringVar(value="Auto")
        self.enforce_tls_var = tk.BooleanVar()
        self.debug_mode_var = tk.BooleanVar()
        self.audio_var = tk.BooleanVar()
        self.printer_var = tk.BooleanVar()
        self.smartcard_var = tk.BooleanVar()
        self.usb_var = tk.BooleanVar()
        self.fullscreen_var = tk.BooleanVar()
        self.multimon_var = tk.BooleanVar()
        self.advanced_extra_var = tk.StringVar()

        self.search_var = tk.StringVar()
        self.debug_mode_var.trace_add("write", self._toggle_debug)
        self.show_pw_var = tk.BooleanVar()

        self.cmd_preview_box: tk.Text | None = None

    # ── build UI ──
    def _build_ui(self):
        self.rowconfigure(0, weight=1); self.columnconfigure(0, weight=1)
        main = ttk.Frame(self, padding=10); main.grid(sticky="nsew")
        main.columnconfigure(0, weight=1, uniform="c"); main.columnconfigure(1, weight=2, uniform="c")
        main.rowconfigure(1, weight=1)

        self._build_tree(main); self._build_notebook(main); self._build_menu()

    # ── menu ──
    def _build_menu(self):
        m = tk.Menu(self)
        file_m = tk.Menu(m, tearoff=0)
        file_m.add_command(label="Backup Profiles…", command=self._backup_profiles)
        file_m.add_command(label="Restore Profiles…", command=self._restore_profiles)
        file_m.add_separator(); file_m.add_command(label="Exit", command=self._on_close)
        m.add_cascade(label="File", menu=file_m)

        sess_m = tk.Menu(m, tearoff=0)
        sess_m.add_command(label="Show Active Sessions", command=self._open_sessions)
        m.add_cascade(label="Sessions", menu=sess_m)

        help_m = tk.Menu(m, tearoff=0)
        help_m.add_command(label="About", command=self._about)
        m.add_cascade(label="Help", menu=help_m)

        self.config(menu=m)

    # ── tree panel ──
    def _build_tree(self, parent):
        box = ttk.LabelFrame(parent, text="Connections", padding=5)
        box.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 10))
        box.columnconfigure(0, weight=1); box.rowconfigure(1, weight=1)

        sfrm = ttk.Frame(box); sfrm.grid(row=0, column=0, columnspan=2, sticky="ew")
        ttk.Label(sfrm, text="Search:").pack(side=LEFT)
        ttk.Entry(sfrm, textvariable=self.search_var, width=25).pack(
            side=LEFT, padx=5, fill="x", expand=True)
        self.search_var.trace_add("write", self._refresh_tree)

        self.tree = ttk.Treeview(box, show="tree")
        self.tree.grid(row=1, column=0, sticky="nsew")
        sb = ttk.Scrollbar(box, orient="vertical", command=self.tree.yview)
        sb.grid(row=1, column=1, sticky="ns"); self.tree.configure(yscrollcommand=sb.set)
        self.tree.bind("<Double-1>", self._tree_dbl)
        self.tree.bind("<<TreeviewSelect>>", self._tree_sel)

    def _refresh_tree(self, *_):
        self.tree.delete(*self.tree.get_children())
        grp_nodes: Dict[str, str] = {}
        ungrp_id: str | None = None
        filt = self.search_var.get().lower()

        for prof, data in self.cfg.connections.items():
            grp_path = (data.get("group") or "").strip()
            if filt and filt not in prof.lower() and filt not in grp_path.lower():
                continue
            if not grp_path:
                if ungrp_id is None:
                    ungrp_id = self.tree.insert("", "end", text="Ungrouped")
                self.tree.insert(ungrp_id, "end", text=prof); continue
            parent = ""
            built: List[str] = []
            for part in grp_path.split("/"):
                built.append(part); key = "/".join(built)
                if key not in grp_nodes:
                    grp_nodes[key] = self.tree.insert(parent, "end", text=part)
                parent = grp_nodes[key]
            self.tree.insert(parent, "end", text=prof)

    def _tree_sel(self, *_):
        sel = self.tree.selection()
        if not sel: return
        iid = sel[0]
        if self.tree.get_children(iid):
            self._clear_form()
        else:
            self._load_profile(self.tree.item(iid, "text"))

    def _tree_dbl(self, event):
        iid = self.tree.identify_row(event.y)
        if iid and not self.tree.get_children(iid):
            self._connect()

    # ── notebook / form ──
    def _build_notebook(self, parent):
        nb = ttk.Notebook(parent); nb.grid(row=0, column=1, rowspan=2, sticky="nsew")
        tab = ttk.Frame(nb, padding=10); nb.add(tab, text="Connection Settings")
        tab.columnconfigure(1, weight=1)

        # widgets
        self.profile_entry = ttk.Entry(tab, width=28)
        self.group_entry = ttk.Entry(tab, width=28)
        self.server_entry = ttk.Entry(tab, width=28)
        self.user_entry = ttk.Entry(tab, width=28)
        self.password_entry = ttk.Entry(tab, width=28, show="*")
        self.domain_entry = ttk.Entry(tab, width=28)

        row = 0
        for lbl, wid in (
            ("Profile Name:", self.profile_entry),
            ("Group:", self.group_entry),
            ("Server:", self.server_entry),
            ("Username:", self.user_entry),
            ("Password:", self.password_entry),
            ("Domain:", self.domain_entry),
        ):
            ttk.Label(tab, text=lbl).grid(row=row, column=0, sticky="w", pady=2)
            wid.grid(row=row, column=1, sticky="w", pady=2); row += 1
        ttk.Checkbutton(tab, text="Show", variable=self.show_pw_var,
                        command=self._toggle_pw).grid(row=4, column=2, sticky="w")

        ttk.Label(tab, text="Resolution:").grid(row=row, column=0, sticky="w")
        ttk.OptionMenu(
            tab, self.resolution_var, "1920x1080",
            "1920x1080", "1366x768", "1280x720", "1024x768"
        ).grid(row=row, column=1, sticky="w"); row += 1
        ttk.Checkbutton(
            tab, text="Dynamic Resolution", variable=self.dynamic_resolution_var
        ).grid(row=row, column=1, sticky="w"); row += 1

        ttk.Button(tab, text="Advanced Settings",
                   command=self._open_adv).grid(row=row, column=0, sticky="w", pady=6)
        ttk.Button(tab, text="Clone Profile",
                   command=self._clone_profile).grid(row=row, column=1, sticky="w"); row += 1

        btn_box = ttk.Frame(tab); btn_box.grid(row=row, column=0, columnspan=3, pady=10)
        for txt, cmd in (("Save Profile", self._save_profile),
                         ("Delete Profile", self._del_profile),
                         ("Connect", self._connect)):
            ttk.Button(btn_box, text=txt, command=cmd).pack(side=LEFT, padx=5)

    # ── advanced popup ──
    def _open_adv(self):
        win = tk.Toplevel(self); win.title("Advanced"); win.geometry("520x640")
        row = 0
        for txt, var in (("Clipboard (+clipboard)", self.clipboard_var),
                         ("Ignore Cert (/cert:ignore)", self.ignore_cert_var)):
            ttk.Checkbutton(win, text=txt, variable=var
                            ).grid(row=row, column=0, sticky="w", padx=10, pady=5); row += 1
        ttk.Label(win, text="Security Protocol:").grid(row=row, column=0, sticky="w", padx=10)
        ttk.OptionMenu(win, self.sec_protocol_var, "Auto", "Auto", "TLS", "NLA", "RDP"
                       ).grid(row=row, column=1, sticky="w"); row += 1
        for txt, var in (
            ("Enforce TLS v1.2", self.enforce_tls_var),
            ("Debug Mode (/log-level:DEBUG)", self.debug_mode_var),
            ("Audio Redirection (/sound)", self.audio_var),
            ("Printer Redirection (/printer)", self.printer_var),
            ("Smartcard Redirection (/smartcard)", self.smartcard_var),
            ("USB Redirection (/usb:auto)", self.usb_var),
            ("Fullscreen (/f)", self.fullscreen_var),
            ("Multi-monitor (/multimon)", self.multimon_var),
        ):
            ttk.Checkbutton(win, text=txt, variable=var
                            ).grid(row=row, column=0, sticky="w", padx=10, pady=5); row += 1
        ttk.Label(win, text="Additional options:").grid(row=row, column=0, sticky="w", padx=10)
        ttk.Entry(win, textvariable=self.advanced_extra_var, width=32
                  ).grid(row=row, column=1, sticky="w", padx=10); row += 1

        box = ttk.LabelFrame(win, text="Command Preview", padding=10)
        box.grid(row=row, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        self.cmd_preview_box = tk.Text(box, height=3, width=60, wrap="none")
        self.cmd_preview_box.grid(row=0, column=0, sticky="nsew")
        ttk.Scrollbar(box, orient="horizontal",
                      command=self.cmd_preview_box.xview
                      ).grid(row=1, column=0, sticky="ew")
        self.cmd_preview_box.configure(xscrollcommand=self.cmd_preview_box.xview)
        ttk.Button(box, text="Preview", command=self._update_preview
                   ).grid(row=2, column=0, pady=5)
        row += 1
        ttk.Button(win, text="Close", command=win.destroy
                   ).grid(row=row, column=0, columnspan=2, pady=10)

    def _update_preview(self):
        if self.cmd_preview_box:
            cmd = " ".join(self._build_cmd(redact_pw=True))
            self.cmd_preview_box.delete("1.0", tk.END); self.cmd_preview_box.insert(tk.END, cmd)

    # ── password show‑toggle ──
    def _toggle_pw(self): self.password_entry.config(show="" if self.show_pw_var.get() else "*")

    # ── debug toggle ──
    def _toggle_debug(self, *_):
        logging.getLogger().setLevel(logging.DEBUG if self.debug_mode_var.get() else logging.INFO)

    # ── clear form ──
    def _clear_form(self):
        for e in (self.profile_entry, self.group_entry, self.server_entry,
                  self.user_entry, self.password_entry, self.domain_entry):
            e.delete(0, tk.END)
        self.resolution_var.set("1920x1080"); self.dynamic_resolution_var.set(False)
        for var in (self.clipboard_var, self.ignore_cert_var, self.enforce_tls_var,
                    self.debug_mode_var, self.audio_var, self.printer_var,
                    self.smartcard_var, self.usb_var, self.fullscreen_var,
                    self.multimon_var):
            var.set(False)
        self.sec_protocol_var.set("Auto"); self.advanced_extra_var.set("")
        self.show_pw_var.set(False); self.password_entry.config(show="*")

    # ── load profile ──
    def _load_profile(self, name: str):
        d = self.cfg.connections.get(name, {})
        self.profile_entry.delete(0, tk.END); self.profile_entry.insert(0, name)
        for wid, key in ((self.group_entry, "group"),
                         (self.server_entry, "server"),
                         (self.user_entry, "username"),
                         (self.domain_entry, "domain")):
            wid.delete(0, tk.END); wid.insert(0, d.get(key, ""))
        try:
            pw = self.enc.dec(d.get("password", "")) if d.get("password") else ""
        except Exception: pw = ""
        self.password_entry.delete(0, tk.END); self.password_entry.insert(0, pw)

        self.resolution_var.set(d.get("resolution", "1920x1080"))
        self.dynamic_resolution_var.set(d.get("dynamic_resolution", False))
        self.clipboard_var.set(d.get("clipboard", False))
        self.ignore_cert_var.set(d.get("ignore_cert", False))
        self.sec_protocol_var.set(d.get("security_protocol", "Auto"))
        self.enforce_tls_var.set(d.get("enforce_tls", False))
        self.debug_mode_var.set(d.get("debug_mode", False))
        self.audio_var.set(d.get("audio", False))
        self.printer_var.set(d.get("printer", False))
        self.smartcard_var.set(d.get("smartcard", False))
        self.usb_var.set(d.get("usb", False))
        self.fullscreen_var.set(d.get("fullscreen", False))
        self.multimon_var.set(d.get("multimon", False))
        self.advanced_extra_var.set(d.get("advanced_extra", ""))

    # ── save / delete / clone ──
    def _save_profile(self):
        name = self.profile_entry.get().strip()
        if not name:
            messagebox.showerror("Error", "Profile name required", parent=self); return
        pdata = {
            "group": self.group_entry.get().strip(),
            "server": self.server_entry.get().strip(),
            "username": self.user_entry.get().strip(),
            "password": self.enc.enc(self.password_entry.get()) if self.password_entry.get() else "",
            "domain": self.domain_entry.get().strip(),
            "resolution": self.resolution_var.get(),
            "dynamic_resolution": self.dynamic_resolution_var.get(),
            "clipboard": self.clipboard_var.get(),
            "ignore_cert": self.ignore_cert_var.get(),
            "security_protocol": self.sec_protocol_var.get(),
            "enforce_tls": self.enforce_tls_var.get(),
            "debug_mode": self.debug_mode_var.get(),
            "audio": self.audio_var.get(), "printer": self.printer_var.get(),
            "smartcard": self.smartcard_var.get(), "usb": self.usb_var.get(),
            "fullscreen": self.fullscreen_var.get(), "multimon": self.multimon_var.get(),
            "advanced_extra": self.advanced_extra_var.get().strip(),
        }
        self.cfg.add(name, pdata); self._refresh_tree()
    def _del_profile(self):
        n = self.profile_entry.get().strip()
        if n in self.cfg.connections and messagebox.askyesno("Delete", f"Delete '{n}'?", parent=self):
            self.cfg.delete(n); self._refresh_tree(); self._clear_form()
    def _clone_profile(self):
        src = self.profile_entry.get().strip()
        if src not in self.cfg.connections:
            messagebox.showerror("Error", "Load a profile first", parent=self); return
        dst = simpledialog.askstring("Clone", "New profile name:", parent=self)
        if not dst: return
        if dst in self.cfg.connections:
            messagebox.showerror("Exists", "Profile already exists", parent=self); return
        self.cfg.add(dst, dict(self.cfg.connections[src])); self._refresh_tree()

    # ── build xfreerdp command ──
    @staticmethod
    def _parse_res(s: str) -> Tuple[int, int] | None:
        try: w,h = map(int, s.lower().split("x")); return (w,h) if w>0 and h>0 else None
        except Exception: return None
    def _build_cmd(self, *, redact_pw=False) -> List[str]:
        if not self.dynamic_resolution_var.get():
            if self._parse_res(self.resolution_var.get()) is None:
                raise ValueError("Invalid resolution")
        cmd = [RDP_BIN,
               f"/v:{self.server_entry.get().strip()}",
               f"/u:{self.user_entry.get().strip()}",
               "/from-stdin"]
        d = self.domain_entry.get().strip()
        if d: cmd.append(f"/d:{d}")
        if self.dynamic_resolution_var.get():
            cmd.append("/dynamic-resolution")
        else: cmd.append(f"/size:{self.resolution_var.get()}")
        if self.clipboard_var.get(): cmd.append("+clipboard")
        if self.ignore_cert_var.get(): cmd.append("/cert:ignore")
        sec = self.sec_protocol_var.get(); 
        if sec != "Auto": cmd.append(f"/sec:{sec.lower()}")
        if self.enforce_tls_var.get(): cmd.append("/tls-seclevel:+enforce-tlsv1_2")
        if self.debug_mode_var.get(): cmd.append("/log-level:DEBUG")
        if self.audio_var.get(): cmd.append("/sound")
        if self.printer_var.get(): cmd.append("/printer")
        if self.smartcard_var.get(): cmd.append("/smartcard")
        if self.usb_var.get(): cmd.append("/usb:auto")
        if self.fullscreen_var.get(): cmd.append("/f")
        if self.multimon_var.get(): cmd.append("/multimon")
        extra = self.advanced_extra_var.get().strip()
        if extra: cmd.extend(extra.split())
        return cmd

    # ── connect ──
    def _connect(self):
        if not self.server_entry.get().strip() or not self.user_entry.get().strip():
            messagebox.showerror("Error", "Server & Username required", parent=self); return
        try: cmd = self._build_cmd()
        except ValueError as e:
            messagebox.showerror("Error", str(e), parent=self); return
        try:
            proc = subprocess.Popen(
                cmd, stdin=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            if proc.stdin:
                pw = self.password_entry.get(); proc.stdin.write((pw+"\n").encode()); proc.stdin.close()
            sid = f"sess-{self.sess_ctr}"; self.sess_ctr += 1
            self.active[sid] = proc
        except Exception as e:
            messagebox.showerror("xfreerdp", str(e), parent=self)

    # ── process kill helper ──
    def _kill_pg(self, proc: subprocess.Popen):
        try:
            os.killpg(proc.pid, signal.SIGTERM); time.sleep(2)
            if proc.poll() is None: os.killpg(proc.pid, signal.SIGKILL)
        except Exception: proc.kill()

    # ── active sessions window ──
    def _open_sessions(self):
        win = tk.Toplevel(self); win.title("Sessions")
        tree = ttk.Treeview(win, columns=("id","pid"), show="headings")
        for c in ("id","pid"): tree.heading(c, text=c.upper())
        tree.grid(row=0, column=0, columnspan=2, sticky="nsew")
        win.columnconfigure(0, weight=1); win.rowconfigure(0, weight=1)
        sb = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        sb.grid(row=0, column=2, sticky="ns"); tree.config(yscrollcommand=sb.set)
        def refresh():
            dead=[sid for sid,p in self.active.items() if p.poll() is not None]
            for d in dead: self.active.pop(d,None)
            tree.delete(*tree.get_children())
            for sid,p in self.active.items(): tree.insert("", "end", iid=sid, values=(sid,p.pid))
            win.after(3000, refresh)
        refresh()
        def kill():
            sel=tree.selection(); 
            if not sel: return
            sid=sel[0]; self._kill_pg(self.active[sid]); self.active.pop(sid,None); refresh()
        ttk.Button(win, text="Kill", command=kill).grid(
            row=1,column=0,sticky="w",padx=5,pady=5)
        ttk.Button(win, text="Refresh", command=refresh).grid(
            row=1,column=1,sticky="e",padx=5,pady=5)

    # ── backup / restore ──
    def _backup_profiles(self):
        dst = filedialog.asksaveasfilename(
            title="Save backup", defaultextension=".rdpbak",
            filetypes=[("Encrypted backup","*.rdpbak"), ("All","*.*")],
            parent=self
        )
        if not dst: return
        pw = simpledialog.askstring(
            "Backup Password",
            "Enter backup password (leave blank to use master password):",
            show="*",
            parent=self
        )
        if pw is None: return
        if pw == "": pw = self.enc.master_pw
        payload = json.dumps({
            "master_hash": PW_FILE.read_text(),
            "connections": self.cfg.connections,
            "mac": MAC_FILE.read_text() if MAC_FILE.exists() else "",
            "mac_salt": base64.b64encode(MAC_SALT_FILE.read_bytes()).decode() if MAC_SALT_FILE.exists() else ""
        }, separators=(",",":"))
        blob = _enc_backup(payload, pw)
        try: Path(dst).write_text(blob); messagebox.showinfo("Backup", f"Backup written: {dst}", parent=self)
        except Exception as e: messagebox.showerror("Error", str(e), parent=self)

    def _restore_profiles(self):
        src = filedialog.askopenfilename(
            title="Restore backup",
            filetypes=[("Encrypted backup","*.rdpbak"), ("All","*.*")],
            parent=self
        )
        if not src: return
        blob = Path(src).read_text()
        if not blob.startswith("bak:"):
            messagebox.showerror("Error", "Not a recognised backup", parent=self); return
        pw = simpledialog.askstring("Password", "Enter backup password:", show="*", parent=self)
        if pw is None: return
        try:
            data = json.loads(_dec_backup(blob, pw))
        except Exception as e:
            messagebox.showerror("Error", f"Decrypt failed: {e}", parent=self); return
        # write files
        try: PW_FILE.write_text(data["master_hash"]); PW_FILE.chmod(0o600)
        except Exception as e: messagebox.showwarning("Warn", f"master.hash write failed: {e}", parent=self)
        try:
            MAC_SALT_FILE.write_bytes(base64.b64decode(data["mac_salt"])); MAC_SALT_FILE.chmod(0o600)
            MAC_FILE.write_text(data["mac"]); MAC_FILE.chmod(0o600)
        except Exception: pass
        self.cfg.connections = data["connections"]; self.cfg.save()
        self._refresh_tree(); self._clear_form()
        messagebox.showinfo("Done", "Restore complete.  Restart recommended.", parent=self)

    # ── about ──
    def _about(self):
        w = ttk.Toplevel(self); w.title("About"); w.resizable(False,False)
        f = ttk.Frame(w, padding=15); f.pack(expand=True, fill="both")
        ttk.Label(f, text="XFreeRDP Manager", font=("TkDefaultFont",14,"bold"),
                  bootstyle="inverse-primary").pack(pady=(0,10))
        ttk.Label(f, text=f"Version: {__version__}").pack(anchor="w")
        link = ttk.Label(f, text="Source: github.com/Marzlio/XFreeRDP-Manager",
                         foreground="cyan", cursor="hand2")
        link.pack(anchor="w"); link.bind("<Button-1>",
            lambda *_: webbrowser.open_new("https://github.com/Marzlio/XFreeRDP-Manager"))
        ttk.Button(f, text="OK", command=w.destroy).pack(pady=(15,0))

    # ── close ──
    def _on_close(self):
        for p in list(self.active.values()): self._kill_pg(p)
        self.destroy(); self.quit()

# ─────────────────────────── main ─────────────────────────────
if __name__ == "__main__":
    master_pw = _get_master()
    enc = EncryptionManager(master_pw)
    cfg = ConfigManager(CFG_FILE, MAC_FILE, enc.mac_key())
    gui = RDPApp(enc, cfg); gui.mainloop()