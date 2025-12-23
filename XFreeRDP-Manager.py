#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import hashlib
import hmac
import io
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

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
    from PIL import Image, ImageTk, ImageDraw
    QR_AVAILABLE = True
except ModuleNotFoundError:
    QR_AVAILABLE = False
    ImageDraw = None

try:
    import xml.etree.ElementTree as ET
    XML_AVAILABLE = True
except ModuleNotFoundError:
    XML_AVAILABLE = False

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

__version__ = "0.7.4"

# ───────────────────────── logging ────────────────────────────
class SensitiveDataFilter(logging.Filter):
    """Filter to prevent sensitive data from appearing in logs."""

    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        msg = str(record.getMessage())
        # Redact common sensitive patterns
        patterns = [
            (r"(password|pwd|passwd|secret|key|token)\s*[:=]\s*[^\s]+", r"\1=***REDACTED***"),
            (r"(/v:|/u:|/d:)\s*[^\s]+", r"\1***REDACTED***"),
        ]
        for pattern, replacement in patterns:
            msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)  # type: ignore[name-defined]
        record.msg = msg
        return True


logger = logging.getLogger()
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.addFilter(SensitiveDataFilter())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ─────────────────────── paths / constants ────────────────────
CFG_DIR = Path.home() / ".rdp_gui"
CFG_DIR.mkdir(exist_ok=True)
CFG_DIR.chmod(0o700)

CFG_FILE = CFG_DIR / "rdp_connections.json"
MAC_FILE = CFG_DIR / "rdp_connections.mac"
PW_FILE = CFG_DIR / "master.hash"
TOTP_FILE = CFG_DIR / "totp.enc"
TOTP_VERIFY_FILE = CFG_DIR / ".totp_verified"  # Timestamp of last successful TOTP verification
MAC_SALT_FILE = CFG_DIR / "mac.salt"
HISTORY_FILE = CFG_DIR / "connection_history.json"
TEMPLATES_FILE = CFG_DIR / "profile_templates.json"
WINDOW_STATE_FILE = CFG_DIR / "window_state.json"

PBKDF2_ITERATIONS = 600_000
BACKUP_ITER = 600_000
ARGON2_PARAMS: Tuple[int, int, int] = (19 * 1024, 2, 1)

# ──────────── UI constants ────────────
DEFAULT_WINDOW_SIZE = "800x500"
DEFAULT_RESOLUTION = "1920x1080"
PROCESS_CLEANUP_INTERVAL = 5000  # milliseconds
TOTP_VERIFY_DURATION = 24 * 60 * 60  # 24 hours in seconds


def _get_icon_path(filename: str) -> Optional[Path]:
    """Get icon file path, checking both bundled and development locations."""
    if hasattr(sys, "_MEIPASS"):
        base_path = Path(sys._MEIPASS)
    else:
        base_path = Path(__file__).parent
    icon_path = base_path / "icons" / filename
    if icon_path.exists():
        return icon_path
    icon_path = Path("icons") / filename
    if icon_path.exists():
        return icon_path
    return None


# ──────────────── Input validation / path safety ───────────────
def _validate_server(server: str) -> bool:
    """Validate server address format (IP or hostname with optional port)."""
    if not server or len(server) > 255:
        return False
    if any(c in server for c in [";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r", " "]):
        return False
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$"
    hostname_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(:\d{1,5})?$"
    return bool(re.match(ip_pattern, server) or re.match(hostname_pattern, server))


def _validate_username(username: str) -> bool:
    """Validate username format."""
    if not username or len(username) > 104:
        return False
    if any(c in username for c in [";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r"]):
        return False
    return True


def _validate_domain(domain: str) -> bool:
    """Validate domain name format (optional)."""
    if not domain:
        return True
    if len(domain) > 255:
        return False
    if any(c in domain for c in [";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r", " "]):
        return False
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    return bool(re.match(pattern, domain))


def _validate_xfreerdp_option(option: str) -> bool:
    """Validate a single xfreerdp command-line option."""
    if not option or len(option) > 256:
        return False
    if not (option.startswith("/") or option.startswith("+")):
        return False
    if re.search(r"[;&|`$()<>\\n\\r]", option):
        return False
    if " " in option:
        return False
    return True


def _validate_backup_path(path: Path) -> bool:
    """Ensure backup file path is safe (no path traversal into sensitive dirs)."""
    try:
        resolved = path.resolve()
        sensitive_dirs = [
            Path.home() / ".ssh",
            Path("/etc"),
            Path("/root"),
            Path("/usr"),
            Path("/bin"),
            Path("/sbin"),
        ]
        for sensitive in sensitive_dirs:
            try:
                if resolved.is_relative_to(sensitive):
                    return False
            except (AttributeError, ValueError):
                if str(resolved).startswith(str(sensitive)):
                    return False
        home = Path.home()
        cwd = Path.cwd()
        return str(resolved).startswith(str(home)) or str(resolved).startswith(str(cwd))
    except (OSError, ValueError) as e:
        logging.error(f"Path validation error: {e}")
        return False


# ─────────────────────── tooltip helper ───────────────────────
class Tooltip:
    """Simple tooltip for Tk/ttk widgets."""

    def __init__(self, widget: tk.Widget, text: str, delay_ms: int = 600):
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self._after_id: Optional[str] = None
        self._tip_window: Optional[tk.Toplevel] = None

        self.widget.bind("<Enter>", self._on_enter, add="+")
        self.widget.bind("<Leave>", self._on_leave, add="+")
        self.widget.bind("<Motion>", self._on_motion, add="+")

    def _on_enter(self, _event):
        self._schedule()

    def _on_motion(self, _event):
        self._schedule()

    def _on_leave(self, _event):
        self._cancel()
        self._hide()

    def _schedule(self):
        self._cancel()
        self._after_id = self.widget.after(self.delay_ms, self._show)

    def _cancel(self):
        if self._after_id:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _show(self):
        if self._tip_window or not self.text:
            return
        try:
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        except Exception:
            return

        self._tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")

        lbl = ttk.Label(
            tw,
            text=self.text,
            padding=(6, 3),
            bootstyle="secondary",
            justify="left",
        )
        lbl.pack()

    def _hide(self):
        if self._tip_window is not None:
            try:
                self._tip_window.destroy()
            except Exception:
                pass
            self._tip_window = None

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
    """Verify TOTP, with 24h caching of successful verification."""
    if pyotp is None:
        return  # 2FA disabled

    # If we have a recent successful verification, skip prompting again
    try:
        if TOTP_VERIFY_FILE.exists():
            last = TOTP_VERIFY_FILE.stat().st_mtime
            if time.time() - last < TOTP_VERIFY_DURATION:
                return
    except Exception:
        # If anything goes wrong, fall back to full verification
        pass

    if not TOTP_FILE.exists():
        _setup_totp(enc, parent)
        # New TOTP requires fresh verification; no cache yet
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
            # Successful verification: update timestamp
            try:
                TOTP_VERIFY_FILE.write_text(str(int(time.time())))
                TOTP_VERIFY_FILE.chmod(0o600)
            except Exception:
                pass
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


# ─────────────── profile template helpers ───────────────
def _load_templates() -> Dict[str, Dict[str, Any]]:
    """Load profile templates from TEMPLATES_FILE."""
    if not TEMPLATES_FILE.exists():
        return {}
    try:
        raw = TEMPLATES_FILE.read_text()
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}


def _save_templates(templates: Dict[str, Dict[str, Any]]) -> None:
    """Persist templates to disk."""
    try:
        TEMPLATES_FILE.write_text(json.dumps(templates, indent=2))
        TEMPLATES_FILE.chmod(0o600)
    except Exception:
        pass


# ───────────── connection history helpers ─────────────
def _load_history() -> List[Dict[str, Any]]:
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text())
    except Exception:
        return []


def _append_history(profile: str, server: str, success: bool) -> None:
    try:
        hist = _load_history()
        hist.append(
            {
                "timestamp": int(time.time()),
                "profile": profile,
                "server": server,
                "success": bool(success),
            }
        )
        # keep last 500 entries
        hist = hist[-500:]
        HISTORY_FILE.write_text(json.dumps(hist, indent=2))
        HISTORY_FILE.chmod(0o600)
    except Exception:
        # history is best-effort only
        pass


# ───────────── master password / TOTP helpers ─────────────

# ──────────────────────── GUI class ───────────────────────────
class RDPApp(ttk.Window):
    def __init__(self, enc: EncryptionManager, cfg: ConfigManager, *, cli_connect: Optional[str] = None, cli_test: Optional[str] = None):
        super().__init__(themename="darkly")
        self.enc, self.cfg = enc, cfg
        # Enhanced session tracking: store dict with proc and metadata
        self.active: Dict[str, Dict[str, Any]] = {}
        self.sess_ctr = 1

        self._define_vars()
        self._load_tree_icons()
        self._build_ui()
        self._refresh_tree()

        self.title("XFreeRDP Manager")
        # Restore window state if available
        try:
            if WINDOW_STATE_FILE.exists():
                state = json.loads(WINDOW_STATE_FILE.read_text())
                geom = state.get("geometry")
                if geom:
                    self.geometry(geom)
                else:
                    self.geometry(DEFAULT_WINDOW_SIZE)
            else:
                self.geometry(DEFAULT_WINDOW_SIZE)
        except Exception:
            self.geometry(DEFAULT_WINDOW_SIZE)
        self._set_icon()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._scan_orphans()
        self._start_process_monitor()

        # CLI-driven actions (optional)
        if cli_connect or cli_test:
            self.after(200, lambda: self._handle_cli_action(cli_connect, cli_test))

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

    # ── automatic process cleanup ──
    def _start_process_monitor(self):
        """Periodically clean up dead processes to prevent memory leaks."""
        dead: List[str] = []
        for sid, session_info in list(self.active.items()):
            proc = session_info.get("proc")
            if proc is not None and proc.poll() is not None:
                dead.append(sid)

        for sid in dead:
            self.active.pop(sid, None)

        # Schedule next check
        self.after(PROCESS_CLEANUP_INTERVAL, self._start_process_monitor)

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
        self.auto_connect_var = tk.BooleanVar(value=True)

        self.cmd_preview_box: tk.Text | None = None
        self.status_bar: ttk.Label | None = None
        self._current_profile_name: Optional[str] = None
        self.recent_menu: Optional[tk.Menu] = None
        self.favorite_var = tk.BooleanVar(value=False)
        # icons (must keep references on self)
        self.rdp_icon: Optional[ImageTk.PhotoImage] = None
        self.folder_icon: Optional[ImageTk.PhotoImage] = None

    # ── build UI ──
    def _build_ui(self):
        self.rowconfigure(0, weight=1); self.columnconfigure(0, weight=1)
        main = ttk.Frame(self, padding=10); main.grid(sticky="nsew", row=0, column=0)
        main.columnconfigure(0, weight=1, uniform="c"); main.columnconfigure(1, weight=2, uniform="c")
        main.rowconfigure(1, weight=1)

        self._build_tree(main); self._build_notebook(main); self._build_menu()
        self._build_status_bar()

    # ── icon helpers ──
    def _set_icon(self) -> None:
        """Set the application window icon if an icon file is available."""
        for icon_file in ["xfreerdp-gui.png", "xfreerdp-gui.svg"]:
            icon_path = _get_icon_path(icon_file)
            if not icon_path:
                continue
            try:
                if icon_file.endswith(".png") and QR_AVAILABLE:
                    img = Image.open(icon_path)
                    photo = ImageTk.PhotoImage(img)
                    self.iconphoto(True, photo)
                    self._icon_photo = photo  # keep reference
                    return
            except Exception:
                continue

    def _load_tree_icons(self) -> None:
        """Load small icons for the tree view."""
        self.rdp_icon = None
        self.folder_icon = None
        if not QR_AVAILABLE or ImageDraw is None:
            return
        # Try to create simple programmatic icons
        try:
            # RDP icon (monitor)
            img = Image.new("RGBA", (16, 16), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            draw.rectangle([2, 2, 13, 11], outline=(100, 150, 255), fill=(50, 100, 200))
            draw.rectangle([3, 3, 12, 10], fill=(200, 220, 255))
            draw.rectangle([6, 11, 9, 13], fill=(100, 150, 255))
            self.rdp_icon = ImageTk.PhotoImage(img)
        except Exception:
            self.rdp_icon = None
        try:
            # Folder icon
            img2 = Image.new("RGBA", (16, 16), (0, 0, 0, 0))
            draw2 = ImageDraw.Draw(img2)
            draw2.polygon(
                [(3, 4), (7, 4), (8, 6), (13, 6), (13, 12), (3, 12)],
                fill=(255, 200, 100),
                outline=(200, 150, 80),
            )
            draw2.polygon(
                [(3, 4), (7, 4), (8, 6), (3, 6)],
                fill=(255, 220, 150),
            )
            self.folder_icon = ImageTk.PhotoImage(img2)
        except Exception:
            self.folder_icon = None

    # ── status bar ──
    def _build_status_bar(self):
        """Create status bar at bottom of window."""
        status_frame = ttk.Frame(self)
        status_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        status_frame.columnconfigure(0, weight=1)

        self.status_bar = ttk.Label(
            status_frame,
            text="Ready",
            relief=tk.SUNKEN,
            anchor=tk.W,
            padding=5,
        )
        self.status_bar.grid(row=0, column=0, sticky="ew")
        self.rowconfigure(1, weight=0)  # Status bar doesn't expand

    def _update_status(self, message: str, status_type: str = "info"):
        """Update status bar with message."""
        if not self.status_bar:
            return
        self.status_bar.config(text=message)

    # ── menu ──
    def _build_menu(self):
        m = tk.Menu(self)

        # File menu
        file_m = tk.Menu(m, tearoff=0)
        file_m.add_command(label="Backup Profiles…", command=self._backup_profiles)
        file_m.add_command(label="Restore Profiles…", command=self._restore_profiles)

        # Import submenu
        import_m = tk.Menu(file_m, tearoff=0)
        import_m.add_command(label="From Remmina (.remmina)…", command=self._import_remmina)
        import_m.add_command(label="From Windows .rdp…", command=self._import_rdp)
        import_m.add_command(label="From CSV…", command=self._import_csv)
        import_m.add_command(label="From Terminals (Favorites.xml)…", command=self._import_terminals)
        file_m.add_cascade(label="Import", menu=import_m)

        file_m.add_separator()
        file_m.add_command(label="Export Current Profile as .rdp…", command=self._export_current_rdp)
        file_m.add_separator()
        file_m.add_command(label="Change Master Password…", command=self._change_master_password)
        m.add_cascade(label="File", menu=file_m)

        # Security menu
        security_m = tk.Menu(m, tearoff=0)
        security_m.add_command(label="Reset TOTP / 2FA…", command=self._reset_totp)
        security_m.add_command(label="Enable TOTP / 2FA…", command=self._enable_totp)
        m.add_cascade(label="Security", menu=security_m)

        # Edit menu
        edit_m = tk.Menu(m, tearoff=0)
        edit_m.add_checkbutton(label="Auto-connect on double-click", variable=self.auto_connect_var)
        edit_m.add_separator()
        presets_m = tk.Menu(edit_m, tearoff=0)
        presets_m.add_command(label="High Security", command=self._apply_preset_high_security)
        presets_m.add_command(label="Performance", command=self._apply_preset_performance)
        presets_m.add_command(label="Multi-Monitor", command=self._apply_preset_multimon)
        edit_m.add_cascade(label="Connection Presets", menu=presets_m)
        edit_m.add_separator()
        edit_m.add_command(label="Bulk Delete Selected Profiles", command=self._bulk_delete_profiles)
        edit_m.add_command(label="Bulk Clone Selected Profiles…", command=self._bulk_clone_profiles)
        edit_m.add_command(label="Bulk Export Selected to .rdp…", command=self._bulk_export_rdp)
        m.add_cascade(label="Edit", menu=edit_m)

        # Sessions menu
        sess_m = tk.Menu(m, tearoff=0)
        sess_m.add_command(label="Show Active Sessions", command=self._open_sessions)
        # Quick access submenus (populated on demand)
        self.recent_menu = tk.Menu(sess_m, tearoff=0)
        self.favorites_menu = tk.Menu(sess_m, tearoff=0)
        self.recent_menu.configure(postcommand=self._populate_recent_menu)
        self.favorites_menu.configure(postcommand=self._populate_favorites_menu)
        sess_m.add_cascade(label="Recent", menu=self.recent_menu)
        sess_m.add_cascade(label="Favorites", menu=self.favorites_menu)
        m.add_cascade(label="Sessions", menu=sess_m)

        # Help menu
        help_m = tk.Menu(m, tearoff=0)
        help_m.add_command(label="About", command=self._about)
        m.add_cascade(label="Help", menu=help_m)

        self.config(menu=m)

        # Bind keyboard shortcuts
        self._bind_shortcuts()

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

        self.tree = ttk.Treeview(box, show="tree", selectmode="extended")
        self.tree.grid(row=1, column=0, sticky="nsew")
        sb = ttk.Scrollbar(box, orient="vertical", command=self.tree.yview)
        sb.grid(row=1, column=1, sticky="ns"); self.tree.configure(yscrollcommand=sb.set)
        self.tree.bind("<Double-1>", self._tree_dbl)
        self.tree.bind("<<TreeviewSelect>>", self._tree_sel)
        # drag & drop for moving profiles between groups
        self.tree.bind("<ButtonPress-1>", self._on_tree_button_press)
        self.tree.bind("<ButtonRelease-1>", self._on_tree_button_release)

    def _refresh_tree(self, *_):
        self.tree.delete(*self.tree.get_children())
        grp_nodes: Dict[str, str] = {}
        ungrp_id: str | None = None
        filt = self.search_var.get().lower()

        for prof, data in self.cfg.connections.items():
            grp_path = (data.get("group") or "").strip()
            if filt and filt not in prof.lower() and filt not in grp_path.lower():
                continue
            is_fav = bool(data.get("favorite"))
            icon = self.rdp_icon
            # we don't have a dedicated favorite icon image; keep same icon but could be extended
            if not grp_path:
                if ungrp_id is None:
                    ungrp_id = self.tree.insert(
                        "", "end", text="Ungrouped", image=self.folder_icon or ""
                    )
                self.tree.insert(
                    ungrp_id,
                    "end",
                    text=prof,
                    image=icon or "",
                )
                continue
            parent = ""
            built: List[str] = []
            for part in grp_path.split("/"):
                built.append(part); key = "/".join(built)
                if key not in grp_nodes:
                    grp_nodes[key] = self.tree.insert(
                        parent,
                        "end",
                        text=part,
                        image=self.folder_icon or "",
                    )
                parent = grp_nodes[key]
            self.tree.insert(
                parent,
                "end",
                text=prof,
                image=icon or "",
            )

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
        if iid and not self.tree.get_children(iid) and self.auto_connect_var.get():
            self._connect()

    # drag & drop helpers
    def _on_tree_button_press(self, event):
        """Remember the item being dragged."""
        iid = self.tree.identify_row(event.y)
        self._drag_iid = iid if iid and not self.tree.get_children(iid) else None

    def _on_tree_button_release(self, event):
        """On release, if over a folder, move the profile into that group."""
        if not getattr(self, "_drag_iid", None):
            return
        src_text = self.tree.item(self._drag_iid, "text")
        # identify drop target
        target_iid = self.tree.identify_row(event.y)
        if not target_iid:
            # dropped on empty area -> ungroup
            if src_text in self.cfg.connections:
                self.cfg.connections[src_text]["group"] = ""
                self.cfg.save()
                self._refresh_tree()
            self._drag_iid = None
            return
        # if target has children, treat as folder; otherwise use its parent as folder
        folder_iid = target_iid if self.tree.get_children(target_iid) else self.tree.parent(target_iid)
        if not folder_iid:
            # top-level, no group
            if src_text in self.cfg.connections:
                self.cfg.connections[src_text]["group"] = ""
                self.cfg.save()
                self._refresh_tree()
            self._drag_iid = None
            return
        # build group path from folder hierarchy
        parts = []
        cur = folder_iid
        while cur:
            parts.insert(0, self.tree.item(cur, "text"))
            cur = self.tree.parent(cur)
        group_path = "/".join(parts)
        if src_text in self.cfg.connections:
            self.cfg.connections[src_text]["group"] = group_path
            self.cfg.save()
            self._refresh_tree()
        self._drag_iid = None

    # ── keyboard shortcuts ──
    def _bind_shortcuts(self):
        """Bind keyboard shortcuts for common actions."""
        self.bind("<Control-s>", lambda e: (self._save_profile(), None)[1])
        self.bind("<Control-c>", lambda e: (self._connect(), None)[1])
        self.bind("<Control-d>", lambda e: (self._del_profile(), None)[1])
        self.bind("<Control-n>", lambda e: (self._clear_form(), None)[1])
        self.bind("<F5>", lambda e: (self._refresh_tree(), None)[1])

        def focus_search(_e):
            # Try to focus the search entry
            for widget in self.winfo_children():
                if isinstance(widget, ttk.Frame):
                    for child in widget.winfo_children():
                        if isinstance(child, ttk.Labelframe):
                            for grandchild in child.winfo_children():
                                if isinstance(grandchild, ttk.Frame):
                                    for entry in grandchild.winfo_children():
                                        if isinstance(entry, ttk.Entry) and entry.cget("textvariable") == str(self.search_var):
                                            entry.focus()
                                            return

        self.bind("<Control-f>", focus_search)

    # ── notebook / form ──
    def _build_notebook(self, parent):
        nb = ttk.Notebook(parent); nb.grid(row=0, column=1, rowspan=2, sticky="nsew")
        tab = ttk.Frame(nb, padding=10); nb.add(tab, text="Connection Settings")
        tab.columnconfigure(0, weight=0)
        tab.columnconfigure(1, weight=1)
        tab.columnconfigure(2, weight=1)

        # widgets
        self.profile_entry = ttk.Entry(tab)
        self.group_entry = ttk.Entry(tab)
        self.server_entry = ttk.Entry(tab)
        self.user_entry = ttk.Entry(tab)
        self.password_entry = ttk.Entry(tab, show="*")
        self.domain_entry = ttk.Entry(tab)

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
            wid.grid(row=row, column=1, columnspan=2, sticky="ew", pady=2); row += 1
        ttk.Checkbutton(
            tab,
            text="Show",
            variable=self.show_pw_var,
            command=self._toggle_pw,
        ).grid(row=4, column=2, sticky="w")

        # Favorite toggle
        fav_cb = ttk.Checkbutton(tab, text="Favorite ★", variable=self.favorite_var)
        fav_cb.grid(row=row, column=1, sticky="w", pady=(2, 6)); row += 1
        Tooltip(fav_cb, "Mark this profile as a favorite for quick access.")

        ttk.Label(tab, text="Resolution:").grid(row=row, column=0, sticky="w")
        ttk.OptionMenu(
            tab,
            self.resolution_var,
            DEFAULT_RESOLUTION,
            "1920x1080",
            "1366x768",
            "1280x720",
            "1024x768",
        ).grid(row=row, column=1, sticky="w"); row += 1
        ttk.Checkbutton(
            tab, text="Dynamic Resolution", variable=self.dynamic_resolution_var
        ).grid(row=row, column=1, sticky="w"); row += 1

        # Primary actions row
        primary_btn_frame = ttk.Frame(tab)
        primary_btn_frame.grid(row=row, column=0, columnspan=3, pady=(10, 5), sticky="ew")
        primary_btn_frame.columnconfigure(0, weight=1)
        primary_btn_frame.columnconfigure(1, weight=1)
        primary_btn_frame.columnconfigure(2, weight=1)

        save_btn = ttk.Button(primary_btn_frame, text="Save Profile", command=self._save_profile, bootstyle="success")
        save_btn.grid(row=0, column=0, padx=5, sticky="ew")
        Tooltip(save_btn, "Save current form data as a new profile or update an existing one.")

        connect_btn = ttk.Button(primary_btn_frame, text="Connect", command=self._connect, bootstyle="primary-outline")
        connect_btn.grid(row=0, column=1, padx=5, sticky="ew")
        Tooltip(connect_btn, "Connect to the remote desktop using the current profile settings.")

        test_btn = ttk.Button(primary_btn_frame, text="Test Connection", command=self._update_preview, bootstyle="info-outline")
        test_btn.grid(row=0, column=2, padx=5, sticky="ew")
        Tooltip(test_btn, "Show the xfreerdp command that would be executed for this profile.")
        row += 1

        # Secondary actions row
        secondary_btn_frame = ttk.Frame(tab)
        secondary_btn_frame.grid(row=row, column=0, columnspan=3, pady=(5, 10), sticky="ew")
        secondary_btn_frame.columnconfigure(0, weight=1)
        secondary_btn_frame.columnconfigure(1, weight=1)
        secondary_btn_frame.columnconfigure(2, weight=1)

        adv_btn = ttk.Button(secondary_btn_frame, text="Advanced Settings", command=self._open_adv, bootstyle="secondary-outline")
        adv_btn.grid(row=0, column=0, padx=5, sticky="ew")
        Tooltip(adv_btn, "Configure advanced xfreerdp options (security, audio, devices, extra flags).")

        clone_btn = ttk.Button(secondary_btn_frame, text="Clone Profile", command=self._clone_profile, bootstyle="secondary-outline")
        clone_btn.grid(row=0, column=1, padx=5, sticky="ew")
        Tooltip(clone_btn, "Create a new profile by copying the settings of the currently loaded profile.")

        del_btn = ttk.Button(secondary_btn_frame, text="Delete Profile", command=self._del_profile, bootstyle="danger-outline")
        del_btn.grid(row=0, column=2, padx=5, sticky="ew")
        Tooltip(del_btn, "Permanently delete the currently loaded profile.")
        row += 1

        # Template actions row
        template_btn_frame = ttk.Frame(tab)
        template_btn_frame.grid(row=row, column=0, columnspan=3, pady=(5, 10), sticky="ew")
        template_btn_frame.columnconfigure(0, weight=1)
        template_btn_frame.columnconfigure(1, weight=1)

        save_tmpl_btn = ttk.Button(
            template_btn_frame,
            text="Save as Template",
            command=self._save_template,
            bootstyle="light-outline",
        )
        save_tmpl_btn.grid(row=0, column=0, padx=5, sticky="ew")
        Tooltip(save_tmpl_btn, "Save the current profile's settings (excluding password) as a reusable template.")

        apply_tmpl_btn = ttk.Button(
            template_btn_frame,
            text="Apply Template…",
            command=self._apply_template,
            bootstyle="light-outline",
        )
        apply_tmpl_btn.grid(row=0, column=1, padx=5, sticky="ew")
        Tooltip(apply_tmpl_btn, "Apply settings from a saved template to the current form.")
        row += 1

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
        hsb = ttk.Scrollbar(box, orient="horizontal", command=self.cmd_preview_box.xview)
        hsb.grid(row=1, column=0, sticky="ew")
        self.cmd_preview_box.configure(xscrollcommand=hsb.set)
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
        self.favorite_var.set(False)
        self._current_profile_name = None

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
        self.favorite_var.set(bool(d.get("favorite")))
        self._current_profile_name = name

    # ── save / delete / clone ──
    def _save_profile(self):
        name = self.profile_entry.get().strip()
        if not name:
            messagebox.showerror("Error", "Profile name required", parent=self)
            return

        # Validate inputs
        server = self.server_entry.get().strip()
        username = self.user_entry.get().strip()
        domain = self.domain_entry.get().strip()

        if server and not _validate_server(server):
            messagebox.showerror("Error", "Invalid server address format", parent=self)
            return
        if username and not _validate_username(username):
            messagebox.showerror("Error", "Invalid username format", parent=self)
            return
        if domain and not _validate_domain(domain):
            messagebox.showerror("Error", "Invalid domain format", parent=self)
            return

        # Check if renaming an existing profile
        is_renaming = self._current_profile_name and self._current_profile_name != name
        if is_renaming:
            if name in self.cfg.connections:
                if not messagebox.askyesno(
                    "Overwrite Profile",
                    f"A profile named '{name}' already exists. Overwrite it?",
                    parent=self,
                ):
                    return
                # Overwrite: delete the old profile name
                self.cfg.delete(self._current_profile_name)
            else:
                # New name does not exist, delete old profile entry (rename)
                self.cfg.delete(self._current_profile_name)
        pdata = {
            "group": self.group_entry.get().strip(),
            "server": server,
            "username": username,
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
            "favorite": self.favorite_var.get(),
        }
        self.cfg.add(name, pdata)
        self._current_profile_name = name
        self._refresh_tree()
        self._update_status(f"Profile '{name}' saved", "info")
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
        if extra:
            parts = extra.split()
            for part in parts:
                if not _validate_xfreerdp_option(part):
                    raise ValueError(
                        f"Invalid xfreerdp option: {part}. Only options starting with / or + are allowed."
                    )
            cmd.extend(parts)
        return cmd

    # ── connect ──
    def _connect(self):
        server = self.server_entry.get().strip()
        user = self.user_entry.get().strip()
        if not server or not user:
            messagebox.showerror("Error", "Server & Username required", parent=self)
            return
        try:
            cmd = self._build_cmd()
        except ValueError as e:
            messagebox.showerror("Error", str(e), parent=self)
            _append_history(self.profile_entry.get().strip() or "Unnamed", server, False)
            return
        try:
            proc = subprocess.Popen(
                cmd, stdin=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            if proc.stdin:
                pw = self.password_entry.get()
                proc.stdin.write((pw + "\n").encode())
                proc.stdin.close()
            sid = f"sess-{self.sess_ctr}"
            self.sess_ctr += 1
            self.active[sid] = {"proc": proc, "profile": self.profile_entry.get().strip(), "server": server}
            _append_history(self.profile_entry.get().strip() or "Unnamed", server, True)
            self._update_status(f"Connected: {server}", "info")
        except Exception as e:
            messagebox.showerror("xfreerdp", str(e), parent=self)
            _append_history(self.profile_entry.get().strip() or "Unnamed", server, False)

    def _test_connection(self):
        """Test server connectivity before connecting."""
        server = self.server_entry.get().strip()
        if not server:
            messagebox.showerror("Error", "Server address required", parent=self)
            return

        self._update_status("Testing connection...", "info")

        if ":" in server:
            host, port_s = server.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                port = 3389
        else:
            host = server
            port = 3389

        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                self._update_status(f"Server {host}:{port} is reachable", "success")
                messagebox.showinfo("Connection Test", f"Server {host}:{port} is reachable!", parent=self)
            else:
                self._update_status(f"Server {host}:{port} is not reachable", "warning")
                if not messagebox.askyesno(
                    "Connection Test",
                    f"Server {host}:{port} is not reachable.\n\n"
                    "This may be normal if the server is behind a firewall.\n"
                    "Continue anyway?",
                    parent=self,
                ):
                    return
        except socket.gaierror:
            self._update_status(f"Could not resolve hostname: {host}", "error")
            if not messagebox.askyesno(
                "Connection Test",
                f"Could not resolve hostname: {host}\n\n"
                "Continue anyway?",
                parent=self,
            ):
                return

    # ── connection presets ──
    def _apply_preset_high_security(self):
        """Apply a 'High Security' preset to the current form."""
        self.enforce_tls_var.set(True)
        self.ignore_cert_var.set(False)
        self.sec_protocol_var.set("TLS")
        self.debug_mode_var.set(False)
        self.audio_var.set(False)
        self.printer_var.set(False)
        self.smartcard_var.set(False)
        self.usb_var.set(False)
        self._update_status("Applied 'High Security' preset", "success")

    def _apply_preset_performance(self):
        """Apply a 'Performance' preset tuned for slower links."""
        try:
            parsed = self._parse_res(self.resolution_var.get()) or (0, 0)
            w, _ = parsed
        except Exception:
            w = 0
        if not w or w > 1366:
            self.resolution_var.set("1366x768")
        self.audio_var.set(False)
        self.printer_var.set(False)
        self.smartcard_var.set(False)
        self.usb_var.set(False)
        self.fullscreen_var.set(False)
        self.multimon_var.set(False)
        self._update_status("Applied 'Performance' preset", "success")

    def _apply_preset_multimon(self):
        """Apply a 'Multi-Monitor' preset."""
        self.multimon_var.set(True)
        self.fullscreen_var.set(True)
        self.dynamic_resolution_var.set(True)
        self._update_status("Applied 'Multi-Monitor' preset", "success")
        except Exception as e:
            logging.error("Connection test error: %s", e, exc_info=True)
            self._update_status("Connection test failed", "warning")
            if not messagebox.askyesno(
                "Connection Test",
                f"Connection test failed: {e}\n\n"
                "Continue anyway?",
                parent=self,
            ):
                return

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

    # ── history / recent ──
    def _quick_connect_profile(self, profile_name: str):
        """Load a profile and initiate connection (used by Recent menu)."""
        if profile_name not in self.cfg.connections:
            messagebox.showerror("Profile", f"Profile '{profile_name}' not found.", parent=self)
            return
        self._load_profile(profile_name)
        self._connect()

    def _populate_recent_menu(self):
        """Populate the Recent submenu from connection history."""
        if not self.recent_menu:
            return
        self.recent_menu.delete(0, "end")

        history = _load_history()
        if not history:
            self.recent_menu.add_command(label="No recent connections", state="disabled")
            return

        seen = set()
        recent_items: List[Tuple[str, str]] = []
        for entry in sorted(history, key=lambda e: e.get("timestamp", 0), reverse=True):
            prof = entry.get("profile") or "Unnamed"
            server = entry.get("server") or ""
            if prof in seen:
                continue
            seen.add(prof)
            label = f"{prof} ({server})" if server else prof
            recent_items.append((prof, label))
            if len(recent_items) >= 10:
                break

        for prof, label in recent_items:
            self.recent_menu.add_command(
                label=label,
                command=lambda p=prof: self._quick_connect_profile(p),
            )

    def _populate_favorites_menu(self):
        """Populate the Favorites submenu from profiles marked as favorite."""
        if not hasattr(self, "favorites_menu") or not self.favorites_menu:
            return
        self.favorites_menu.delete(0, "end")

        favorites = sorted(
            [name for name, data in self.cfg.connections.items() if data.get("favorite")],
            key=str.lower,
        )
        if not favorites:
            self.favorites_menu.add_command(label="No favorites", state="disabled")
            return

        for prof in favorites:
            self.favorites_menu.add_command(
                label=prof,
                command=lambda p=prof: self._quick_connect_profile(p),
            )

    def _show_history(self):
        """Show full connection history window."""
        history = _load_history()
        win = tk.Toplevel(self)
        win.title("Connection History")
        win.geometry("600x320")

        cols = ("time", "profile", "server", "success")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for c in cols:
            tree.heading(c, text=c.title())
            tree.column(c, width=120 if c != "server" else 200, anchor="w")
        tree.grid(row=0, column=0, sticky="nsew")
        win.columnconfigure(0, weight=1)
        win.rowconfigure(0, weight=1)

        sb = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        tree.config(yscrollcommand=sb.set)

        for entry in sorted(history, key=lambda e: e.get("timestamp", 0), reverse=True):
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.get("timestamp", 0)))
            prof = entry.get("profile") or ""
            server = entry.get("server") or ""
            success = "OK" if entry.get("success") else "Failed"
            tree.insert("", "end", values=(ts, prof, server, success))

    # ── templates ──
    def _save_template(self):
        """Save current profile fields as a reusable template (without password)."""
        name = self.profile_entry.get().strip()
        if not name:
            messagebox.showerror("Template", "Enter a profile name before saving a template.", parent=self)
            return

        tmpl_name = simpledialog.askstring(
            "Save as Template",
            "Template name:",
            initialvalue=name,
            parent=self,
        )
        if not tmpl_name or not tmpl_name.strip():
            return
        tmpl_name = tmpl_name.strip()

        template = {
            "group": self.group_entry.get().strip(),
            "server": self.server_entry.get().strip(),
            "username": self.user_entry.get().strip(),
            "domain": self.domain_entry.get().strip(),
            "resolution": self.resolution_var.get(),
            "dynamic_resolution": self.dynamic_resolution_var.get(),
            "clipboard": self.clipboard_var.get(),
            "ignore_cert": self.ignore_cert_var.get(),
            "security_protocol": self.sec_protocol_var.get(),
            "enforce_tls": self.enforce_tls_var.get(),
            "debug_mode": self.debug_mode_var.get(),
            "audio": self.audio_var.get(),
            "printer": self.printer_var.get(),
            "smartcard": self.smartcard_var.get(),
            "usb": self.usb_var.get(),
            "fullscreen": self.fullscreen_var.get(),
            "multimon": self.multimon_var.get(),
            "advanced_extra": self.advanced_extra_var.get().strip(),
        }

        templates = _load_templates()
        if tmpl_name in templates:
            if not messagebox.askyesno(
                "Overwrite Template",
                f"Template '{tmpl_name}' already exists.\n\nOverwrite it?",
                parent=self,
            ):
                return
        templates[tmpl_name] = template
        _save_templates(templates)
        self._update_status(f"Template '{tmpl_name}' saved", "success")

    def _apply_template(self):
        """Apply a saved template to the current form (does not change profile name or password)."""
        templates = _load_templates()
        if not templates:
            messagebox.showinfo("Templates", "No templates saved yet.", parent=self)
            return

        # pick template name
        names = sorted(templates.keys(), key=str.lower)
        dlg = tk.Toplevel(self)
        dlg.title("Apply Template")
        dlg.resizable(False, False)
        frm = ttk.Frame(dlg, padding=10)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Choose a template:").pack(anchor="w")
        var = tk.StringVar(value=names[0])
        combo = ttk.Combobox(frm, textvariable=var, values=names, state="readonly")
        combo.pack(fill="x", pady=5)

        def on_ok():
            dlg.destroy()

        ttk.Button(frm, text="Apply", command=on_ok).pack(pady=(5, 0))
        dlg.transient(self)
        dlg.grab_set()
        dlg.wait_window()
        tmpl_name = var.get()
        if not tmpl_name or tmpl_name not in templates:
            return

        tmpl = templates[tmpl_name]
        self.group_entry.delete(0, tk.END); self.group_entry.insert(0, tmpl.get("group", ""))
        self.server_entry.delete(0, tk.END); self.server_entry.insert(0, tmpl.get("server", ""))
        self.user_entry.delete(0, tk.END); self.user_entry.insert(0, tmpl.get("username", ""))
        self.domain_entry.delete(0, tk.END); self.domain_entry.insert(0, tmpl.get("domain", ""))
        self.resolution_var.set(tmpl.get("resolution", DEFAULT_RESOLUTION))
        self.dynamic_resolution_var.set(tmpl.get("dynamic_resolution", False))
        self.clipboard_var.set(tmpl.get("clipboard", False))
        self.ignore_cert_var.set(tmpl.get("ignore_cert", False))
        self.sec_protocol_var.set(tmpl.get("security_protocol", "Auto"))
        self.enforce_tls_var.set(tmpl.get("enforce_tls", False))
        self.debug_mode_var.set(tmpl.get("debug_mode", False))
        self.audio_var.set(tmpl.get("audio", False))
        self.printer_var.set(tmpl.get("printer", False))
        self.smartcard_var.set(tmpl.get("smartcard", False))
        self.usb_var.set(tmpl.get("usb", False))
        self.fullscreen_var.set(tmpl.get("fullscreen", False))
        self.multimon_var.set(tmpl.get("multimon", False))
        self.advanced_extra_var.set(tmpl.get("advanced_extra", ""))
        self._update_status(f"Template '{tmpl_name}' applied", "success")

    # ── CLI helpers ──
    def _handle_cli_action(self, cli_connect: Optional[str], cli_test: Optional[str]) -> None:
        """Handle CLI-driven actions after GUI is constructed."""
        try:
            if cli_connect:
                if cli_connect not in self.cfg.connections:
                    messagebox.showerror("CLI", f"Profile '{cli_connect}' not found.", parent=self)
                    return
                self._load_profile(cli_connect)
                self._connect()
            elif cli_test:
                if cli_test not in self.cfg.connections:
                    messagebox.showerror("CLI", f"Profile '{cli_test}' not found.", parent=self)
                    return
                self._load_profile(cli_test)
                self._test_connection()
        except Exception as e:
            logging.error("CLI action error: %s", e, exc_info=True)

    # ── backup / restore ──
    def _backup_profiles(self):
        dst = filedialog.asksaveasfilename(
            title="Save backup", defaultextension=".rdpbak",
            filetypes=[("Encrypted backup","*.rdpbak"), ("All","*.*")],
            parent=self
        )
        if not dst: return
        backup_path = Path(dst)
        if not _validate_backup_path(backup_path):
            messagebox.showerror("Error", "Invalid backup location. Please choose a safe location in your home or current directory.", parent=self)
            return
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
        try:
            backup_path.write_text(blob)
            messagebox.showinfo("Backup", f"Backup written: {dst}", parent=self)
        except Exception as e: messagebox.showerror("Error", str(e), parent=self)

    def _change_master_password(self):
        """Change master password and re-encrypt all profiles."""
        current_pw = _prompt_pw(self, "Current Master Password", "Enter current master password:")
        if current_pw is None:
            return
        if not _verify_pw(PW_FILE.read_text(), current_pw):
            messagebox.showerror("Error", "Incorrect current password", parent=self)
            return

        new_pw1 = _prompt_pw(self, "New Master Password", "Enter new master password:")
        if new_pw1 is None:
            return
        new_pw2 = _prompt_pw(self, "Confirm New Password", "Re-enter new master password:")
        if new_pw2 is None:
            return
        if new_pw1 != new_pw2:
            messagebox.showerror("Error", "New passwords do not match", parent=self)
            return
        if len(new_pw1) < 8:
            if not messagebox.askyesno(
                "Weak Password",
                "Password is less than 8 characters. Continue anyway?",
                parent=self,
            ):
                return

        # Optional: extra TOTP verification if enabled
        if pyotp and TOTP_FILE.exists():
            try:
                old_enc = EncryptionManager(current_pw)
                secret = old_enc.dec(TOTP_FILE.read_text())
                code = simpledialog.askstring("TOTP Verification", "Enter 6-digit TOTP code:", show="*", parent=self)
                if code is None:
                    return
                if not pyotp.TOTP(secret).verify(code, valid_window=1):
                    messagebox.showerror("Error", "Invalid TOTP code", parent=self)
                    return
            except Exception:
                messagebox.showerror("Error", "TOTP verification failed", parent=self)
                return

        try:
            old_enc = EncryptionManager(current_pw)
            new_enc = EncryptionManager(new_pw1)

            re_encrypted = 0
            for name, data in self.cfg.connections.items():
                if data.get("password"):
                    try:
                        old_pw = old_enc.dec(data["password"])
                        data["password"] = new_enc.enc(old_pw)
                        re_encrypted += 1
                    except Exception as e:
                        logging.error("Failed to re-encrypt profile '%s': %s", name, e)
                        messagebox.showerror("Error", f"Failed to re-encrypt profile '{name}'. Aborting.", parent=self)
                        return

            if pyotp and TOTP_FILE.exists():
                try:
                    totp_secret = old_enc.dec(TOTP_FILE.read_text())
                    TOTP_FILE.write_text(new_enc.enc(totp_secret))
                    TOTP_FILE.chmod(0o600)
                except Exception:
                    messagebox.showerror("Error", "Failed to re-encrypt TOTP secret", parent=self)
                    return

            # Update master password hash and MAC key
            PW_FILE.write_text(_hash_pw(new_pw1))
            PW_FILE.chmod(0o600)

            # Reset TOTP cache
            try:
                if TOTP_VERIFY_FILE.exists():
                    TOTP_VERIFY_FILE.unlink()
            except Exception:
                pass

            self.enc = new_enc
            self.cfg.mac_key = new_enc.mac_key()
            self.cfg.save()
            self._update_status("Master password changed successfully", "success")
            messagebox.showinfo(
                "Master Password",
                f"Master password changed successfully.\n\nRe-encrypted {re_encrypted} profile(s).",
                parent=self,
            )
        except Exception as e:
            logging.error("Error changing master password: %s", e, exc_info=True)
            messagebox.showerror("Error", "Failed to change master password. Please check logs.", parent=self)

    def _reset_totp(self):
        """Reset TOTP/2FA - generates a new secret and shows QR code."""
        if pyotp is None:
            messagebox.showerror("TOTP", "pyotp not installed; cannot reset 2‑factor.", parent=self)
            return
        if not TOTP_FILE.exists():
            self._enable_totp()
            return

        current_pw = _prompt_pw(
            self,
            "Master Password Verification",
            "Enter master password to reset TOTP:",
        )
        if current_pw is None:
            return
        if not _verify_pw(PW_FILE.read_text(), current_pw):
            messagebox.showerror("Error", "Incorrect master password", parent=self)
            return

        if not messagebox.askyesno(
            "Reset TOTP",
            "This will invalidate your current TOTP/2FA setup.\n\n"
            "You will need to scan the new QR code in your authenticator app.\n\n"
            "Continue?",
            parent=self,
        ):
            return

        try:
            new_secret = pyotp.random_base32()
            uri = pyotp.totp.TOTP(new_secret).provisioning_uri("xfreerdp‑GUI", issuer_name="Local")

            TOTP_FILE.write_text(self.enc.enc(new_secret))
            TOTP_FILE.chmod(0o600)

            win = tk.Toplevel(self)
            win.title("Reset 2‑Factor Authentication")
            win.resizable(False, False)
            frm = ttk.Frame(win, padding=15)
            frm.pack(fill="both", expand=True)

            ttk.Label(
                frm,
                text="Scan this NEW QR code in your authenticator app:",
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
                    text="(Install 'qrcode' and 'pillow' packages to get a QR code automatically)\n",
                    foreground="red",
                ).pack()

            ttk.Label(frm, text=f"URI:\n{uri}", wraplength=320, justify="left").pack(anchor="w", pady=(8, 4))
            ttk.Label(frm, text=f"Secret:\n{new_secret}", wraplength=320, justify="left").pack(anchor="w")
            ttk.Button(frm, text="OK", command=win.destroy).pack(pady=10)
        except Exception as e:
            logging.error("Error resetting TOTP: %s", e, exc_info=True)
            messagebox.showerror("Error", "Failed to reset TOTP. Please check logs.", parent=self)

    def _enable_totp(self):
        """Enable TOTP/2FA if not already enabled."""
        if pyotp is None:
            messagebox.showerror("TOTP", "pyotp not installed; cannot enable 2‑factor.", parent=self)
            return
        if TOTP_FILE.exists():
            messagebox.showinfo(
                "TOTP",
                "TOTP/2FA is already enabled. Use 'Reset TOTP' to generate a new secret.",
                parent=self,
            )
            return

        current_pw = _prompt_pw(
            self,
            "Master Password Verification",
            "Enter master password to enable TOTP:",
        )
        if current_pw is None:
            return
        if not _verify_pw(PW_FILE.read_text(), current_pw):
            messagebox.showerror("Error", "Incorrect master password", parent=self)
            return

        _setup_totp(self.enc, parent=self)
        self._update_status("TOTP/2FA enabled successfully", "success")

    def _restore_profiles(self):
        src = filedialog.askopenfilename(
            title="Restore backup",
            filetypes=[("Encrypted backup","*.rdpbak"), ("All","*.*")],
            parent=self
        )
        if not src: return
        restore_path = Path(src)
        if not _validate_backup_path(restore_path):
            messagebox.showerror("Error", "Invalid backup file location.", parent=self)
            return
        blob = restore_path.read_text()
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

    # ── import / export helpers ──
    def _unique_profile_name(self, base: str) -> str:
        """Return a unique profile name based on base."""
        name = base or "Imported"
        if name not in self.cfg.connections:
            return name
        idx = 2
        while f"{name} ({idx})" in self.cfg.connections:
            idx += 1
        return f"{name} ({idx})"

    def _import_remmina(self):
        path = filedialog.askopenfilename(
            title="Import Remmina profile",
            filetypes=[("Remmina files", "*.remmina"), ("All files", "*.*")],
            parent=self,
        )
        if not path:
            return
        cp = configparser.ConfigParser()
        try:
            cp.read(path, encoding="utf-8")
        except Exception as e:
            messagebox.showerror("Import", f"Failed to read .remmina: {e}", parent=self)
            return
        if "remmina" not in cp:
            messagebox.showerror("Import", "Not a valid Remmina profile.", parent=self)
            return
        s = cp["remmina"]
        if s.get("protocol") != "RDP":
            messagebox.showerror("Import", "Only RDP Remmina profiles are supported.", parent=self)
            return

        name = s.get("name") or Path(path).stem
        name = self._unique_profile_name(name)

        pdata = {
            "group": "",
            "server": s.get("server", ""),
            "username": s.get("username", ""),
            "password": self.enc.enc(s.get("password", "")) if s.get("password") else "",
            "domain": s.get("domain", ""),
            "resolution": self.resolution_var.get(),
            "dynamic_resolution": False,
            "clipboard": True,
            "ignore_cert": True,
            "security_protocol": "Auto",
            "enforce_tls": False,
            "debug_mode": False,
            "audio": False,
            "printer": False,
            "smartcard": False,
            "usb": False,
            "fullscreen": False,
            "multimon": False,
            "advanced_extra": "",
        }
        self.cfg.add(name, pdata)
        self._refresh_tree()
        messagebox.showinfo("Import", f"Imported Remmina profile as '{name}'.", parent=self)

    def _import_rdp(self):
        path = filedialog.askopenfilename(
            title="Import .rdp file",
            filetypes=[("RDP files", "*.rdp"), ("All files", "*.*")],
            parent=self,
        )
        if not path:
            return
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as e:
            messagebox.showerror("Import", f"Failed to read .rdp: {e}", parent=self)
            return
        data: Dict[str, str] = {}
        for line in lines:
            if ":" in line:
                key, _, rest = line.partition(":")
                _, _, val = rest.partition(":")
                data[key.strip()] = val.strip()

        server = data.get("full address", "")
        user = data.get("username", "")
        domain = data.get("domain", "")
        name = self._unique_profile_name(Path(path).stem)

        pdata = {
            "group": "",
            "server": server,
            "username": user,
            "password": "",
            "domain": domain,
            "resolution": self.resolution_var.get(),
            "dynamic_resolution": False,
            "clipboard": True,
            "ignore_cert": True,
            "security_protocol": "Auto",
            "enforce_tls": False,
            "debug_mode": False,
            "audio": False,
            "printer": False,
            "smartcard": False,
            "usb": False,
            "fullscreen": False,
            "multimon": False,
            "advanced_extra": "",
        }
        self.cfg.add(name, pdata)
        self._refresh_tree()
        messagebox.showinfo("Import", f"Imported .rdp profile as '{name}'.", parent=self)

    def _import_csv(self):
        path = filedialog.askopenfilename(
            title="Import profiles from CSV",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            parent=self,
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                count = 0
                for row in reader:
                    base = (row.get("name") or "").strip() or "Imported"
                    name = self._unique_profile_name(base)
                    server = (row.get("server") or "").strip()
                    user = (row.get("username") or "").strip()
                    domain = (row.get("domain") or "").strip()
                    pw_plain = (row.get("password") or "").strip()
                    group = (row.get("group") or "").strip()
                    pdata = {
                        "group": group,
                        "server": server,
                        "username": user,
                        "password": self.enc.enc(pw_plain) if pw_plain else "",
                        "domain": domain,
                        "resolution": self.resolution_var.get(),
                        "dynamic_resolution": False,
                        "clipboard": True,
                        "ignore_cert": True,
                        "security_protocol": "Auto",
                        "enforce_tls": False,
                        "debug_mode": False,
                        "audio": False,
                        "printer": False,
                        "smartcard": False,
                        "usb": False,
                        "fullscreen": False,
                        "multimon": False,
                        "advanced_extra": "",
                    }
                    self.cfg.add(name, pdata)
                    count += 1
        except Exception as e:
            messagebox.showerror("Import", f"CSV import failed: {e}", parent=self)
            return
        self._refresh_tree()
        messagebox.showinfo("Import", "CSV import completed.", parent=self)

    def _import_terminals(self):
        """Import RDP connections from Terminals Favorites.xml (RDP only)."""
        if not XML_AVAILABLE:
            messagebox.showerror("Import", "XML support not available; cannot import Terminals files.", parent=self)
            return
        src = filedialog.askopenfilename(
            title="Import from Terminals - Select Favorites.xml",
            filetypes=[
                ("Terminals Favorites", "Favorites.xml"),
                ("XML files", "*.xml"),
                ("All files", "*.*"),
            ],
            parent=self,
        )
        if not src:
            return
        try:
            tree = ET.parse(src)
            root = tree.getroot()
        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to parse XML: {e}", parent=self)
            return

        def get_text(elem, tag, default=""):
            if elem is None:
                return default
            child = elem.find(tag)
            if child is not None and child.text:
                return child.text.strip()
            for alt in (tag.lower(), tag.upper(), tag.capitalize()):
                child = elem.find(alt)
                if child is not None and child.text:
                    return child.text.strip()
            return default

        favorites = (
            root.findall(".//favorite")
            or root.findall(".//Favorite")
            or root.findall("favorite")
            or root.findall("Favorite")
        )
        if not favorites:
            messagebox.showerror(
                "Import Error",
                "No <favorite> entries found. Please select Terminals Favorites.xml.",
                parent=self,
            )
            return

        imported = 0
        skipped = 0

        for fav in favorites:
            protocol = get_text(fav, "protocol", "").lower()
            if protocol and protocol != "rdp":
                skipped += 1
                continue
            name = (
                get_text(fav, "name")
                or get_text(fav, "displayName")
                or get_text(fav, "connectionName")
                or "Imported Connection"
            )
            host = get_text(fav, "serverName") or get_text(fav, "server") or ""
            username = get_text(fav, "userName") or ""
            domain = get_text(fav, "domain") or ""
            password = get_text(fav, "password") or ""
            group = get_text(fav, "groupName") or ""

            if not host:
                skipped += 1
                continue

            prof_name = self._unique_profile_name(name)
            pdata = {
                "group": group,
                "server": host,
                "username": username,
                "password": self.enc.enc(password) if password else "",
                "domain": domain,
                "resolution": self.resolution_var.get(),
                "dynamic_resolution": False,
                "clipboard": True,
                "ignore_cert": True,
                "security_protocol": "Auto",
                "enforce_tls": False,
                "debug_mode": False,
                "audio": False,
                "printer": False,
                "smartcard": False,
                "usb": False,
                "fullscreen": False,
                "multimon": False,
                "advanced_extra": "",
            }
            self.cfg.add(prof_name, pdata)
            imported += 1

        self._refresh_tree()
        msg = f"Imported {imported} RDP connection(s)"
        if skipped:
            msg += f"\nSkipped {skipped} non-RDP or invalid entries."
        messagebox.showinfo("Terminals Import", msg, parent=self)

    def _export_current_rdp(self):
        name = self.profile_entry.get().strip()
        if not name or name not in self.cfg.connections:
            messagebox.showerror("Export", "Load a profile first.", parent=self)
            return
        pdata = self.cfg.connections[name]
        server = pdata.get("server", "")
        user = pdata.get("username", "")
        domain = pdata.get("domain", "")

        dst = filedialog.asksaveasfilename(
            title="Export profile as .rdp",
            defaultextension=".rdp",
            initialfile=f"{name}.rdp",
            filetypes=[("RDP files", "*.rdp"), ("All files", "*.*")],
            parent=self,
        )
        if not dst:
            return
        lines = [
            f"full address:s:{server}",
            f"username:s:{user}",
        ]
        if domain:
            lines.append(f"domain:s:{domain}")
        try:
            Path(dst).write_text("\n".join(lines), encoding="utf-8")
            messagebox.showinfo("Export", f"Profile exported to {dst}", parent=self)
        except Exception as e:
            messagebox.showerror("Export", f"Failed to write .rdp: {e}", parent=self)

    # ── bulk operations ──
    def _get_selected_profiles(self) -> List[str]:
        """Return list of selected profile names from the tree (ignoring folders)."""
        names: List[str] = []
        for iid in self.tree.selection():
            if self.tree.get_children(iid):
                continue
            name = self.tree.item(iid, "text")
            if name in self.cfg.connections:
                names.append(name)
        return names

    def _bulk_delete_profiles(self):
        """Delete all selected profiles."""
        names = self._get_selected_profiles()
        if not names:
            messagebox.showinfo("Bulk Delete", "No profiles selected.", parent=self)
            return
        if not messagebox.askyesno(
            "Bulk Delete",
            f"Delete {len(names)} selected profile(s)?\n\nThis action cannot be undone.",
            parent=self,
        ):
            return
        for n in names:
            self.cfg.delete(n)
        self._refresh_tree()
        self._clear_form()
        self._update_status(f"Deleted {len(names)} profile(s)", "success")

    def _bulk_clone_profiles(self):
        """Clone all selected profiles into new profiles."""
        names = self._get_selected_profiles()
        if not names:
            messagebox.showinfo("Bulk Clone", "No profiles selected.", parent=self)
            return
        prefix = simpledialog.askstring(
            "Bulk Clone",
            "Optional name prefix for cloned profiles (leave blank to reuse names):",
            parent=self,
        )
        if prefix is None:
            return
        prefix = prefix.strip()

        cloned = 0
        for src in names:
            base_name = f"{prefix}{src}" if prefix else src
            dst = base_name
            counter = 1
            while dst in self.cfg.connections:
                dst = f"{base_name} ({counter})"
                counter += 1
            self.cfg.add(dst, dict(self.cfg.connections[src]))
            cloned += 1
        self._refresh_tree()
        self._update_status(f"Cloned {cloned} profile(s)", "success")

    def _bulk_export_rdp(self):
        """Export selected profiles to .rdp files in a chosen directory."""
        names = self._get_selected_profiles()
        if not names:
            messagebox.showinfo("Bulk Export", "No profiles selected.", parent=self)
            return
        dest_dir = filedialog.askdirectory(
            title="Select folder to save .rdp files",
            parent=self,
        )
        if not dest_dir:
            return

        exported = 0
        errors: List[str] = []
        for name in names:
            data = self.cfg.connections.get(name) or {}
            server = data.get("server") or ""
            username = data.get("username") or ""
            domain = data.get("domain") or ""
            res = data.get("resolution") or DEFAULT_RESOLUTION
            try:
                width, height = res.split("x", 1)
            except Exception:
                width, height = DEFAULT_RESOLUTION.split("x", 1)
            clipboard = "1" if data.get("clipboard") else "0"

            safe_name = "".join(c if c.isalnum() or c in "-._" else "_" for c in name)
            out_path = os.path.join(dest_dir, f"{safe_name}.rdp")
            lines = [
                f"full address:s:{server}",
                f"username:s:{username}",
                f"domain:s:{domain}",
                f"desktopwidth:i:{width}",
                f"desktopheight:i:{height}",
                f"redirectclipboard:i:{clipboard}",
            ]
            try:
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
                exported += 1
            except Exception as e:
                errors.append(f"{name}: {e}")

        msg = "Bulk .rdp export complete!\n\n"
        msg += f"Exported: {exported} file(s)\n"
        if errors:
            msg += "\nErrors:\n" + "\n".join(errors[:5])
            if len(errors) > 5:
                msg += f"\n... and {len(errors) - 5} more"
        messagebox.showinfo("Bulk Export", msg, parent=self)

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
        # Save window geometry
        try:
            state = {"geometry": self.geometry()}
            WINDOW_STATE_FILE.write_text(json.dumps(state))
            WINDOW_STATE_FILE.chmod(0o600)
        except Exception:
            pass

        # Kill all active sessions
        for info in list(self.active.values()):
            proc = info.get("proc") if isinstance(info, dict) else info
            if proc:
                self._kill_pg(proc)
        self.destroy(); self.quit()

# ─────────────────────────── main ─────────────────────────────
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="XFreeRDP Manager")
    parser.add_argument("--connect", metavar="PROFILE", help="Connect to the given profile on startup")
    parser.add_argument("--test", metavar="PROFILE", help="Test connection for the given profile on startup")
    parser.add_argument("--list", action="store_true", help="List available profiles and exit")

    args = parser.parse_args(argv)

    master_pw = _get_master()
    enc = EncryptionManager(master_pw)
    cfg = ConfigManager(CFG_FILE, MAC_FILE, enc.mac_key())

    if args.list:
        for name in sorted(cfg.connections.keys(), key=str.lower):
            data = cfg.connections.get(name) or {}
            server = data.get("server", "")
            print(f"{name}\t{server}")
        return 0

    gui = RDPApp(enc, cfg, cli_connect=args.connect, cli_test=args.test)
    gui.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())