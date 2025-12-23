# XFreeRDP-Manager

## Overview
**XFreeRDP-Manager** is a hardened, cross‑platform GUI that lets you organise and launch `xfreerdp` sessions securely.  
Passwords, smart‑card options, multi‑monitor flags and dozens of other settings are saved per‑profile and protected by **strong encryption + two‑factor authentication**.

---

## Feature Highlights (v0.7.4)

|Category|Details|
|----------|---------|
| **Security** | • Master vault unlocked with **Argon2id** (≈600K iterations PBKDF2 fallback)<br>• **TOTP 2‑factor** (Google Authenticator, Authy, 1Password) with **24‑hour unlock cache**<br>• QR code shown automatically (*qrcode+Pillow*).<br>• Per‑file **HMAC‑SHA‑256** integrity; tamper ⇒ refuse to load<br>• Encrypted, password‑protected **`.rdpbak`** backup (vault + MAC + salts) with safe-path validation.<br>• In‑app **Change Master Password…** re‑encrypts all profiles + TOTP secret. |
| **Profiles** | Nested group tree with drag‑and‑drop between folders, tag search, clone, JSON backup/restore, **favorites**, **profile templates**, and bulk operations (delete / clone / export to `.rdp`). |
| **RDP options** | Clipboard, sound, USB, smart‑card, TLSv1.2 enforce, multi‑monitor, dynamic‑resolution, extra CLI flags (validated to avoid shell injection). |
| **Sessions** | Launch `xfreerdp` in its own **process‑group**; GUI can list / kill orphan sessions; automatic cleanup loop; optional `psutil` orphan scan. |
| **History / CLI** | Connection history viewer, **Recent** and **Favorites** menus, plus a CLI: `python XFreeRDP-Manager.py --list/--connect NAME/--test NAME`. |
| **Import / Export** | One‑click import from **Remmina** (`.remmina`), **Windows `.rdp`**, **CSV**, and **Terminals Favorites.xml** (RDP entries only); single or bulk export to `.rdp`. |
| **UI / UX** | Dark mode via **ttkbootstrap**, modern button layout, command preview, tooltips on all major actions, window‑state restore, and theme‑aware icons. |

---

## Installation

### 1.Prerequisites
* Python≥3.9 (with `tkinter`)
* `xfreerdp` **3.x** or **2.x** in `$PATH`

### 2.Recommended Python packages

```bash
pip install   cryptography argon2-cffi   ttkbootstrap   pyotp qrcode[pil] pillow   psutil
```

*Packages in **italics** are optional; the GUI degrades gracefully if they are missing (e.g. no QR, no orphan scan).*

### 3.Running from source

```bash
git clone https://github.com/Marzlio/XFreeRDP-Manager.git
cd XFreeRDP-Manager
python XFreeRDP-Manager.py
 # or use the CLI:
 #   list profiles:   python XFreeRDP-Manager.py --list
 #   connect:         python XFreeRDP-Manager.py --connect "My Profile"
 #   test connection: python XFreeRDP-Manager.py --test "My Profile"
```

### 4.Building a single‑file executable (PyInstaller≥6)

```bash
# inside a clean virtual‑env with all deps installed
pyinstaller XFreeRDP-Manager.py   --onefile --clean --noupx   --collect-submodules ttkbootstrap --collect-data ttkbootstrap   --collect-submodules argon2   --collect-binaries argon2   --collect-submodules pyotp    --collect-submodules psutil   --collect-submodules qrcode   --collect-submodules PIL --collect-data PIL   --hidden-import PIL._tkinter_finder
```

The resulting `dist/XFreeRDP-Manager` (or `.exe`) contains all runtime libraries and can be copied to a machine with **no Python installed**.

---

## Quick‑start

1. **First launch** → choose a master password → scan the QR with GoogleAuthenticator.  
2. Click **New Profile**, fill in server / username / password, adjust advanced options, **Save**.  
3. Double‑click the profile (or select →**Connect**) to start the session.  
4. **File▸Backup Profiles…** to create an encrypted `.rdpbak`.  
5. Restore on a new computer via **File▸Restore Profiles…**, then unlock with the same master password + TOTP.

---

## Security Details

| Component | Implementation |
|-----------|----------------|
| Master secret | Argon2id *(19MiB×2 passes)* → 32‑byte key.  PBKDF2‑SHA‑256 (600k) fallback on systems without `argon2-cffi`. |
| Vault encryption | AES‑128 in Fernet wrapper (`cryptography.fernet`). |
| Integrity | HMAC‑SHA‑256 keyed with a derivative of the master password (unique salt, 600k PBKDF2). |
| 2‑FA | TOTP RFC6238; 6‑digit code, 30s window, verified locally (offline). |
| Backup file | Fernet‑encrypted JSON blob; includes vault + `master.hash` + MAC + salts. |
| File permissions | Config dir `0700`; every sensitive file `0600`; validated on startup. |
| Process hygiene | `xfreerdp` spawned in a new process‑group → GUI can send `SIGTERM` / `SIGKILL` to the whole group; orphan scan with`psutil`. |

---

## Planned / Nice‑to‑Have

* FIDO2 / YubiKey challenge‑response unlock  
* Structured JSON logging with rotation  
* Auto‑update notifier via GitHub releases  

---

## License
MIT – see [LICENSE](LICENSE).

---

©2025[Marzlio](https://github.com/Marzlio)
