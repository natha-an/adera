#!/usr/bin/env python3
"""
Adera - a small command-line password manager.

Security model
--------------
* The encryption key is DERIVED from the master password with scrypt.
  No key file is stored, so stealing the vault file alone is useless
  without the master password.
* The whole vault (account names + passwords) is encrypted as one Fernet
  token (AES-128-CBC + HMAC). A wrong master password simply fails to
  decrypt, so no separate password hash is needed.
* Files live in ~/.adera (override with ADERA_HOME) with 0700/0600 perms.
* Writes are atomic (temp file + rename) so a crash can't corrupt the vault.

Requirements:  pip install cryptography
"""

import base64
import getpass
import json
import os
import secrets
import string
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

BANNER = r"""
       ▄▄
   ████          ██
   ████     ▄███▄██   ▄████▄    ██▄████   ▄█████▄
  ██  ██   ██▀  ▀██  ██▄▄▄▄██   ██▀       ▀ ▄▄▄██
  ██████   ██    ██  ██▀▀▀▀▀▀   ██       ▄██▀▀▀██
 ▄██  ██▄  ▀██▄▄███  ▀██▄▄▄▄█   ██       ██▄▄▄███
 ▀▀    ▀▀    ▀▀▀ ▀▀    ▀▀▀▀▀    ▀▀        ▀▀▀▀ ▀▀
"""

APP_DIR = Path(os.environ.get("ADERA_HOME", Path.home() / ".adera"))
VAULT_FILE = APP_DIR / "vault.json"

MIN_MASTER_LENGTH = 12
MAX_UNLOCK_ATTEMPTS = 3
VAULT_VERSION = 1

# scrypt cost parameters (about 32 MB of RAM, a fraction of a second)
KDF_N = 2 ** 15
KDF_R = 8
KDF_P = 1


# --------------------------------------------------------------------------
# Low-level helpers
# --------------------------------------------------------------------------
def derive_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def secure_chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass  # e.g. Windows; best effort


def ensure_app_dir() -> None:
    APP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    secure_chmod(APP_DIR, 0o700)


def atomic_write(path: Path, data: str) -> None:
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        secure_chmod(Path(tmp_name), 0o600)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------
# Vault
# --------------------------------------------------------------------------
class Vault:
    def __init__(self):
        self.entries = []          # list of {"name": str, "site": str, "password": str}
        self._salt = b""
        self._kdf = (KDF_N, KDF_R, KDF_P)
        self._fernet = None

    # ---- creation / unlocking ------------------------------------------
    def create(self, master_password: str) -> None:
        self._salt = os.urandom(16)
        self._kdf = (KDF_N, KDF_R, KDF_P)
        self._fernet = Fernet(derive_key(master_password, self._salt, *self._kdf))
        self.entries = []
        self.save()

    def unlock(self, master_password: str) -> None:
        """Raises InvalidToken on a wrong password, ValueError on a bad file."""
        try:
            doc = json.loads(VAULT_FILE.read_text(encoding="utf-8"))
            self._salt = base64.b64decode(doc["salt"])
            n, r, p = doc["kdf"]["n"], doc["kdf"]["r"], doc["kdf"]["p"]
            token = doc["data"].encode()
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("Vault file is corrupted or unreadable.") from exc

        self._kdf = (n, r, p)
        fernet = Fernet(derive_key(master_password, self._salt, n, r, p))
        plaintext = fernet.decrypt(token)  # InvalidToken if password is wrong
        self.entries = json.loads(plaintext.decode("utf-8"))
        self._fernet = fernet

    # ---- persistence ----------------------------------------------------
    def save(self) -> None:
        ensure_app_dir()
        token = self._fernet.encrypt(json.dumps(self.entries).encode("utf-8"))
        n, r, p = self._kdf
        doc = {
            "version": VAULT_VERSION,
            "kdf": {"name": "scrypt", "n": n, "r": r, "p": p},
            "salt": base64.b64encode(self._salt).decode(),
            "data": token.decode(),
        }
        atomic_write(VAULT_FILE, json.dumps(doc, indent=2))

    def change_master_password(self, new_password: str) -> None:
        self._salt = os.urandom(16)
        self._kdf = (KDF_N, KDF_R, KDF_P)
        self._fernet = Fernet(derive_key(new_password, self._salt, *self._kdf))
        self.save()


# --------------------------------------------------------------------------
# User-input helpers
# --------------------------------------------------------------------------
def prompt_new_master_password() -> str:
    while True:
        pw = getpass.getpass(f"Choose a master password (min {MIN_MASTER_LENGTH} chars): ")
        if len(pw) < MIN_MASTER_LENGTH:
            print(f"Too short. Use at least {MIN_MASTER_LENGTH} characters "
                  "(a passphrase of several words works well).")
            continue
        if pw != getpass.getpass("Confirm master password: "):
            print("Passwords do not match. Try again.")
            continue
        return pw


def prompt_new_secret(label: str) -> str:
    """Ask for a password for an entry, or generate one."""
    while True:
        pw = getpass.getpass(f"Password for {label} (leave empty to generate one)\n: ")
        if not pw:
            pw = generate_password()
            wannaSee=input('Password generated and saved ,you want to see it? y/N: ')
            if wannaSee == 'Y' or 'Yes' or 'y' or 'yes': 
                print(f"Generated password: {pw}")
            elif wannaSee == 'N' or 'No' or 'n' or 'no':
                print('Password saved!')
            return pw
        if pw != getpass.getpass("Confirm password: "):
            print("Passwords do not match. Try again.")
            continue
        return pw


def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)
                and any(c in "!@#$%^&*()-_=+" for c in pw)):
            return pw


def list_entries(vault: Vault) -> bool:
    if not vault.entries:
        print("The vault is empty.")
        return False
    for i, entry in enumerate(vault.entries, start=1):
        site = entry.get("site", "")
        print(f"  {i}. {entry['name']}" + (f"  [{site}]" if site else ""))
    return True


def ask_index(prompt: str, count: int):
    raw = input(prompt).strip()
    if raw.isdigit() and 1 <= int(raw) <= count:
        return int(raw) - 1
    print("Invalid selection.")
    return None


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------
def action_add(vault: Vault) -> None:
    name = input("Account name: ").strip()
    if not name:
        print("Account name cannot be empty.")
        return
    site = input("Site or purpose (what is this password for? Enter to skip): ").strip()
    if any(e["name"].lower() == name.lower() and e.get("site", "").lower() == site.lower()
           for e in vault.entries):
        print("An entry with that account name and site already exists. "
              "Use 'Update' to change it.")
        return
    vault.entries.append({"name": name, "site": site, "password": prompt_new_secret(name)})
    vault.save()
    print("Password added.")


def action_view(vault: Vault) -> None:
    if not list_entries(vault):
        return
    idx = ask_index("Number of the entry to reveal (Enter to cancel): ", len(vault.entries))
    if idx is None:
        return
    entry = vault.entries[idx]
    print(f"\nAccount:  {entry['name']}")
    print(f"Site/Purpose: {entry.get('site') or '-'}")
    print(f"Password: {entry['password']}\n")


def action_remove(vault: Vault) -> None:
    if not list_entries(vault):
        return
    raw = input("Numbers to remove, comma-separated (Enter to cancel): ")
    wanted = {int(x) - 1 for x in raw.replace(" ", "").split(",") if x.isdigit()}
    wanted = {i for i in wanted if 0 <= i < len(vault.entries)}
    if not wanted:
        print("No valid entries selected.")
        return
    names = ", ".join(vault.entries[i]["name"] for i in sorted(wanted))
    if input(f"Permanently delete: {names}? Type 'yes' to confirm: ").strip().lower() != "yes":
        print("Cancelled.")
        return
    vault.entries = [e for i, e in enumerate(vault.entries) if i not in wanted]
    vault.save()
    print("Removed.")


def action_update(vault: Vault) -> None:
    if not list_entries(vault):
        return
    idx = ask_index("Number of the entry to update (Enter to cancel): ", len(vault.entries))
    if idx is None:
        return
    entry = vault.entries[idx]
    entry["password"] = prompt_new_secret(entry["name"])
    vault.save()
    print("Password updated.")


def action_change_master(vault: Vault) -> None:
    print("Your vault will be re-encrypted under the new master password.")
    vault.change_master_password(prompt_new_master_password())
    print("Master password changed.")


# --------------------------------------------------------------------------
# Startup / main loop
# --------------------------------------------------------------------------
def open_vault() -> Vault:
    ensure_app_dir()
    vault = Vault()

    if not VAULT_FILE.exists():
        print("No vault found. Let's create one.\n")
        vault.create(prompt_new_master_password())
        print("Vault created.\n")
        return vault

    for attempt in range(1, MAX_UNLOCK_ATTEMPTS + 1):
        pw = getpass.getpass("Master password: ")
        try:
            vault.unlock(pw)
            return vault
        except InvalidToken:
            left = MAX_UNLOCK_ATTEMPTS - attempt
            print("Wrong master password." + (f" {left} attempt(s) left." if left else ""))
        except ValueError as exc:
            print(exc)
            sys.exit(1)
    print("Too many failed attempts.")
    sys.exit(1)


MENU = """
1. Add password
2. View password
3. Remove password
4. Update password
5. Change master password
6. Quit
"""

ACTIONS = {
    "1": action_add,
    "2": action_view,
    "3": action_remove,
    "4": action_update,
    "5": action_change_master,
}


def main() -> None:
    print(BANNER)
    try:
        vault = open_vault()
        while True:
            print(MENU)
            choice = input("Enter your choice: ").strip()
            if choice == "6":
                print("Goodbye.")
                break
            action = ACTIONS.get(choice)
            if action is None:
                print("Invalid choice.")
                continue
            action(vault)
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted. Quitting.")


if __name__ == "__main__":
    main()