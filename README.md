# Adera

A small command-line password manager written in Python. Your passwords are stored in a single encrypted vault, and the encryption key is derived from your master password, so it is never saved anywhere.

> **Learning project.** Adera was built to practice applied cryptography and secure design. For real-world use, prefer a well-audited manager such as KeePassXC or Bitwarden.

## Features

- Add, view, update and remove saved passwords
- Record the site or purpose of each password
- Built-in generator for strong random passwords (20 characters, mixed character types)
- Master password minimum length of 12 characters, entered without echo
- 3 attempts to unlock, then the program exits
- Change the master password (the vault is re-encrypted under the new one)

## Requirements

- Python 3.8+
- The [`cryptography`](https://pypi.org/project/cryptography/) library

## Install and run

```bash
git clone https://github.com/natha-an/adera.git
cd adera

# a virtual environment is recommended (required on some Linux distros such as Kali)
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
python3 adera.py
```

On first run you are asked to create a master password. On later runs you unlock the vault with it.

## Menu

```
1. Add password
2. View password
3. Remove password
4. Update password
5. Change master password
6. Quit
```

## How it works

1. **Key derivation.** The master password and a random 16-byte salt go through **scrypt** (N=2^15, r=8, p=1) to produce a 32-byte key. scrypt is deliberately slow and memory-hungry, which makes offline guessing expensive.
2. **Encryption.** All entries are serialized to JSON and encrypted as a single token with **Fernet** (AES-128-CBC with an HMAC-SHA256 authentication tag). Any tampering with the file is detected.
3. **Storage.** `~/.adera/vault.json` contains only the KDF settings, the salt and the encrypted data. The master password, the key and the plaintext passwords are never written to disk.
4. **Unlocking.** The key is re-derived from the typed password and used to decrypt the vault. A wrong password fails the authentication check, so no password hash needs to be stored.
5. **Safe writes.** Saves go to a temporary file that is then renamed over the vault, so a crash cannot leave a half-written file. The folder is created with `0700` and the vault with `0600` permissions.

The storage location can be changed with the `ADERA_HOME` environment variable.

## Threat model and limitations

**Protects against**
- Someone obtaining `vault.json` alone: they must guess the master password offline, and scrypt makes each guess costly. A long passphrase makes this impractical.
- Accidental or malicious modification of the vault file, which is detected on unlock.

**Does not protect against**
- Malware, a keylogger or a compromised machine while the vault is in use. Passwords are decrypted in memory and printed to the terminal.
- Shoulder surfing or terminal scrollback: revealed and generated passwords stay visible until the terminal is cleared.
- A forgotten master password. There is no recovery mechanism.
- Online-style attempt limits: the 3-attempt limit only restarts the program. Real protection against offline guessing comes from scrypt and a strong master password.

## Project layout

```
adera.py           the application
requirements.txt   dependencies
LICENSE            MIT license
```

## License

MIT. See [LICENSE](LICENSE).
