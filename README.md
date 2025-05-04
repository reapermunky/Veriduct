[![License: Dual - Apache 2.0 & Commercial](https://img.shields.io/badge/license-Apache%202.0%20%26%20Commercial-blue.svg)](LICENSE)
# Veriduct: A Framework for Semantic Erasure and Post-Encryption Data Control

**Veriduct doesn’t encrypt your data — it destroys its meaning.**  
It fragments files into semantically isolated chunks, stores them in an encrypted SQLCipher database, and emits a disguised reassembly key. Without the key, your data is **unrecoverable and unrecognizable**.

This isn’t a wrapper around cryptography. It’s a new layer **beneath** it.

---

## Key Features

- **Semantic Erasure:** Chunks carry no meaningful structure, metadata, or patterns. Files become forensic dead-ends.
- **Encrypted/Disguised Keymaps:** Output keys in formats like `.csv`, `.log`, or `.conf` — or encrypt them using password-derived AES via Fernet.
- **Encrypted SQL Storage:** Uses SQLCipher-compatible SQLite DB with PBKDF2-HMAC-SHA256 keying.
- **Post-Quantum Resilience:** Removes ciphertext artifacts and attack surfaces before quantum threats can even apply.
- **Total Control:** You can encode, disguise, destroy, and selectively decode — all from the CLI.

---

## Why?

Traditional encryption creates ciphertext: detectable, analyzable, and sometimes even recoverable with enough time or future compute power. Veriduct bypasses that entirely. It turns files into **meaningless entropy** unless paired with the correct reconstruction logic.

If the key is deleted, the data isn't just unreadable — it's **irreversibly uninterpretable**.

---

## Use Cases

- **Secure messaging / post-encryption channels**
- **Stealth file delivery / exfiltration**
- **Keyless self-destructing data**
- **Anti-forensic archival**
- **Quantum-resistant storage primitives**

---

## Basic Usage

### Encoding

```bash
python veriduct.py encode myfiles/ outdir/ --encrypt
```

- Stores data as fragments in a secure SQLite DB
- Writes a password-encrypted key file (`veriduct.key.enc`) or disguised output

### Disguise Key Instead

```bash
python veriduct.py encode myfiles/ outdir/ --disguise log
```

Output will look like a system log file with fake timestamps and noise.

---

### Decoding

```bash
python veriduct.py decode outdir/veriduct.key.enc restored/ --decrypt
```

Prompts for password and rebuilds original files in `restored/`.

---

## Example: Disguised Log Output

```
2025-05-04T01:18:07 [INFO] secrets.docx ChunkRef: e9af12...
2025-05-04T01:18:08 [WARN] secrets.docx ChunkRef: a3c21f...
```

---

## Architecture Highlights

- `SecureChunkStorage`: Encrypted SQL interface for storing and retrieving chunks
- `disguise_key()`: Flexible keymap disguise logic (CSV, log, conf)
- `derive_fernet_key()`: PBKDF2-HMAC key derivation for secure key encryption
- CLI-based with `argparse`, ready for integration or automation

---

## Legal

**For research and educational purposes only.**  
Author assumes no responsibility for misuse.

---

## Contact

Built by Christopher Aziz  
[GitHub](https://github.com/reapermunky) | chrisaziz@proton.me linkedin.com/in/christopher-aziz/
