[![License: Dual - Apache 2.0 & Commercial](https://img.shields.io/badge/license-Apache%202.0%20%26%20Commercial-blue.svg)](LICENSE)

Veriduct is free to use for nonprofit, humanitarian, or journalistic purposes under the Apache 2.0 license.

# Veriduct: A Framework for Semantic Erasure and Post-Cryptographic Data Control

**Veriduct doesn’t encrypt your data, it annihilates its meaning.**  
It fragments files into semantically isolated chunks, strips headers, and emits a disguised reassembly key. Without that key, your data is **permanently uninterpretable**.

Not encryption. This is **semantic annihilation**.

---

## Key Features

- **Cognitive Security Layer:** Fragments carry no metadata, structure, or identifiable patterns. Meaning is destroyed, not just concealed.
- **Disguised Keymaps:** Output keys in formats like `.csv`, `.log`, or `.conf` to blend into existing systems and workflows.
- **Header Stripping:** The original file header is removed, stored separately, and re-applied only during valid reassembly.
- **No Encryption Required:** No ciphertext, no cryptographic weaknesses. Just raw unlabelled entropy.
- **Irreversible Without Key:** The chunk database is meaningless without the salted keymap - deletion of the key equals total semantic loss.

---

## Why?

Encryption creates ciphertext, which is inherently recognizable and potentially reversible under future conditions (quantum or otherwise). Veriduct removes the assumption that files need to be "protected." Instead, it makes them **meaningless without instruction**.

If the key is lost, the data is not merely scrambled, it's **irretrievable** in any semantic form.

---

## Use Cases

- **Post-encryption secure messaging**
- **Stealth file transport / anti-forensic archival**
- **Keyless self-destructing files**
- **Quantum-neutral secure storage**
- **Red-team tools & intelligence-grade data handling**

---

## Usage

### Annihilate (Encode)

```bash
python veriduct.py annihilate myfiles/ outdir/ --disguise log
```

- Randomizes the header
- Shreds file into unlabelled chunks
- Stores them in a raw SQLite DB
- Outputs a disguised reassembly key (`veriduct_key.log`)

---

### Reassemble (Decode)

```bash
python veriduct.py reassemble outdir/veriduct_key.log restored/ --disguise log
```

- Reads chunk DB
- Verifies stream integrity (HMAC optional)
- Restores USF stream and reattaches original header

---

## Sample Log Key Output

```
2025-05-22T10:12:44 [INFO] FileMetadata: File=secrets.docx Salt=... USFHash=... MAC=... OriginalHeader=...
2025-05-22T10:12:45 [DEBUG] FileRef=secrets.docx ChunkId=0 ChunkHash=abc123...
2025-05-22T10:12:45 [INFO] FileRef=secrets.docx ChunkId=1 ChunkHash=def456...
```

---

## Architecture Highlights

- `ChunkStorage`: Raw SQLite interface for chunk persistence
- `disguise_key()`: Converts keymap to fake `.log`, `.csv`, or `.conf` formats
- Optional per-file HMAC for tamper detection
- Header randomization using entropy-based wiping
- All data recoverability hinges on presence of keymap

---

## Legal

**For educational and research use only.**  
You are responsible for any deployment or misuse.  
This tool intentionally destroys semantic data fidelity.

---

## Licensing Summary

Veriduct is dual-licensed:

- **Apache 2.0 License** (see `LICENSE`): Free for personal, academic, research, nonprofit, and civilian use.
- **Commercial License** (see `COMMERCIAL_LICENSE.txt`): Required for integration into paid products, commercial services, enterprise infrastructure, government contracts, or military use.

For commercial licensing inquiries, contact: chrisaziz@proton.me

---

## Contact

Created by Christopher Aziz  
[GitHub](https://github.com/reapermunky) | chrisaziz@proton.me 

---

### Live:
Try Veriduct: https://web-production-404ea.up.railway.app/
