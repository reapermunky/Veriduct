"""
Veriduct: A Data Framework for Stealth File Encoding and Decoding

DISCLAIMER: For educational and research purposes only. Use legally and ethically.
The author is not responsible for any misuse.

Dependencies:
  - Python 3.7+
  - pysqlite3 (for encrypted SQLite via SQLCipher)
  - cryptography
  - zstandard
"""

import os
import sys
import json
import hashlib
import argparse
import datetime
import random
import logging
import base64
import getpass
from pathlib import Path
from typing import Dict, Any, Optional

import zstandard as zstd
import sqlite3

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
CHUNK_SIZE = 4 * 1024  # 4 KiB
DEFAULT_DB    = Path("veriduct_chunks.db")
KEY_FILE_ZST  = "veriduct.key.zst"
KEY_FILE_ENC  = "veriduct.key.enc"
DISGUISE_FORMATS = ("csv", "log", "conf")

# A hard-coded salt (bytes). Displayed/exported in hex.
SALT = bytes.fromhex("9ec5b91a08192c57ad890f09fbcd5a93")

# ------------------------------------------------------------------------------
# Logging setup
# ------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# ------------------------------------------------------------------------------
# Utility Functions
# ------------------------------------------------------------------------------
def sha256_hash(data: bytes) -> str:
    """Return the SHA-256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()

def file_sha256(path: Path) -> Optional[str]:
    """Compute SHA-256 digest of a file, or return None on error."""
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logging.error(f"Failed to hash file '{path}': {e}")
        return None

def derive_raw_key(password: bytes, salt: bytes = SALT,
                   iterations: int = 100_000, length: int = 32) -> bytes:
    """Derive raw bytes for a key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)

def derive_fernet_key(password: bytes, salt: bytes = SALT) -> bytes:
    """Derive a Fernet-compatible key (base64-encoded)."""
    raw = derive_raw_key(password, salt)
    return base64.urlsafe_b64encode(raw)

def ensure_dir(path: Path) -> None:
    """Create directory (and parents) if it doesn’t exist."""
    try:
        path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logging.error(f"Could not create directory '{path}': {e}")
        sys.exit(1)

# ------------------------------------------------------------------------------
# SecureChunkStorage
# ------------------------------------------------------------------------------
class SecureChunkStorage:
    """
    Securely store/retrieve chunks in an encrypted SQLite database (SQLCipher).
    """
    def __init__(self, db_path: Path, raw_key: Optional[bytes] = None):
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path))
        if raw_key:
            # SQLCipher PRAGMA
            fkey = raw_key.decode() if isinstance(raw_key, bytes) else raw_key
            self.conn.execute("PRAGMA key = ?;", (fkey,))
        self._init_table()

    def _init_table(self):
        try:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS chunks (
                    hash TEXT PRIMARY KEY,
                    data BLOB NOT NULL
                );
            """)
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f"DB init error: {e}")
            self.conn.rollback()
            sys.exit(1)

    def store_chunk(self, chunk_hash: str, data: bytes) -> None:
        try:
            self.conn.execute(
                "INSERT OR REPLACE INTO chunks (hash, data) VALUES (?, ?);",
                (chunk_hash, data)
            )
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Error storing chunk {chunk_hash}: {e}")
            self.conn.rollback()

    def retrieve_chunk(self, chunk_hash: str) -> Optional[bytes]:
        try:
            cur = self.conn.execute(
                "SELECT data FROM chunks WHERE hash = ?;", (chunk_hash,)
            )
            row = cur.fetchone()
            return row[0] if row else None
        except sqlite3.Error as e:
            logging.error(f"Error retrieving chunk {chunk_hash}: {e}")
            return None

    def close(self):
        self.conn.close()

# ------------------------------------------------------------------------------
# Disguise / Undisguise
# ------------------------------------------------------------------------------
def disguise_key(key_map: Dict[str, Any], out_dir: Path, style: str) -> None:
    ensure_dir(out_dir)
    out_file = out_dir / f"veriduct_key.{style}"
    try:
        if style == "csv":
            with out_file.open("w", encoding="utf-8") as f:
                f.write("filename,index,chunk\n")
                for fname, info in key_map.items():
                    for idx, ch in enumerate(info["key"]):
                        f.write(f"{fname},{idx},{ch}\n")
        elif style == "log":
            with out_file.open("w", encoding="utf-8") as f:
                for fname, info in key_map.items():
                    for ch in info["key"]:
                        ts = datetime.datetime.now().isoformat()
                        lvl = random.choice(("INFO","DEBUG","WARN"))
                        f.write(f"{ts} [{lvl}] {fname} ChunkRef: {ch}\n")
        elif style == "conf":
            with out_file.open("w", encoding="utf-8") as f:
                for fname, info in key_map.items():
                    f.write(f"[{fname}]\n")
                    for idx, ch in enumerate(info["key"]):
                        f.write(f"chunk{idx} = {ch}\n")
        else:
            raise ValueError(f"Unsupported disguise style: {style}")
        logging.info(f"Disguised key written to '{out_file}'")
    except Exception as e:
        logging.error(f"Failed to write disguised key: {e}")
        sys.exit(1)

def decode_disguise(key_path: Path, style: str) -> Dict[str, Any]:
    key_map: Dict[str, Any] = {}
    try:
        lines = key_path.read_text(encoding="utf-8").splitlines()
        if style == "csv":
            for line in lines[1:]:
                fn, _, ch = line.split(",", 2)
                key_map.setdefault(fn, {"key": []})["key"].append(ch)
        elif style == "log":
            for line in lines:
                if "ChunkRef: " in line:
                    fn = line.split()[2]
                    ch = line.split("ChunkRef: ")[1].strip()
                    key_map.setdefault(fn, {"key": []})["key"].append(ch)
        elif style == "conf":
            current = None
            for line in lines:
                if line.startswith("[") and line.endswith("]"):
                    current = line[1:-1]
                    key_map[current] = {"key": []}
                elif current and "=" in line:
                    ch = line.split("=",1)[1].strip()
                    key_map[current]["key"].append(ch)
        else:
            raise ValueError(f"Unsupported disguise style: {style}")

        # compute combined file_hash for each entry
        for fn, info in key_map.items():
            combined = "".join(info["key"]).encode()
            info["file_hash"] = sha256_hash(combined)
        return key_map

    except Exception as e:
        logging.error(f"Error decoding disguised key file '{key_path}': {e}")
        sys.exit(1)

# ------------------------------------------------------------------------------
# Encode / Decode Logic
# ------------------------------------------------------------------------------
def encode_directory(
    input_dir: Path,
    output_dir: Path,
    db_path: Path,
    disguise: Optional[str] = None,
    encrypt_key: bool = False
):
    if not input_dir.exists():
        logging.error(f"Input path not found: {input_dir}")
        sys.exit(1)
    ensure_dir(output_dir)

    # Prepare chunk storage
    raw_db_key = None
    if encrypt_key:
        pwd = getpass.getpass("Password for key encryption: ").encode()
        raw_db_key = derive_raw_key(pwd)
    storage = SecureChunkStorage(db_path, raw_db_key)

    key_map: Dict[str, Any] = {}
    for f in input_dir.rglob("*"):
        if f.is_file():
            rel = f.relative_to(input_dir).as_posix()
            h = file_sha256(f)
            if h is None:
                continue
            key_seq = []
            with f.open("rb") as src:
                for chunk in iter(lambda: src.read(CHUNK_SIZE), b""):
                    chash = sha256_hash(chunk)
                    storage.store_chunk(chash, chunk)
                    key_seq.append(chash)
            key_map[rel] = {"file_hash": h, "key": key_seq}
            logging.info(f"Encoded '{rel}' ({len(key_seq)} chunks)")

    storage.close()

    # Emit key
    if disguise:
        disguise_key(key_map, output_dir, disguise)
    elif encrypt_key:
        pwd = getpass.getpass("Re-enter password to encrypt key file: ").encode()
        fkey = derive_fernet_key(pwd)
        token = Fernet(fkey).encrypt(json.dumps(key_map).encode())
        outp = output_dir / KEY_FILE_ENC
        outp.write_bytes(token)
        logging.info(f"Encrypted key written to '{outp}' (salt={SALT.hex()})")
    else:
        compressed = zstd.ZstdCompressor().compress(json.dumps(key_map).encode())
        outp = output_dir / KEY_FILE_ZST
        outp.write_bytes(compressed)
        logging.info(f"Key written to '{outp}' (salt={SALT.hex()})")

def decode_file(
    key_file: Path,
    output_dir: Path,
    db_path: Path,
    disguise: Optional[str] = None,
    decrypt_key: bool = False
):
    ensure_dir(output_dir)

    # Load key_map
    if disguise:
        key_map = decode_disguise(key_file, disguise)
    else:
        raw = key_file.read_bytes()
        if decrypt_key:
            pwd = getpass.getpass("Password to decrypt key: ").encode()
            fkey = derive_fernet_key(pwd)
            try:
                raw = Fernet(fkey).decrypt(raw)
            except Exception as e:
                logging.error(f"Decryption failed: {e}")
                sys.exit(1)
        else:
            try:
                raw = zstd.ZstdDecompressor().decompress(raw)
            except Exception as e:
                logging.error(f"Decompression failed: {e}")
                sys.exit(1)
        key_map = json.loads(raw.decode())

    # Prepare storage
    raw_db_key = derive_raw_key(getpass.getpass("DB password (if used): ").encode()) if decrypt_key else None
    storage = SecureChunkStorage(db_path, raw_db_key)

    # Reconstruct files
    for rel, info in key_map.items():
        outp = output_dir / rel
        ensure_dir(outp.parent)
        with outp.open("wb") as outf:
            for chash in info["key"]:
                chunk = storage.retrieve_chunk(chash)
                if chunk:
                    outf.write(chunk)
                else:
                    logging.error(f"Missing chunk {chash} for '{rel}'")
        new_h = file_sha256(outp)
        if new_h == info["file_hash"]:
            logging.info(f"Rebuilt '{rel}' successfully")
        else:
            logging.error(f"Hash mismatch for '{rel}': expected {info['file_hash']} vs {new_h}")

    storage.close()

# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(prog="veriduct", description="Veriduct – channel beneath control")
    p.add_argument("--db",    type=Path, default=DEFAULT_DB, help="Path to SQLite DB")
    sp = p.add_subparsers(dest="cmd", required=True)

    enc = sp.add_parser("encode", help="Encode a directory")
    enc.add_argument("input", type=Path,  help="Directory to encode")
    enc.add_argument("out",   type=Path,  help="Directory for key output")
    enc.add_argument("--disguise", choices=DISGUISE_FORMATS, help="Disguise format")
    enc.add_argument("--encrypt", action="store_true", help="Encrypt key output")

    dec = sp.add_parser("decode", help="Decode and rebuild files")
    dec.add_argument("key",    type=Path, help="Path to key file")
    dec.add_argument("out",    type=Path, help="Directory for restored files")
    dec.add_argument("--disguise", choices=DISGUISE_FORMATS, help="Specify disguise format used")
    dec.add_argument("--decrypt", action="store_true", help="Decrypt key input")

    args = p.parse_args()

    if args.cmd == "encode":
        encode_directory(args.input, args.out, args.db, args.disguise, args.encrypt)
    else:
        decode_file(args.key, args.out, args.db, args.disguise, args.decrypt)

if __name__ == "__main__":
    main()
