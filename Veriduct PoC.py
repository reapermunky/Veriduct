"""
Veriduct: A Data Framework for Stealth File Encoding and Decoding

DISCLAIMER: This tool is provided for educational and research purposes only.
It is intended for legal and ethical use. The author is not responsible for any misuse.

Dependencies:
  - pysqlite3 (for SQLite)
  - cryptography
  - zstandard

"""

import os
import sys
import json
import hashlib
import argparse
import datetime
import zstandard as zstd
import random
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import sqlite3

# Configure logging for robust output
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

CHUNK_SIZE = 4096
#DICT_DIR = "veriduct_dict"  # No longer used for file system storage
KEY_FILE = "veriduct.key.zst"
ENCRYPTED_KEY_FILE = "veriduct.key.enc"
DB_FILE = "veriduct_chunks.db"  # SQLite database file
DISGUISE_FORMATS = ["csv", "log", "conf"]
# Set a strong, unique, and hardcoded salt.  This should be a byte string.
SALT = b'\\x9e\\xc5\\xb9\x1a\x08\x92\x8cW\xad\x89\x0f\t\xfb\xcdZ\x93'

def sha256_hash(data: bytes) -> str:
    """Return SHA-256 hash of the given data as a hexadecimal string."""
    return hashlib.sha256(data).hexdigest()

def ensure_dirs(directory):
    """Ensure the specified directory exists."""
    try:
        os.makedirs(directory, exist_ok=True)
    except Exception as e:
        logging.error(f"Failed to create directory '{directory}': {e}")
        sys.exit(1)



class SecureChunkStorage:
    """
    Handles secure storage of data chunks in an encrypted SQLite database.
    """
    def __init__(self, db_path, encryption_key):
        """
        Initialize the SecureChunkStorage with the database path and encryption key.

        Args:
            db_path (str): Path to the SQLite database file.
            encryption_key (bytes):  The raw encryption key (from KDF).
        """
        self.db_path = db_path
        self.encryption_key = encryption_key
        self.conn = sqlite3.connect(self.db_path)
        # Use a PRAGMA statement to set the key.  The exact PRAGMA is
        # database-specific.  This is for SQLCipher.  For other
        # databases, this will need to change.  Plain sqlite does not support encryption.
        self.conn.execute(f"PRAGMA key = :key", {"key": encryption_key})
        try:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chunks (
                    hash TEXT PRIMARY KEY,
                    data BLOB
                )
                """
            )
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Error creating database table: {e}")
            self.conn.rollback()
            self.conn.close()
            sys.exit(1)

    def store_chunk(self, chunk_hash, chunk_data):
        """
        Store a chunk of data in the database, replacing any existing chunk with the same hash.

        Args:
            chunk_hash (str): The SHA-256 hash of the chunk (used as the key).
            chunk_data (bytes): The data to store.
        """
        try:
            self.conn.execute(
                "INSERT OR REPLACE INTO chunks (hash, data) VALUES (?, ?)",
                (chunk_hash, chunk_data),
            )
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f"SQLite error storing chunk: {e}")
            self.conn.rollback()

    def retrieve_chunk(self, chunk_hash):
        """
        Retrieve a chunk of data from the database.

        Args:
            chunk_hash (str): The SHA-256 hash of the chunk to retrieve.

        Returns:
            bytes: The chunk data, or None if the chunk is not found.
        """
        try:
            cursor = self.conn.execute(
                "SELECT data FROM chunks WHERE hash = ?", (chunk_hash,)
            )
            result = cursor.fetchone()
            if result:
                return result[0]
            else:
                return None
        except sqlite3.Error as e:
            logging.error(f"SQLite error retrieving chunk: {e}")
            return None

    def close(self):
        """Close the database connection."""
        self.conn.close()



def disguise_key(key_data: dict, out_dir: str, style: str):
    """Disguise key data in a specified format and write to output file."""
    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception as e:
        logging.error(f"Failed to create output directory '{out_dir}': {e}")
        sys.exit(1)

    output_path = os.path.join(out_dir, f"veriduct_key.{style}")

    try:
        if style == "csv":
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("filename,id,value\n")
                for fname, data in key_data.items():
                    for i, ch in enumerate(data["key"]):
                        f.write(f"{fname},{i},{ch}\n")
        elif style == "log":
            with open(output_path, "w", encoding="utf-8") as f:
                for fname, data in key_data.items():
                    for ch in data["key"]:
                        ts = datetime.datetime.now().isoformat()
                        fake_level = random.choice(["INFO", "DEBUG", "WARN"])
                        f.write(f"{ts} [{fake_level}] {fname} ChunkRef: {ch}\n")
        elif style == "conf":
            with open(output_path, "w", encoding="utf-8") as f:
                for fname, data in key_data.items():
                    f.write(f"[{fname}]\n")
                    for i, ch in enumerate(data["key"]):
                        f.write(f"chunk{i} = {ch}\n")
        else:
            raise ValueError(f"Unknown disguise style: {style}")
    except Exception as e:
        logging.error(f"Error writing disguised key to '{output_path}': {e}")
        sys.exit(1)

    logging.info(f"Disguised key written to: {output_path}")



def decode_disguised_directory_key(key_path: str, style: str) -> dict:
    """Decode a disguised key file and return the key mapping."""
    key_map = {}
    try:
        with open(key_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        logging.error(f"Error reading key file '{key_path}': {e}")
        sys.exit(1)

    try:
        if style == "csv":
            # Skip header and parse CSV lines
            for line in lines[1:]:
                parts = line.strip().split(",")
                if len(parts) != 3:
                    continue
                fname, _, ch = parts
                key_map.setdefault(fname, {"key": []})["key"].append(ch)
        elif style == "log":
            for line in lines:
                if "ChunkRef: " in line:
                    parts = line.strip().split("ChunkRef: ")
                    if len(parts) != 2:
                        continue
                    pre, ch = parts
                    tokens = pre.split()
                    if tokens:
                        fname = tokens[-1]
                        key_map.setdefault(fname, {"key": []})["key"].append(ch)
        elif style == "conf":
            current_file = None
            for line in lines:
                line = line.strip()
                if line.startswith("[") and line.endswith("]"):
                    current_file = line[1:-1]
                    key_map[current_file] = {"key": []}
                elif line.startswith("chunk") and current_file:
                    parts = line.split("=")
                    if len(parts) != 2:
                        continue
                    ch = parts[-1].strip()
                    key_map[current_file]["key"].append(ch)
        else:
            raise ValueError(f"Unknown disguise style: {style}")

        # Generate a combined hash for verification purposes
        for fname in key_map:
            combined = "".join(key_map[fname]["key"]).encode("utf-8")
            key_map[fname]["file_hash"] = sha256_hash(combined)[:64]
    except Exception as e:
        logging.error(f"Error decoding disguised key: {e}")
        sys.exit(1)

    return key_map



def encode_directory(input_path, out_dir, disguise=None, encrypt_key=False):
    """
    Encode a directory (or file's parent directory) into chunks and generate a key mapping.

    This function walks through the directory structure, breaks files into chunks,
    stores them in a secure database, and outputs a key that can be optionally
    disguised or encrypted.
    """
    if not os.path.exists(input_path):
        logging.error(f"Input path does not exist: {input_path}")
        sys.exit(1)

    ensure_dirs(out_dir) # Ensure the output directory exists.
    key_map = {}

    # 1.  Create and initialize the chunk storage.
    if encrypt_key:
        # Derive a key from the user-supplied password.
        password = input("Enter a password to encrypt the key: ")
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=SALT,
            length=32,  # 256 bits
            backend=default_backend()
        )
        derived_key = kdf.derive(password_bytes)
        chunk_storage = SecureChunkStorage(DB_FILE, derived_key)
    else:
      chunk_storage = SecureChunkStorage(DB_FILE, b'') # Use empty key for unencrypted case.


    # Process each file in the directory
    for root, _, files in os.walk(input_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, input_path)
            key_sequence = []
            file_hash = file_sha256(fpath)
            if file_hash is None:
                continue
            try:
                with open(fpath, "rb") as f:
                    while True:
                        data = f.read(CHUNK_SIZE)
                        if not data:
                            break
                        chash = sha256_hash(data)
                        chunk_storage.store_chunk(chash, data)
                        key_sequence.append(chash)
            except Exception as e:
                logging.error(f"Error processing file '{fpath}': {e}")
                continue

            key_map[rel_path] = {"file_hash": file_hash, "key": key_sequence}

    # Close the chunk storage
    chunk_storage.close()

    # Output the key data
    try:
        if disguise:
            disguise_key(key_map, out_dir, disguise)
        elif encrypt_key:
            #  Encrypt the key_map using the derived key
            password = input("Re-enter the password to encrypt the key: ")
            password_bytes = password.encode('utf-8')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                iterations=100000,
                salt=SALT,
                length=32,  # 256 bits
                backend=default_backend()
            )
            derived_key = kdf.derive(password_bytes)
            cipher = Fernet(derived_key)
            encoded = json.dumps(key_map).encode("utf-8")
            encrypted = cipher.encrypt(encoded)
            out_path = os.path.join(out_dir, ENCRYPTED_KEY_FILE)
            with open(out_path, "wb") as f:
                f.write(encrypted)
            logging.info(f"Encrypted key written to: {out_path}")
            logging.info(f"Key Derivation Salt (save this!): {SALT.decode()}")

        else:
            key_path = os.path.join(out_dir, KEY_FILE)
            cctx = zstd.ZstdCompressor()
            compressed = cctx.compress(json.dumps(key_map).encode("utf-8"))
            with open(key_path, "wb") as kf:
                kf.write(compressed)
            logging.info(f"Directory encoded into '{key_path}' using database: '{DB_FILE}'")
    except Exception as e:
        logging.error(f"Error during key output: {e}")
        sys.exit(1)



def decode_file(key_path, out_dir, disguise=None, decrypt_key=None):
    """
    Decode a key file (disguised, encrypted, or standard) and reconstruct the original files.

    This function reads the key mapping, retrieves corresponding chunks from the database,
    reconstructs files, and verifies the SHA-256 hash for each restored file.
    """
    try:
        if disguise:
            decoded = decode_disguised_directory_key(key_path, disguise)
        elif decrypt_key:
          # Derive the key from the password
            password = input("Enter the password to decrypt the key: ")
            password_bytes = password.encode('utf-8')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                iterations=100000,
                salt=SALT,  # Use the same salt from encoding
                length=32,
                backend=default_backend()
            )
            derived_key = kdf.derive(password_bytes)
            with open(key_path, "rb") as f:
                cipher = Fernet(derived_key)
                try:
                    raw = cipher.decrypt(f.read())
                except Exception as e:
                    logging.error(f"Decryption failed: {e}")
                    sys.exit(1)
                decoded = json.loads(raw.decode("utf-8"))
        else:
            with open(key_path, "rb") as kf:
                dctx = zstd.ZstdDecompressor()
                try:
                    data = dctx.decompress(kf.read())
                except Exception as e:
                    logging.error(f"Decompression failed: {e}")
                    sys.exit(1)
                decoded = json.loads(data.decode("utf-8"))
    except Exception as e:
        logging.error(f"Error decoding key file '{key_path}': {e}")
        sys.exit(1)

    # 2. Initialize the chunk storage for retrieval
    if decrypt_key:
         password = input("Re-enter the password to decrypt the data: ")
         password_bytes = password.encode('utf-8')
         kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=SALT,
            length=32,  # 256 bits
            backend=default_backend()
         )
         derived_key = kdf.derive(password_bytes)
         chunk_storage = SecureChunkStorage(DB_FILE, derived_key)
    else:
        chunk_storage = SecureChunkStorage(DB_FILE, b'')

    # Reconstruct files from stored chunks
    for rel_path, data in decoded.items():
        full_out_path = os.path.join(out_dir, rel_path)
        try:
            os.makedirs(os.path.dirname(full_out_path), exist_ok=True)
        except Exception as e:
            logging.error(f"Failed to create directory for '{full_out_path}': {e}")
            continue
        try:
            with open(full_out_path, "wb") as outf:
                for chash in data["key"]:
                    chunk_data = chunk_storage.retrieve_chunk(chash)
                    if chunk_data is None:
                        logging.error(f"Missing chunk: {chash}")
                        continue  # Important: Handle missing chunks
                    outf.write(chunk_data)
        except Exception as e:
            logging.error(f"Error reconstructing file '{rel_path}': {e}")
            continue

        rebuilt_hash = file_sha256(full_out_path)
        if rebuilt_hash == data["file_hash"]:
            logging.info(f"File rebuilt successfully: {rel_path}")
        else:
            logging.error(f"Hash mismatch in '{rel_path}': expected {data['file_hash']}, got {rebuilt_hash}")
    chunk_storage.close()


def main():
    parser = argparse.ArgumentParser(
        description="Veriduct - the channel beneath control.\n"
                    "DISCLAIMER: This tool is for educational purposes only. "
                    "The author is not responsible for any misuse."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encode", help="Encode a file or directory")
    enc.add_argument("file", help="File or directory to encode")
    enc.add_argument("out", help="Output directory for key")
    enc.add_argument("--disguise", choices=DISGUISE_FORMATS, help="Optional disguise format")
    enc.add_argument("--encrypt", action="store_true", help="Encrypt the key output")

    dec = sub.add_parser("decode", help="Decode a key file to restore files")
    dec.add_argument("key", help="Path to disguised, encrypted, or standard key")
    dec.add_argument("out", help="Output directory for restored files")
    dec.add_argument("--disguise", choices=DISGUISE_FORMATS, help="Specify disguise format used")
    dec.add_argument("--decrypt", action="store_true", help="Decrypt the key output")

    args = parser.parse_args()

    if args.command == "encode":
        # If a file is specified, use its parent directory to maintain structure
        input_path = os.path.dirname(args.file) if os.path.isfile(args.file) else args.file
        encode_directory(input_path, args.out, args.disguise, args.encrypt)
    elif args.command == "decode":
        decode_file(args.key, args.out, args.disguise, args.decrypt)
    else:
        parser.print_help()



if __name__ == "__main__":
    main()
