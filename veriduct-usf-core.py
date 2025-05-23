"""
Veriduct: A Data Framework for Semantic Annihilation and Chunking

DISCLAIMER: This tool is provided for educational and research purposes only.
It is intended for legal and ethical use. The author is not responsible for any misuse.
This tool implements the Universal Substrate Format (USF) principle of semantic
annihilation through structural destruction, *without using encryption*.

WARNING: The USF header randomization is an *irreversible* process on the stored chunks.
However, with the key, the *original* file header can be restored. Reassembly
recreates the USF-modified data stream, *then* restores the original header.
Without the key, the original file header is permanently lost in the chunk data.

WARNING: The SQLite database is *not* encrypted. While file headers are
obliterated in the chunks, the chunk data itself is stored raw. An attacker
with access to the database may be able to carve out data chunks,
though identifying their original file format or structure will be difficult
without the keymap and analysis tools.

Dependencies:
    - pysqlite3 (for SQLite)
    - zstandard
    - hmac # For optional tamper detection

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
import base64
import hmac

import sqlite3

CHUNK_SIZE = 4096
KEY_FILE = "veriduct_key.zst"
DB_FILE = "veriduct_chunks.db"
DISGUISE_FORMATS = ["csv", "log", "conf"]

DEFAULT_USF_WIPE_SIZE = 256
BATCH_FLUSH_THRESHOLD = 1000
FILE_SALT_SIZE = 16

KEYMAP_FORMAT_VERSION = 4


def calculate_salted_chunk_hash(salt: bytes, chunk_data: bytes) -> str:
    return hashlib.sha256(salt + chunk_data).hexdigest()

def calculate_stream_hash(data_stream_iterator):
    sha256_hash_obj = hashlib.sha256()
    for chunk in data_stream_iterator:
         sha256_hash_obj.update(chunk)
    return sha256_hash_obj.hexdigest()

def calculate_hmac(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def calculate_file_hash(filepath: str) -> str:
    sha256_hash_obj = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256_hash_obj.update(chunk)
        return sha256_hash_obj.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for '{filepath}': {e}")
        return None

def ensure_dirs(directory):
    try:
        os.makedirs(directory, exist_ok=True)
    except Exception as e:
        logging.error(f"Failed to create directory '{directory}': {e}")
        sys.exit(2)


class ChunkStorage:
    def __init__(self, db_path):
        self.db_path = db_path
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")

            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chunks (
                    hash TEXT PRIMARY KEY,
                    data BLOB
                )
                """
            )
            self.conn.execute("PRAGMA user_version = 1;")
            self.conn.commit()
            logging.debug(f"Database initialized at {db_path}")
        except sqlite3.Error as e:
            logging.error(f"Error initializing database '{self.db_path}': {e}")
            if hasattr(self, 'conn') and self.conn:
                self.conn.close()
            sys.exit(2)
        except Exception as e:
            logging.error(f"Unexpected error during database initialization: {e}")
            if hasattr(self, 'conn') and self.conn:
                self.conn.close()
            sys.exit(2)


    def store_chunks_batch(self, chunks_to_store):
        if not chunks_to_store:
            return
        try:
            with self.conn:
                 self.conn.executemany(
                     "INSERT OR REPLACE INTO chunks (hash, data) VALUES (?, ?)",
                     chunks_to_store,
                 )
            logging.debug(f"Flushed batch of {len(chunks_to_store)} chunks to DB.")
        except sqlite3.Error as e:
            logging.error(f"SQLite error storing chunk batch: {e}")
            raise


    def retrieve_chunk(self, salted_chunk_hash):
        try:
            cursor = self.conn.execute(
                "SELECT data FROM chunks WHERE hash = ?", (salted_chunk_hash,)
            )
            result = cursor.fetchone()
            if result:
                return result[0]
            else:
                return None
        except sqlite3.Error as e:
            logging.error(f"SQLite error retrieving chunk {salted_chunk_hash}: {e}")
            return None


    def close(self):
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
            logging.debug("Database connection closed.")


def disguise_key(key_data: dict, out_dir: str, style: str):
    ensure_dirs(out_dir)

    output_path = os.path.join(out_dir, f"veriduct_key.{style}")

    try:
        serializable_key_data = {"format_version": key_data.get('format_version', 'N/A')}
        for fname, data in key_data.items():
            if fname == 'format_version': continue
            serializable_key_data[fname] = {
                 "file_salt": base64.b64encode(data.get("file_salt", b"")).decode('ascii'),
                 "usf_hash": data.get("usf_hash", ""),
                 "mac": data.get("mac", ""),
                 "original_header": base64.b64encode(data.get("original_header", b"")).decode('ascii'),
                 "key": data.get("key", [])
            }


        if style == "csv":
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(f"# Veriduct Keymap Format Version: {serializable_key_data.get('format_version', 'N/A')}\n")
                f.write("filename,file_salt,usf_hash,mac,original_header,chunk_id,chunk_hash\n")
                for fname, data in serializable_key_data.items():
                    if fname == 'format_version': continue

                    file_salt_b64 = data["file_salt"]
                    usf_hash = data["usf_hash"]
                    mac = data["mac"]
                    original_header_b64 = data["original_header"]

                    for i, ch in enumerate(data["key"]):
                        if i == 0:
                             f.write(f"{fname},{file_salt_b64},{usf_hash},{mac},{original_header_b64},{i},{ch}\n")
                        else:
                             f.write(f"{fname},,,,,{i},{ch}\n")

        elif style == "log":
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(f"[{datetime.datetime.now().isoformat()}] [INFO] Veriduct Keymap Format Version: {serializable_key_data.get('format_version', 'N/A')}\n")
                for fname, data in serializable_key_data.items():
                    if fname == 'format_version': continue

                    file_salt_b64 = data["file_salt"]
                    usf_hash = data["usf_hash"]
                    mac = data["mac"]
                    original_header_b64 = data["original_header"]

                    f.write(f"[{datetime.datetime.now().isoformat()}] [INFO] FileMetadata: File={fname} Salt={file_salt_b64} USFHash={usf_hash} MAC={mac} OriginalHeader={original_header_b64}\n")

                    for i, ch in enumerate(data["key"]):
                        ts = datetime.datetime.now().isoformat()
                        fake_level = random.choice(["INFO", "DEBUG", "WARN"])
                        f.write(f"{ts} [{fake_level}] FileRef={fname} ChunkId={i} ChunkHash={ch}\n")

        elif style == "conf":
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(f"# Veriduct Keymap Format Version: {serializable_key_data.get('format_version', 'N/A')}\n")
                f.write("\n")
                for fname, data in serializable_key_data.items():
                    if fname == 'format_version': continue

                    file_salt_b64 = data["file_salt"]
                    usf_hash = data["usf_hash"]
                    mac = data["mac"]
                    original_header_b64 = data["original_header"]

                    f.write(f"[{fname}]\n")
                    f.write(f"file_salt = {file_salt_b64}\n")
                    f.write(f"usf_hash = {usf_hash}\n")
                    if mac:
                        f.write(f"mac = {mac}\n")
                    if original_header_b64:
                        f.write(f"original_header = {original_header_b64}\n")
                    for i, ch in enumerate(data["key"]):
                        f.write(f"chunk{i} = {ch}\n")
                    f.write("\n")
        else:
            raise ValueError(f"Unknown disguise style: {style}")
    except Exception as e:
        logging.error(f"Error writing disguised key to '{output_path}': {e}")
        sys.exit(2)

    logging.info(f"Disguised key written to: {output_path}")


def decode_disguised_key(key_path: str, style: str) -> dict:
    key_map = {"format_version": None}
    try:
        with open(key_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        logging.error(f"Error reading key file '{key_path}': {e}")
        sys.exit(2)

    try:
        for line in lines:
             line_strip = line.strip()
             if line_strip.startswith("# Veriduct Keymap Format Version:") or line_strip.startswith("[INFO] Veriduct Keymap Format Version:"):
                  try:
                       parts = line_strip.split(":", 1)
                       if len(parts) == 2:
                            key_map["format_version"] = int(parts[1].strip())
                  except ValueError:
                       logging.warning(f"Could not parse keymap format version from line: {line_strip}")

        file_buffer = {}

        if style == "csv":
            data_lines = [line for line in lines if not line.strip().startswith("#")]
            if not data_lines:
                 logging.error("CSV key file is empty or contains only comments/headers.")
                 sys.exit(2)

            for line in data_lines:
                parts = line.strip().split(",")
                if len(parts) != 7:
                    logging.debug(f"Skipping malformed CSV line: {line.strip()}")
                    continue
                fname, file_salt_b64, usf_hash, mac, original_header_b64, chunk_id_str, chunk_hash = parts

                if fname not in file_buffer:
                    file_buffer[fname] = {
                         "file_salt_b64": file_salt_b64 if file_salt_b64 else None,
                         "usf_hash": usf_hash if usf_hash else None,
                         "mac": mac if mac else None,
                         "original_header_b64": original_header_b64 if original_header_b64 else None,
                         "chunk_hashes_with_ids": []
                         }
                else:
                     if file_buffer[fname].get("file_salt_b64") is None: file_buffer[fname]["file_salt_b64"] = file_salt_b64 if file_salt_b64 else None
                     if file_buffer[fname].get("usf_hash") is None: file_buffer[fname]["usf_hash"] = usf_hash if usf_hash else None
                     if file_buffer[fname].get("mac") is None: file_buffer[fname]["mac"] = mac if mac else None
                     if file_buffer[fname].get("original_header_b64") is None: file_buffer[fname]["original_header_b64"] = original_header_b64 if original_header_b64 else None


                try:
                    chunk_id = int(chunk_id_str)
                    if chunk_hash:
                         file_buffer[fname]["chunk_hashes_with_ids"].append((chunk_id, chunk_hash))
                except ValueError:
                     logging.debug(f"Skipping CSV line with invalid chunk_id: {line.strip()}")
                     continue

        elif style == "log":
            for line in lines:
                line_strip = line.strip()
                if "FileMetadata: File=" in line_strip and "Salt=" in line_strip and "USFHash=" in line_strip:
                     parts = line_strip.split()
                     fname = None
                     file_salt_b64 = None
                     usf_hash = None
                     mac = None
                     original_header_b64 = None
                     for part in parts:
                         if part.startswith("File="):
                             fname = part.split("=", 1)[1]
                         elif part.startswith("Salt="):
                             file_salt_b64 = part.split("=", 1)[1]
                         elif part.startswith("USFHash="):
                             usf_hash = part.split("=", 1)[1]
                         elif part.startswith("MAC="):
                             mac = part.split("=", 1)[1]
                         elif part.startswith("OriginalHeader="):
                             original_header_b64 = part.split("=", 1)[1]

                     if fname:
                          file_buffer[fname] = {
                              "file_salt_b64": file_salt_b64 if file_salt_b64 != "N/A" else None,
                              "usf_hash": usf_hash if usf_hash != "N/A" else None,
                              "mac": mac if mac != "N/A" else None,
                              "original_header_b64": original_header_b64 if original_header_b64 != "N/A" else None,
                              "chunk_hashes_with_ids": []
                              }
                     else:
                          logging.debug(f"Skipping incomplete LOG metadata line: {line_strip}")

                elif "FileRef=" in line_strip and "ChunkId=" in line_strip and "ChunkHash=" in line_strip:
                    parts = line_strip.split()
                    fname = None
                    chunk_id = None
                    chunk_hash = None
                    for part in parts:
                         if part.startswith("FileRef="):
                              fname = part.split("=", 1)[1]
                         elif part.startswith("ChunkId="):
                              try:
                                   chunk_id = int(part.split("=", 1)[1])
                              except ValueError:
                                   logging.debug(f"Skipping LOG line with invalid ChunkId: {line_strip}")
                                   continue
                         elif part.startswith("ChunkHash="):
                              chunk_hash = part.split("=", 1)[1]

                    if fname and chunk_id is not None and chunk_hash:
                         file_buffer.setdefault(fname, {"file_salt_b64": None, "usf_hash": None, "mac": None, "original_header_b64": None, "chunk_hashes_with_ids": []})
                         file_buffer[fname]["chunk_hashes_with_ids"].append((chunk_id, chunk_hash))
                    else:
                         logging.debug(f"Skipping incomplete LOG chunk line: {line_strip}")

        elif style == "conf":
            current_file = None
            file_buffer_entry = None

            for line in lines:
                line_strip = line.strip()
                if not line_strip or line_strip.startswith("#"):
                    continue
                if line_strip.startswith("[") and line_strip.endswith("]"):
                    if current_file and file_buffer_entry:
                         file_buffer[current_file] = file_buffer_entry
                    current_file = line_strip[1:-1]
                    file_buffer_entry = {"file_salt_b64": None, "usf_hash": None, "mac": None, "original_header_b64": None, "chunk_hashes_with_ids": []}

                elif current_file and "=" in line_strip and file_buffer_entry is not None:
                     parts = line_strip.split("=", 1)
                     key = parts[0].strip()
                     value = parts[1].strip()
                     if key == "file_salt":
                          file_buffer_entry["file_salt_b64"] = value
                     elif key == "usf_hash":
                          file_buffer_entry["usf_hash"] = value
                     elif key == "mac":
                          file_buffer_entry["mac"] = value
                     elif key == "original_header":
                          file_buffer_entry["original_header_b64"] = value
                     elif key.startswith("chunk"):
                          try:
                              chunk_id = int(key[len("chunk"):])
                              if value:
                                   file_buffer_entry["chunk_hashes_with_ids"].append((chunk_id, value))
                          except ValueError:
                              logging.debug(f"Skipping CONF line with invalid chunk key: {line_strip}")
                              continue
                     else:
                          logging.debug(f"Skipping unknown CONF key: {line_strip}")

            if current_file and file_buffer_entry:
                 file_buffer[current_file] = file_buffer_entry

        else:
            raise ValueError(f"Unknown disguise style: {style}")

        for fname, data in list(file_buffer.items()):
            file_salt = None
            if data.get("file_salt_b64"):
                 try:
                      file_salt = base64.b64decode(data["file_salt_b64"])
                 except Exception as e:
                      logging.error(f"Failed to decode salt for file '{fname}': {e}")
                      del file_buffer[fname]
                      continue

            if file_salt is None:
                 logging.error(f"Missing file salt for '{fname}'. Cannot reassemble chunks.")
                 del file_buffer[fname]
                 continue

            original_header_bytes = None
            if data.get("original_header_b64"):
                 try:
                      original_header_bytes = base64.b64decode(data["original_header_b64"])
                 except Exception as e:
                      logging.error(f"Failed to decode original header for file '{fname}': {e}")
                      original_header_bytes = None

            chunk_hashes_with_ids = data.get("chunk_hashes_with_ids", [])
            sorted_chunk_hashes = [h for id, h in sorted(chunk_hashes_with_ids, key=lambda item: item[0])]

            if not sorted_chunk_hashes:
                 logging.warning(f"File '{fname}' has no chunk hashes in keymap. Skipping.")
                 del file_buffer[fname]
                 continue

            key_map[fname] = {
                 "file_salt": file_salt,
                 "usf_hash": data.get("usf_hash"),
                 "mac": data.get("mac"),
                 "original_header": original_header_bytes,
                 "key": sorted_chunk_hashes
                 }

    except Exception as e:
        logging.error(f"Error decoding key file content: {e}")
        sys.exit(2)

    loaded_version = key_map.get("format_version")
    if loaded_version is None:
         logging.warning("Keymap format version not found in key file. Assuming latest version for parsing.")

    elif loaded_version != KEYMAP_FORMAT_VERSION:
         logging.error(f"Keymap format version mismatch. Expected {KEYMAP_FORMAT_VERSION}, found {loaded_version}. "
                       "This key file might be incompatible with this version of Veriduct.")
         sys.exit(2)


    if "format_version" in key_map:
         del key_map["format_version"]


    if not key_map:
        logging.error("No valid file entries found in key file after decoding.")
        sys.exit(2)


    return key_map


def annihilate_path(input_path, out_dir, wipe_size, add_hmac=False, disguise=None, force_internal=False, verbose=False):
    input_path_abs = os.path.abspath(input_path)
    out_dir_abs = os.path.abspath(out_dir)

    out_dir_real_norm = os.path.normcase(os.path.realpath(out_dir_abs))

    input_path_real_norm = os.path.normcase(os.path.realpath(input_path_abs))
    if out_dir_real_norm.startswith(input_path_real_norm) and input_path_real_norm != out_dir_real_norm:
        if not force_internal:
            logging.error(
                f"Output directory '{out_dir_abs}' (resolved to '{out_dir_real_norm}') "
                f"is inside the input path '{input_path_abs}' (resolved to '{input_path_real_norm}'). "
                "This will cause the annihilator to process its own output. "
                "Use --force-internal to allow this (output directory will be skipped)."
            )
            return 1
        else:
            logging.warning(
                f"Output directory '{out_dir_abs}' (resolved to '{out_dir_real_norm}') "
                f"is inside the input path '{input_path_abs}' (resolved to '{input_path_real_norm}'). "
                "Using --force-internal flag, skipping the output directory during traversal."
            )


    ensure_dirs(out_dir_abs)
    key_map = {"format_version": KEYMAP_FORMAT_VERSION}
    db_path = os.path.join(out_dir_abs, DB_FILE)

    try:
        chunk_storage = ChunkStorage(db_path)
    except SystemExit as e:
        return e.code


    files_to_process = []
    input_base_path = input_path_abs

    is_single_file_input = os.path.isfile(input_path_abs)

    if is_single_file_input:
        files_to_process.append(input_path_abs)
        input_base_path = os.path.dirname(input_path_abs)
    elif os.path.isdir(input_path_abs):
         for root, dirs, files in os.walk(input_path_abs):
             root_real_norm = os.path.normcase(os.path.realpath(root))
             if out_dir_real_norm.startswith(root_real_norm):
                  dirs[:] = [d for d in dirs if os.path.normcase(os.path.realpath(os.path.join(root, d))) != out_dir_real_norm]

             for fname in files:
                 fpath_abs = os.path.abspath(os.path.join(root, fname))
                 fpath_real_norm = os.path.normcase(os.path.realpath(fpath_abs))
                 if fpath_real_norm.startswith(out_dir_real_norm):
                      logging.debug(f"Skipping file in output directory: {fpath_abs}")
                      continue
                 files_to_process.append(fpath_abs)
    else:
        logging.error(f"Input path is neither a file nor a directory: {input_path}")
        chunk_storage.close()
        return 1

    total_files = len(files_to_process)
    if total_files == 0:
         logging.warning(f"No files found to process in '{input_path}'.")
         chunk_storage.close()
         return 0


    processed_count = 0
    for fpath_abs in files_to_process:
        if is_single_file_input:
            rel_path = os.path.basename(fpath_abs)
        else:
            rel_path = os.path.relpath(fpath_abs, input_base_path)

        file_salt = os.urandom(FILE_SALT_SIZE)

        key_sequence = []
        chunks_to_store_batch = []
        usf_data_hasher = hashlib.sha256()
        original_file_header_bytes = b''

        logging.info(f"Annihilating file ({processed_count+1}/{total_files}): {rel_path}")
        try:
            with open(fpath_abs, "rb") as f:
                original_file_header_bytes = f.read(wipe_size)
                f.seek(0)

                bytes_processed = 0

                while True:
                    data = f.read(CHUNK_SIZE)
                    if not data:
                        break

                    current_data_block = bytearray(data)
                    actual_read_size = len(current_data_block)

                    wipe_amount_in_block = max(0, min(actual_read_size, wipe_size - bytes_processed))
                    if wipe_amount_in_block > 0:
                        current_data_block[:wipe_amount_in_block] = os.urandom(wipe_amount_in_block)

                    chunk_data = bytes(current_data_block)

                    chash = calculate_salted_chunk_hash(file_salt, chunk_data)

                    chunks_to_store_batch.append((chash, chunk_data))
                    key_sequence.append(chash)
                    usf_data_hasher.update(chunk_data)

                    if verbose:
                        logging.debug(f"  Processed chunk {len(key_sequence)-1} for '{rel_path}' (salted hash {chash[:8]}...)")

                    bytes_processed += actual_read_size

                    if len(chunks_to_store_batch) >= BATCH_FLUSH_THRESHOLD:
                        try:
                            chunk_storage.store_chunks_batch(chunks_to_store_batch)
                            chunks_to_store_batch = []
                        except Exception as db_e:
                            logging.error(f"Error flushing batch for file '{rel_path}': {db_e}")
                            raise

            if chunks_to_store_batch:
                 try:
                     chunk_storage.store_chunks_batch(chunks_to_store_batch)
                 except Exception as db_e:
                     logging.error(f"Error flushing final batch for file '{rel_path}': {db_e}")
                     raise


            usf_stream_hash = usf_data_hasher.hexdigest()
            mac_tag = ""
            if add_hmac:
                 try:
                      mac_tag = calculate_hmac(file_salt, usf_stream_hash.encode('utf-8'))
                      logging.debug(f"  Calculated HMAC for '{rel_path}': {mac_tag[:8]}...")
                 except Exception as mac_e:
                      logging.error(f"Error calculating HMAC for file '{rel_path}': {mac_e}")
                      mac_tag = ""


            key_map[rel_path] = {
                 "file_salt": file_salt,
                 "usf_hash": usf_stream_hash,
                 "mac": mac_tag,
                 "original_header": original_file_header_bytes,
                 "key": key_sequence
                 }
            processed_count += 1

        except Exception as e:
            logging.error(f"Error processing file '{rel_path}': {e}")
            continue


    chunk_storage.close()

    try:
        serializable_key_map = {"format_version": key_map.get("format_version", KEYMAP_FORMAT_VERSION)}
        for fname, data in key_map.items():
            if fname == 'format_version': continue
            serializable_key_map[fname] = {
                 "file_salt": base64.b64encode(data.get("file_salt", b"")).decode('ascii'),
                 "usf_hash": data.get("usf_hash", ""),
                 "mac": data.get("mac", ""),
                 "original_header": base64.b64encode(data.get("original_header", b"")).decode('ascii'),
                 "key": data.get("key", [])
            }

        if disguise:
            disguise_key(serializable_key_map, out_dir_abs, disguise)
        else:
            key_path = os.path.join(out_dir_abs, KEY_FILE)
            cctx = zstd.ZstdCompressor()
            compressed = cctx.compress(json.dumps(serializable_key_map).encode("utf-8"))
            with open(key_path, "wb") as kf:
                kf.write(compressed)
            logging.info(f"Annihilation complete ({processed_count} files processed successfully). Key written to '{key_path}' using database: '{db_path}'")
    except Exception as e:
        logging.error(f"Error during key output: {e}")
        return 1

    if processed_count < total_files:
         logging.warning(f"Annihilation completed with errors or skipped files: {processed_count}/{total_files} files processed successfully.")
         return 1
    else:
         return 0


def reassemble_path(key_path, out_dir, disguise=None, ignore_integrity=False, verbose=False):
    key_path_abs = os.path.abspath(key_path)
    out_dir_abs = os.path.abspath(out_dir)
    ensure_dirs(out_dir_abs)

    key_dir = os.path.dirname(key_path_abs)
    db_path = os.path.join(key_dir, DB_FILE)
    if not os.path.exists(db_path):
        logging.error(f"Database file not found next to key file: {db_path}")
        return 1

    logging.info(f"Using database file: {db_path}")

    try:
        if disguise:
            decoded_key_map = decode_disguised_key(key_path_abs, disguise)
        else:
            with open(key_path_abs, "rb") as kf:
                dctx = zstd.ZstdDecompressor()
                try:
                    data = dctx.decompress(kf.read())
                except Exception as e:
                    logging.error(f"Decompression failed: {e}")
                    return 1

                raw_key_map = json.loads(data.decode("utf-8"))

            loaded_version = raw_key_map.get("format_version")
            if loaded_version is None:
                 logging.warning("Keymap format version not found in standard key file. Assuming latest version for parsing.")
                 if KEYMAP_FORMAT_VERSION != 4:
                      logging.error(f"Keymap format version missing. This key file might be incompatible. Expected {KEYMAP_FORMAT_VERSION}.")
                      return 1

            elif loaded_version != KEYMAP_FORMAT_VERSION:
                 logging.error(f"Keymap format version mismatch. Expected {KEYMAP_FORMAT_VERSION}, found {loaded_version}. "
                               "This key file might be incompatible with this version of Veriduct.")
                 return 1

            decoded_key_map = {}
            for fname, data in raw_key_map.items():
                 if fname == 'format_version': continue
                 file_salt_b64 = data.get("file_salt")
                 file_salt = None
                 if file_salt_b64:
                      try:
                           file_salt = base64.b64decode(file_salt_b64)
                      except Exception as e:
                           logging.error(f"Failed to decode salt for file '{fname}' from keymap: {e}")
                           continue

                 if file_salt is None:
                      logging.error(f"File salt missing for '{fname}' in keymap. Cannot reassemble chunks.")
                      continue

                 original_header_b64 = data.get("original_header")
                 original_header_bytes = None
                 if original_header_b64:
                      try:
                           original_header_bytes = base64.b64decode(original_header_b64)
                      except Exception as e:
                           logging.warning(f"Failed to decode original header for file '{fname}' from keymap: {e}")
                           original_header_bytes = None


                 decoded_key_map[fname] = {
                      "file_salt": file_salt,
                      "usf_hash": data.get("usf_hash"),
                      "mac": data.get("mac"),
                      "original_header": original_header_bytes,
                      "key": data.get("key", [])
                 }


    except FileNotFoundError:
        logging.error(f"Key file not found: {key_path}")
        return 1
    except SystemExit as e:
         return e.code
    except Exception as e:
        logging.error(f"Error decoding key file '{key_path}': {e}")
        return 1


    try:
        chunk_storage = ChunkStorage(db_path)
    except SystemExit as e:
        return e.code

    reassembled_count = 0
    failed_count = 0
    total_files_in_keymap = len(decoded_key_map)

    if total_files_in_keymap == 0:
         logging.error("No valid file entries found in key file after decoding/parsing.")
         chunk_storage.close()
         return 1


    for rel_path, data in decoded_key_map.items():

        full_out_path = os.path.join(out_dir_abs, rel_path)
        logging.info(f"Reassembling USF file ({reassembled_count+failed_count+1}/{total_files_in_keymap}): {rel_path}")

        expected_usf_hash = data.get("usf_hash")
        file_salt = data.get("file_salt")
        expected_mac = data.get("mac")
        original_header_bytes = data.get("original_header")
        chunk_hashes_sequence = data.get("key", [])

        if file_salt is None:
             logging.error(f"Cannot reassemble '{rel_path}': File salt is missing.")
             failed_count += 1
             continue


        missing_chunks = False
        reconstruction_hasher = hashlib.sha256()

        output_file = None

        integrity_check_passed = True
        try:
            os.makedirs(os.path.dirname(full_out_path), exist_ok=True)
            output_file = open(full_out_path, "wb")

            chunk_index = 0
            for salted_chash in chunk_hashes_sequence:
                chunk_data = chunk_storage.retrieve_chunk(salted_chash)
                if chunk_data is None:
                    logging.error(f"Missing chunk: {salted_chash} for file '{rel_path}'. File reassembly incomplete.")
                    missing_chunks = True
                    integrity_check_passed = False
                    break

                reconstruction_hasher.update(chunk_data)

                output_file.write(chunk_data)

                if verbose:
                     logging.debug(f"  Retrieved and wrote chunk {chunk_index} for '{rel_path}' (salted hash {salted_chash[:8]}...)")
                chunk_index += 1

        except Exception as e:
             logging.error(f"Error during chunk retrieval or file writing for '{rel_path}': {e}")
             integrity_check_passed = False
        finally:
            if output_file:
                 output_file.close()


        if not missing_chunks:
            rebuilt_usf_hash = reconstruction_hasher.hexdigest()

            if expected_usf_hash is None:
                 logging.warning(f"Expected USF hash missing in key map for '{rel_path}'. Cannot verify integrity of reassembled USF data.")
                 if not ignore_integrity:
                     logging.error(f"Integrity verification skipped for '{rel_path}' due to missing hash. Treating as failure.")
                     integrity_check_passed = False
                 else:
                      integrity_check_passed = True
            elif rebuilt_usf_hash == expected_usf_hash:
                 logging.info(f"USF hash verification successful for reassembled file: {rel_path}")
                 if expected_mac:
                      try:
                          calculated_mac = calculate_hmac(file_salt, rebuilt_usf_hash.encode('utf-8'))
                          if hmac.compare_digest(calculated_mac, expected_mac):
                               logging.info(f"HMAC verification successful for reassembled file: {rel_path}")
                               integrity_check_passed = True
                          else:
                               logging.error(f"HMAC mismatch for reassembled file '{rel_path}'. Data or keymap may be tampered.")
                               integrity_check_passed = False
                      except Exception as mac_e:
                           logging.error(f"Error calculating/comparing HMAC for '{rel_path}': {mac_e}")
                           integrity_check_passed = False
                 else:
                      integrity_check_passed = True
            else:
                 logging.error(f"USF hash mismatch in reassembled file '{rel_path}': expected {expected_usf_hash}, got {rebuilt_usf_hash}. File may be corrupted.")
                 integrity_check_passed = False


        if not integrity_check_passed:
             failed_count += 1
             logging.error(f"File reassembly failed integrity check for '{rel_path}'.")
             if not ignore_integrity:
                  logging.error(f"Deleting potentially corrupted reassembled file: {full_out_path}")
                  if os.path.exists(full_out_path):
                      try:
                           os.remove(full_out_path)
                           logging.debug(f"Removed potentially corrupted file: {full_out_path}")
                      except Exception as cleanup_e:
                           logging.error(f"Error removing potentially corrupted file '{full_out_path}': {cleanup_e}")
             else:
                  logging.warning(f"Ignoring integrity failure for '{rel_path}' (--ignore-integrity). Output file {full_out_path} may be corrupted.")

             continue

        if original_header_bytes:
             try:
                  with open(full_out_path, "rb+") as outf_patch:
                       outf_patch.write(original_header_bytes)
                  logging.info(f"Original header restored for file: {rel_path}")
             except Exception as header_e:
                  logging.error(f"Error restoring original header for '{rel_path}': {header_e}. "
                                "File may be present but still semantically annihilated.")
        else:
             logging.debug(f"No original header found in keymap for '{rel_path}', skipping restoration.")


        reassembled_count += 1


    chunk_storage.close()
    logging.info(f"Reassembly complete: {reassembled_count} files reassembled successfully, {failed_count} files failed integrity checks or had errors.")

    if failed_count > 0:
         return 2
    elif reassembled_count == 0 and total_files_in_keymap > 0:
         logging.error("No files were successfully reassembled.")
         return 1
    else:
         return 0


def main():
    parser = argparse.ArgumentParser(
        description="Veriduct - the channel beneath control.\n"
                    "Implements Universal Substrate Format (USF) via structural destruction.\n"
                    "WARNING: This process is irreversible on stored chunks. Reassembly recovers the USF data,\n"
                    "         then restores the original header if captured in the key. \n"
                    "         WITHOUT THE KEY, the original file header is permanently lost in the chunk data.\n"
                    "DISCLAIMER: This tool is for educational purposes only. "
                    "The author is not responsible for any misuse."
    )
    sub = parser.add_subparsers(dest="command", required=True, help="Available commands")

    annihilate_parser = sub.add_parser(
        "annihilate",
        help="Annihilate semantics of a file or directory using USF and store chunks"
    )
    annihilate_parser.add_argument("input_path", help="File or directory to annihilate")
    annihilate_parser.add_argument("out_dir", help="Output directory for key and database")
    annihilate_parser.add_argument(
        "--wipe-bytes",
        type=int,
        default=DEFAULT_USF_WIPE_SIZE,
        help=f"Number of bytes to randomize at the start of each file (and store as original header) (default: {DEFAULT_USF_WIPE_SIZE})"
    )
    annihilate_parser.add_argument(
        "--add-hmac",
        action="store_true",
        help="Calculate and store HMAC-SHA256 for each file's USF data using the file salt."
             "Provides tamper detection for reassembly, but NOT confidentiality."
    )
    annihilate_parser.add_argument(
        "--disguise",
        choices=DISGUISE_FORMATS,
        help="Optional disguise format for the key file"
    )
    annihilate_parser.add_argument(
        "--force-internal",
        action="store_true",
        help="Allow output directory to be inside the input directory (output dir will be skipped)"
    )
    annihilate_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging (e.g., per chunk)"
    )


    reassemble_parser = sub.add_parser(
        "reassemble",
        help="Reassemble USF files from a key file"
    )
    reassemble_parser.add_argument("key_path", help="Path to disguised or standard key file")
    reassemble_parser.add_argument("out_dir", help="Output directory for reassembled files")
    reassemble_parser.add_argument(
        "--disguise",
        choices=DISGUISE_FORMATS,
        help="Specify disguise format used for the key file"
    )
    reassemble_parser.add_argument(
        "--ignore-integrity",
        action="store_true",
        help="Attempt to reassemble even if integrity checks (hash/HMAC mismatch, missing chunks) fail."
             "Note: This will likely result in corrupted output files."
    )
    reassemble_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging (e.g., per chunk)"
    )

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    if args.command == "annihilate":
        if not os.path.exists(args.input_path):
            logging.error(f"Input path does not exist: {args.input_path}")
            sys.exit(1)
        if args.wipe_bytes < 0:
             logging.error("--wipe-bytes must be a non-negative integer.")
             sys.exit(1)

        exit_code = annihilate_path(args.input_path, args.out_dir, args.wipe_bytes, args.add_hmac, args.disguise, args.force_internal, args.verbose)
        sys.exit(exit_code)


    elif args.command == "reassemble":
        if not os.path.exists(args.key_path):
             logging.error(f"Key file not found: {args.key_path}")
             sys.exit(1)

        exit_code = reassemble_path(args.key_path, args.out_dir, args.disguise, args.ignore_integrity, args.verbose)
        sys.exit(exit_code)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

