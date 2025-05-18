"""
Veriduct: A Data Framework for Semantic Annihilation and Chunking

DISCLAIMER: This tool is provided for educational and research purposes only.
It is intended for legal and ethical use. The author is not responsible for any misuse.
This tool implements the Universal Substrate Format (USF) principle of semantic
annihilation through structural destruction, *without using encryption*.

WARNING: The USF header randomization is an *irreversible* process. Reassembly
recreates the USF-modified data stream, *not* the original file bytes. The
original file header is permanently lost. Do not use this tool on data you
cannot afford to lose unless you fully understand the process.

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

# Logging is configured in main based on verbose flag

CHUNK_SIZE = 4096
# Key file is always unencrypted Zstd or disguised
KEY_FILE = "veriduct_key.zst"
DB_FILE = "veriduct_chunks.db"  # SQLite database file name
DISGUISE_FORMATS = ["csv", "log", "conf"]

# USF Configuration
# Number of bytes to wipe/randomize at the start. Default, can be overridden by CLI.
DEFAULT_USF_WIPE_SIZE = 256
# Threshold for flushing the chunk batch to the database during annihilation
BATCH_FLUSH_THRESHOLD = 1000
# Size of the per-file salt for chunk hashing and HMAC
FILE_SALT_SIZE = 16 # 128 bits recommended

# Keymap Format Version - Increment when the keymap structure changes significantly
KEYMAP_FORMAT_VERSION = 3
# Format Version 1: Initial JSON structure, no salt, file_hash of original file (removed)
# Format Version 2: JSON structure includes "format_version", "file_salt", "usf_hash" (hash of USF stream), "key" (salted chunk hashes)
# Format Version 3: Added optional "mac" (HMAC) field


def calculate_salted_chunk_hash(salt: bytes, chunk_data: bytes) -> str:
    """Return SHA-256 hash of salt concatenated with chunk data."""
    return hashlib.sha256(salt + chunk_data).hexdigest()

def calculate_stream_hash(data_stream_iterator):
    """Calculate the SHA-256 hash of a data stream from an iterator of bytes objects."""
    sha256_hash_obj = hashlib.sha256()
    for chunk in data_stream_iterator:
         sha256_hash_obj.update(chunk)
    return sha256_hash_obj.hexdigest()

def calculate_hmac(key: bytes, message: bytes) -> str:
    """Calculate HMAC-SHA256."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def calculate_file_hash(filepath: str) -> str:
    """Calculate the SHA-256 hash of a file by reading it in chunks."""
    # Note: This function is mainly for comparison/verification of original files
    # if that feature were added back or for initial logging, not part of the
    # core USF process which hashes the *modified* stream.
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
    """Ensure the specified directory exists."""
    try:
        os.makedirs(directory, exist_ok=True)
    except Exception as e:
        logging.error(f"Failed to create directory '{directory}': {e}")
        sys.exit(2) # Use a non-zero exit code for critical setup errors


class ChunkStorage:
    """
    Handles storage and retrieval of data chunks in a standard SQLite database.
    Note: This implementation uses standard sqlite3 and does NOT provide database encryption.
    Data integrity is based on chunk hashing, not confidentiality in storage.
    Chunk hashes stored are salted to prevent cross-file/cross-collection correlation.
    """
    def __init__(self, db_path):
        """
        Initialize the ChunkStorage with the database path.

        Args:
            db_path (str): Path to the SQLite database file.
        """
        self.db_path = db_path
        try:
            self.conn = sqlite3.connect(self.db_path)
            # Improve performance with WAL mode and less strict synchronous mode
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;") # Or OFF, but NORMAL is safer on crashes

            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chunks (
                    hash TEXT PRIMARY KEY, -- This hash is salted per file
                    data BLOB
                )
                """
            )
            # Add a schema version for future potential upgrades
            # Note: This version applies to the DB schema, not the keymap format.
            self.conn.execute("PRAGMA user_version = 1;")
            self.conn.commit()
            logging.debug(f"Database initialized at {db_path}")
        except sqlite3.Error as e:
            logging.error(f"Error initializing database '{self.db_path}': {e}")
            if hasattr(self, 'conn') and self.conn:
                self.conn.close()
            sys.exit(2) # Use a non-zero exit code for errors
        except Exception as e:
            logging.error(f"Unexpected error during database initialization: {e}")
            if hasattr(self, 'conn') and self.conn:
                self.conn.close()
            sys.exit(2) # Use a non-zero exit code for errors


    def store_chunks_batch(self, chunks_to_store):
        """
        Store a batch of chunks in the database using executemany.

        Args:
            chunks_to_store (list): A list of tuples, where each tuple is
                                    (salted_chunk_hash, chunk_data).
        """
        if not chunks_to_store:
            return
        try:
            # Use a transaction for the batch insert
            # The 'with self.conn:' context manager handles BEGIN, COMMIT, ROLLBACK
            with self.conn:
                 self.conn.executemany(
                     "INSERT OR REPLACE INTO chunks (hash, data) VALUES (?, ?)",
                     chunks_to_store,
                 )
            logging.debug(f"Flushed batch of {len(chunks_to_store)} chunks to DB.")
        except sqlite3.Error as e:
            logging.error(f"SQLite error storing chunk batch: {e}")
            # The 'with self.conn:' context automatically rolls back on exception
            raise # Re-raise the exception after logging


    def retrieve_chunk(self, salted_chunk_hash):
        """
        Retrieve a chunk of data from the database using its salted hash.

        Args:
            salted_chunk_hash (str): The SHA-256 hash (salted) of the chunk to retrieve.

        Returns:
            bytes: The chunk data, or None if the chunk is not found.
        """
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
            return None # Return None to indicate retrieval failure


    def close(self):
        """Close the database connection."""
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
            logging.debug("Database connection closed.")


def disguise_key(key_data: dict, out_dir: str, style: str):
    """Disguise key data in a specified format and write to output file."""
    # key_data now includes 'format_version', filenames as keys.
    # Each file entry includes 'file_salt' (bytes), 'usf_hash' (str),
    # optional 'mac' (str), and 'key' (list of salted hashes).
    ensure_dirs(out_dir)

    output_path = os.path.join(out_dir, f"veriduct_key.{style}")

    try:
        # Ensure salt is base64 encoded for serialization
        serializable_key_data = {"format_version": key_data.get('format_version', 'N/A')}
        for fname, data in key_data.items():
            if fname == 'format_version': continue
            serializable_key_data[fname] = {
                 "file_salt": base64.b64encode(data.get("file_salt", b"")).decode('ascii'),
                 "usf_hash": data.get("usf_hash", ""),
                 "mac": data.get("mac", ""), # Include optional MAC
                 "key": data.get("key", [])
            }


        if style == "csv":
            with open(output_path, "w", encoding="utf-8") as f:
                # Add version, salt, usf_hash, and mac headers
                f.write(f"# Veriduct Keymap Format Version: {serializable_key_data.get('format_version', 'N/A')}\n")
                f.write("filename,file_salt,usf_hash,mac,chunk_id,chunk_hash\n") # Added mac column
                for fname, data in serializable_key_data.items():
                    if fname == 'format_version': continue

                    file_salt_b64 = data["file_salt"]
                    usf_hash = data["usf_hash"]
                    mac = data["mac"]

                    for i, ch in enumerate(data["key"]):
                        # Include salt, usf_hash, and mac on the first row for each file
                        if i == 0:
                             f.write(f"{fname},{file_salt_b64},{usf_hash},{mac},{i},{ch}\n")
                        else:
                             # Leave metadata columns empty for subsequent chunks
                             f.write(f"{fname},,,,{i},{ch}\n")

        elif style == "log":
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(f"[{datetime.datetime.now().isoformat()}] [INFO] Veriduct Keymap Format Version: {serializable_key_data.get('format_version', 'N/A')}\n")
                for fname, data in serializable_key_data.items():
                    if fname == 'format_version': continue

                    file_salt_b64 = data["file_salt"]
                    usf_hash = data["usf_hash"]
                    mac = data["mac"]

                    # Add specific log entries for file metadata, including MAC
                    f.write(f"[{datetime.datetime.now().isoformat()}] [INFO] FileMetadata: File={fname} Salt={file_salt_b64} USFHash={usf_hash} MAC={mac}\n")

                    for i, ch in enumerate(data["key"]):
                        ts = datetime.datetime.now().isoformat()
                        fake_level = random.choice(["INFO", "DEBUG", "WARN"])
                        # Include index for deterministic order
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

                    f.write(f"[{fname}]\n")
                    # Add salt, usf_hash, and mac entries under the section
                    f.write(f"file_salt = {file_salt_b64}\n")
                    f.write(f"usf_hash = {usf_hash}\n")
                    if mac: # Only write MAC if present
                        f.write(f"mac = {mac}\n")
                    for i, ch in enumerate(data["key"]):
                        f.write(f"chunk{i} = {ch}\n")
                    f.write("\n") # Add newline between files
        else:
            raise ValueError(f"Unknown disguise style: {style}")
    except Exception as e:
        logging.error(f"Error writing disguised key to '{output_path}': {e}")
        sys.exit(2) # Use a non-zero exit code

    logging.info(f"Disguised key written to: {output_path}")


def decode_disguised_key(key_path: str, style: str) -> dict:
    """Decode a disguised key file and return the key mapping."""
    key_map = {"format_version": None} # Initialize with version placeholder
    try:
        with open(key_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        logging.error(f"Error reading key file '{key_path}': {e}")
        sys.exit(2)

    try:
        # Attempt to parse format version first
        for line in lines:
             line_strip = line.strip()
             if line_strip.startswith("# Veriduct Keymap Format Version:") or line_strip.startswith("[INFO] Veriduct Keymap Format Version:"):
                  try:
                       parts = line_strip.split(":", 1)
                       if len(parts) == 2:
                            key_map["format_version"] = int(parts[1].strip())
                            # Continue searching in case metadata lines are out of order
                  except ValueError:
                       logging.warning(f"Could not parse keymap format version from line: {line_strip}")
                       # Continue parsing the rest, version might be missing or malformed

        # Now parse the actual key data based on style
        # Use a buffer to collect metadata and chunk hashes for each file
        file_buffer = {} # {fname: {"file_salt_b64": ..., "usf_hash": ..., "mac": ..., "chunk_hashes_with_ids": [(id, hash), ...]}}

        if style == "csv":
            # Skip header lines including the version and column names
            data_lines = [line for line in lines if not line.strip().startswith("#")]
            if not data_lines:
                 logging.error("CSV key file is empty or contains only comments/headers.")
                 sys.exit(2)

            for line in data_lines:
                parts = line.strip().split(",")
                if len(parts) != 6: # Expect 6 columns now: filename, salt_b64, usf_hash, mac, chunk_id, chunk_hash
                    logging.debug(f"Skipping malformed CSV line: {line.strip()}")
                    continue
                fname, file_salt_b64, usf_hash, mac, chunk_id_str, chunk_hash = parts

                if fname not in file_buffer:
                    file_buffer[fname] = {
                         "file_salt_b64": file_salt_b64 if file_salt_b64 else None,
                         "usf_hash": usf_hash if usf_hash else None,
                         "mac": mac if mac else None,
                         "chunk_hashes_with_ids": [] # Collect (id, hash) tuples
                         }
                else: # Update buffer with metadata if found on subsequent lines (defensive)
                     if file_buffer[fname].get("file_salt_b64") is None: file_buffer[fname]["file_salt_b64"] = file_salt_b64 if file_salt_b64 else None
                     if file_buffer[fname].get("usf_hash") is None: file_buffer[fname]["usf_hash"] = usf_hash if usf_hash else None
                     if file_buffer[fname].get("mac") is None: file_buffer[fname]["mac"] = mac if mac else None


                # Collect chunk hash and index
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
                     # Parse file metadata line, including MAC
                     parts = line_strip.split()
                     fname = None
                     file_salt_b64 = None
                     usf_hash = None
                     mac = None # Initialize mac
                     for part in parts:
                         if part.startswith("File="):
                             fname = part.split("=", 1)[1]
                         elif part.startswith("Salt="):
                             file_salt_b64 = part.split("=", 1)[1]
                         elif part.startswith("USFHash="):
                             usf_hash = part.split("=", 1)[1]
                         elif part.startswith("MAC="): # Parse MAC
                             mac = part.split("=", 1)[1]


                     if fname:
                          file_buffer[fname] = {
                              "file_salt_b64": file_salt_b64 if file_salt_b64 != "N/A" else None,
                              "usf_hash": usf_hash if usf_hash != "N/A" else None,
                              "mac": mac if mac != "N/A" else None, # Store MAC
                              "chunk_hashes_with_ids": []
                              }
                     else:
                          logging.debug(f"Skipping incomplete LOG metadata line: {line_strip}")

                elif "FileRef=" in line_strip and "ChunkId=" in line_strip and "ChunkHash=" in line_strip:
                    # Parse chunk line
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
                         file_buffer.setdefault(fname, {"file_salt_b64": None, "usf_hash": None, "mac": None, "chunk_hashes_with_ids": []}) # Ensure buffer entry exists
                         file_buffer[fname]["chunk_hashes_with_ids"].append((chunk_id, chunk_hash))
                    else:
                         logging.debug(f"Skipping incomplete LOG chunk line: {line_strip}")

        elif style == "conf":
            current_file = None
            file_buffer_entry = None # Buffer for the current file's data

            for line in lines:
                line_strip = line.strip()
                if not line_strip or line_strip.startswith("#"): # Skip empty lines and comments
                    continue
                if line_strip.startswith("[") and line_strip.endswith("]"):
                    # Start of a new file section
                    if current_file and file_buffer_entry:
                         # Store data for the previous file from the buffer entry
                         file_buffer[current_file] = file_buffer_entry
                    current_file = line_strip[1:-1]
                    file_buffer_entry = {"file_salt_b64": None, "usf_hash": None, "mac": None, "chunk_hashes_with_ids": []} # Init buffer for new file

                elif current_file and "=" in line_strip and file_buffer_entry is not None:
                     parts = line_strip.split("=", 1) # Split only on the first '='
                     key = parts[0].strip()
                     value = parts[1].strip()
                     if key == "file_salt":
                          file_buffer_entry["file_salt_b64"] = value
                     elif key == "usf_hash":
                          file_buffer_entry["usf_hash"] = value
                     elif key == "mac": # Parse MAC
                          file_buffer_entry["mac"] = value
                     elif key.startswith("chunk"):
                          try:
                              chunk_id = int(key[len("chunk"):]) # Extract index after "chunk"
                              if value:
                                   file_buffer_entry["chunk_hashes_with_ids"].append((chunk_id, value))
                          except ValueError:
                              logging.debug(f"Skipping CONF line with invalid chunk key: {line_strip}")
                              continue
                     else:
                          logging.debug(f"Skipping unknown CONF key: {line_strip}")

            # Store the last file's data from the buffer
            if current_file and file_buffer_entry:
                 file_buffer[current_file] = file_buffer_entry

        else:
            # Should not be reached
            raise ValueError(f"Unknown disguise style: {style}")

        # Process buffered data for each file: decode salt, sort chunks by ID, check for missing salt
        for fname, data in list(file_buffer.items()): # Iterate over a copy
            file_salt = None
            if data.get("file_salt_b64"):
                 try:
                      file_salt = base64.b64decode(data["file_salt_b64"])
                 except Exception as e:
                      logging.error(f"Failed to decode salt for file '{fname}': {e}")
                      # Critical error as chunks are salted - remove this file entry
                      del file_buffer[fname]
                      continue # Move to next file

            if file_salt is None:
                 logging.error(f"Missing file salt for '{fname}'. Cannot reassemble chunks.")
                 del file_buffer[fname] # Remove entry if salt is missing
                 continue # Move to next file

            # Sort chunk hashes by ID
            chunk_hashes_with_ids = data.get("chunk_hashes_with_ids", [])
            sorted_chunk_hashes = [h for id, h in sorted(chunk_hashes_with_ids, key=lambda item: item[0])]

            if not sorted_chunk_hashes:
                 logging.warning(f"File '{fname}' has no chunk hashes in keymap. Skipping.")
                 del file_buffer[fname]
                 continue

            # Add processed data to the main keymap dictionary
            key_map[fname] = {
                 "file_salt": file_salt, # Store decoded salt bytes
                 "usf_hash": data.get("usf_hash"),
                 "mac": data.get("mac"), # Store MAC string
                 "key": sorted_chunk_hashes # Store sorted list of chunk hashes
                 }

    except Exception as e:
        logging.error(f"Error decoding key file content: {e}")
        sys.exit(2) # Use a non-zero exit code

    # Check keymap format version
    loaded_version = key_map.get("format_version")
    if loaded_version is None:
         logging.warning("Keymap format version not found in key file. Assuming latest version.")
         # Decide if missing version is a failure. For safety, require it or warn heavily.
         # Let's allow missing but assume latest, which might fail on salted hashes etc.
         # A stricter approach would be sys.exit(2) unless ignore_version is set.
         pass # Continue assuming latest format

    elif loaded_version != KEYMAP_FORMAT_VERSION:
         logging.error(f"Keymap format version mismatch. Expected {KEYMAP_FORMAT_VERSION}, found {loaded_version}. "
                       "This key file might be incompatible with this version of Veriduct.")
         sys.exit(2) # Exit on version mismatch


    # Remove the format_version key itself before returning the keymap
    if "format_version" in key_map:
         del key_map["format_version"]


    if not key_map:
        logging.error("No valid file entries found in key file after decoding.")
        sys.exit(2)


    return key_map


def annihilate_path(input_path, out_dir, wipe_size, add_hmac=False, disguise=None, force_internal=False, verbose=False):
    """
    Annihilate the semantics of a file or directory using USF, chunk the data,
    and generate a key mapping.

    This function walks through the specified path (file or directory), applies
    the Universal Substrate Format (USF) header nullification to each file,
    breaks the modified data into chunks, stores them in a database, and
    outputs a non-encrypted, optionally disguised, key mapping.
    The hash stored in the keymap is the hash of the *USF-modified* data stream.
    The original file header is permanently lost.
    Chunk hashes are salted per file to prevent cross-collection correlation.
    Optionally calculates an HMAC over the USF hash using the file salt for tamper detection.
    """
    input_path_abs = os.path.abspath(input_path)
    out_dir_abs = os.path.abspath(out_dir)

    # Use realpath and normcase for robust path comparison on case-insensitive file systems
    out_dir_real_norm = os.path.normcase(os.path.realpath(out_dir_abs))

    # Check if output directory is inside the input path
    input_path_real_norm = os.path.normcase(os.path.realpath(input_path_abs))
    if out_dir_real_norm.startswith(input_path_real_norm) and input_path_real_norm != out_dir_real_norm:
        if not force_internal:
            logging.error(
                f"Output directory '{out_dir_abs}' (resolved to '{out_dir_real_norm}') "
                f"is inside the input path '{input_path_abs}' (resolved to '{input_path_real_norm}'). "
                "This will cause the annihilator to process its own output. "
                "Use --force-internal to allow this (output directory will be skipped)."
            )
            return 1 # Use return code
        else:
            logging.warning(
                f"Output directory '{out_dir_abs}' (resolved to '{out_dir_real_norm}') "
                f"is inside the input path '{input_path_abs}' (resolved to '{input_path_real_norm}'). "
                "Using --force-internal flag, skipping the output directory during traversal."
            )


    ensure_dirs(out_dir_abs) # Ensure the output directory exists.
    key_map = {"format_version": KEYMAP_FORMAT_VERSION} # Add format version to keymap
    db_path = os.path.join(out_dir_abs, DB_FILE) # Place DB in output directory

    # Create and initialize the chunk storage (standard, non-encrypted SQLite)
    try:
        chunk_storage = ChunkStorage(db_path)
    except SystemExit as e:
        # Catch the sys.exit from ChunkStorage init error
        return e.code


    # Determine the list of files to process and the base path for relative names
    files_to_process = []
    input_base_path = input_path_abs # Default base path

    is_single_file_input = os.path.isfile(input_path_abs) # Flag for single file input

    if is_single_file_input:
        files_to_process.append(input_path_abs)
        # If a single file, the base path for relative names is its parent directory
        input_base_path = os.path.dirname(input_path_abs)
    elif os.path.isdir(input_path_abs):
         # Use os.walk for directories, respecting the --force-internal flag
         for root, dirs, files in os.walk(input_path_abs):
             # Skip the output directory if it's within the input path using realpath and normcase
             root_real_norm = os.path.normcase(os.path.realpath(root))
             if out_dir_real_norm.startswith(root_real_norm):
                  # If the output directory is a subdirectory of the current root, remove it
                  # from the list of directories to visit using realpath+normcase for robustness.
                  dirs[:] = [d for d in dirs if os.path.normcase(os.path.realpath(os.path.join(root, d))) != out_dir_real_norm]

             for fname in files:
                 fpath_abs = os.path.abspath(os.path.join(root, fname))
                 # Skip files within the output directory itself using realpath+normcase
                 fpath_real_norm = os.path.normcase(os.path.realpath(fpath_abs))
                 if fpath_real_norm.startswith(out_dir_real_norm):
                      logging.debug(f"Skipping file in output directory: {fpath_abs}")
                      continue
                 files_to_process.append(fpath_abs)
    else:
        logging.error(f"Input path is neither a file nor a directory: {input_path}")
        chunk_storage.close()
        return 1 # Use return code for error

    total_files = len(files_to_process)
    if total_files == 0:
         logging.warning(f"No files found to process in '{input_path}'.")
         chunk_storage.close()
         return 0


    # Process each file
    processed_count = 0
    for fpath_abs in files_to_process:
        # Determine the relative path for the keymap
        if is_single_file_input:
            rel_path = os.path.basename(fpath_abs) # Key is just the filename
        else:
            rel_path = os.path.relpath(fpath_abs, input_base_path) # Key is path relative to base dir

        # Generate a unique salt for this file
        file_salt = os.urandom(FILE_SALT_SIZE)

        key_sequence = []
        chunks_to_store_batch = [] # Collect chunks for batch insert
        usf_data_hasher = hashlib.sha256() # Hasher for the USF-modified data stream

        logging.info(f"Annihilating file ({processed_count+1}/{total_files}): {rel_path}")
        try:
            with open(fpath_abs, "rb") as f:
                bytes_processed = 0

                while True:
                    # Read a standard chunk size block
                    data = f.read(CHUNK_SIZE)
                    if not data: # End of file
                        break

                    current_data_block = bytearray(data)
                    actual_read_size = len(current_data_block)

                    # Apply randomization if this block overlaps with the wipe region
                    # Calculate how much of this block needs wiping
                    wipe_amount_in_block = max(0, min(actual_read_size, wipe_size - bytes_processed))
                    if wipe_amount_in_block > 0:
                        current_data_block[:wipe_amount_in_block] = os.urandom(wipe_amount_in_block)

                    chunk_data = bytes(current_data_block)

                    # Calculate the salted hash for this chunk
                    chash = calculate_salted_chunk_hash(file_salt, chunk_data)

                    # Add to batch list, key sequence, update USF hash
                    chunks_to_store_batch.append((chash, chunk_data))
                    key_sequence.append(chash)
                    usf_data_hasher.update(chunk_data) # USF hash is hash of the modified stream data

                    if verbose:
                        logging.debug(f"  Processed chunk {len(key_sequence)-1} for '{rel_path}' (salted hash {chash[:8]}...)")

                    bytes_processed += actual_read_size # Track total bytes processed

                    # Flush batch if threshold is reached
                    if len(chunks_to_store_batch) >= BATCH_FLUSH_THRESHOLD:
                        try:
                            chunk_storage.store_chunks_batch(chunks_to_store_batch)
                            chunks_to_store_batch = [] # Clear batch after flush
                        except Exception as db_e:
                            logging.error(f"Error flushing batch for file '{rel_path}': {db_e}")
                            raise db_e # Re-raise to be caught by the file-level except block

            # Store any remaining chunks in the batch for this file
            if chunks_to_store_batch:
                 try:
                     chunk_storage.store_chunks_batch(chunks_to_store_batch)
                     # chunks_to_store_batch = [] # Not needed after final flush
                 except Exception as db_e:
                     logging.error(f"Error flushing final batch for file '{rel_path}': {db_e}")
                     raise db_e


            # Calculate the hash of the USF-modified data stream
            usf_stream_hash = usf_data_hasher.hexdigest()
            mac_tag = ""
            # Calculate HMAC if requested
            if add_hmac:
                 try:
                      mac_tag = calculate_hmac(file_salt, usf_stream_hash.encode('utf-8'))
                      logging.debug(f"  Calculated HMAC for '{rel_path}': {mac_tag[:8]}...")
                 except Exception as mac_e:
                      logging.error(f"Error calculating HMAC for file '{rel_path}': {mac_e}")
                      # Non-fatal error, but warn that MAC is missing
                      mac_tag = "" # Ensure MAC is empty if calculation failed


            # Store the hash of the USF-modified data stream, the salt, the sequence of salted chunk hashes, and optional MAC
            key_map[rel_path] = {
                 "file_salt": file_salt, # Store salt bytes
                 "usf_hash": usf_stream_hash, # Store hash of the USF data stream
                 "mac": mac_tag, # Store optional MAC tag (hex string)
                 "key": key_sequence # Store sequence of salted chunk hashes
                 }
            processed_count += 1 # Increment count only on successful file processing

        except Exception as e:
            logging.error(f"Error processing file '{rel_path}': {e}")
            # The file processing failed. Decide if this is a fatal error or skip file.
            # For now, just log and continue to the next file. The key_map won't have this file.
            continue # Move to the next file if an error occurs


    # Close the chunk storage
    chunk_storage.close()

    # Output the key data (unencrypted, Zstd or disguised)
    try:
        # Note: Keymap JSON structure includes "format_version", filenames as keys,
        # each file entry includes "file_salt" (bytes), "usf_hash" (str),
        # optional "mac" (str), and "key" (list of salted hashes).
        # Convert salt bytes to base64 string *before* JSON dumping/disguising
        serializable_key_map = {"format_version": key_map.get("format_version", KEYMAP_FORMAT_VERSION)}
        for fname, data in key_map.items():
            if fname == 'format_version': continue
            serializable_key_map[fname] = {
                 "file_salt": base64.b64encode(data.get("file_salt", b"")).decode('ascii'),
                 "usf_hash": data.get("usf_hash", ""),
                 "mac": data.get("mac", ""),
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
        return 1 # Use return code for error

    # Check if all files were processed successfully
    if processed_count < total_files:
         logging.warning(f"Annihilation completed with errors or skipped files: {processed_count}/{total_files} files processed successfully.")
         return 1 # Indicate partial failure
    else:
         return 0 # Indicate success


def reassemble_path(key_path, out_dir, disguise=None, ignore_integrity=False, verbose=False):
    """
    Reassemble the USF files from a key file (disguised or standard Zstd).

    This function reads the key mapping, retrieves corresponding chunks from the database,
    reconstructs the USF-modified files, and verifies the SHA-256 hash of the
    reconstructed USF data stream against the hash stored during annihilation.
    Optionally verifies an HMAC tag for tamper detection.
    The original file header is *not* restored, as it was permanently randomized.

    Args:
        key_path (str): Path to key file.
        out_dir (str): Output directory.
        disguise (str, optional): Disguise format. Defaults to None.
        ignore_integrity (bool, optional): Ignore hash/HMAC mismatch and missing chunks. Defaults to False.
        verbose (bool, optional): Enable verbose logging. Defaults to False.

    Returns:
        int: 0 on success, non-zero on error (1 for general error, 2 for integrity failure).
    """
    key_path_abs = os.path.abspath(key_path)
    out_dir_abs = os.path.abspath(out_dir)
    ensure_dirs(out_dir_abs)

    # Determine database path relative to the key file's directory
    key_dir = os.path.dirname(key_path_abs)
    db_path = os.path.join(key_dir, DB_FILE)
    if not os.path.exists(db_path):
        logging.error(f"Database file not found next to key file: {db_path}")
        return 1

    logging.info(f"Using database file: {db_path}")

    # Read and decode the key file
    try:
        if disguise:
            # decode_disguised_key handles version check and salt/mac decoding
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

            # Standard JSON keymap needs salt/mac decoding and version check
            loaded_version = raw_key_map.get("format_version")
            if loaded_version is None:
                 logging.warning("Keymap format version not found in standard key file. Assuming latest version.")
                 # Let's enforce version check for safety unless explicitly ignored (not implemented)
                 if KEYMAP_FORMAT_VERSION != 3: # Check if we are on version 3 and file is not marked
                      logging.error(f"Keymap format version missing. This key file might be incompatible. Expected {KEYMAP_FORMAT_VERSION}.")
                      return 1 # Indicate failure

            elif loaded_version != KEYMAP_FORMAT_VERSION:
                 logging.error(f"Keymap format version mismatch. Expected {KEYMAP_FORMAT_VERSION}, found {loaded_version}. "
                               "This key file might be incompatible with this version of Veriduct.")
                 return 1 # Exit on version mismatch

            decoded_key_map = {}
            # Decode salts and store other metadata for each file entry
            for fname, data in raw_key_map.items():
                 if fname == 'format_version': continue
                 file_salt_b64 = data.get("file_salt")
                 file_salt = None
                 if file_salt_b64:
                      try:
                           file_salt = base64.b64decode(file_salt_b64)
                      except Exception as e:
                           logging.error(f"Failed to decode salt for file '{fname}' from keymap: {e}")
                           # Critical error, cannot reassemble chunks for this file
                           continue # Skip this file

                 if file_salt is None:
                      logging.error(f"File salt missing for '{fname}' in keymap. Cannot reassemble chunks.")
                      continue # Skip this file


                 decoded_key_map[fname] = {
                      "file_salt": file_salt, # Store decoded salt bytes
                      "usf_hash": data.get("usf_hash"),
                      "mac": data.get("mac"), # Store MAC string
                      "key": data.get("key", []) # Store list of salted hashes
                 }


    except FileNotFoundError:
        logging.error(f"Key file not found: {key_path}")
        return 1
    except SystemExit as e:
         # Catch sys.exit from decode_disguised_key
         return e.code
    except Exception as e:
        logging.error(f"Error decoding key file '{key_path}': {e}")
        return 1


    # Initialize the chunk storage for retrieval (standard, non-encrypted SQLite)
    try:
        chunk_storage = ChunkStorage(db_path)
    except SystemExit as e:
        # Catch the sys.exit from ChunkStorage init error
        return e.code

    # Reassemble files from stored chunks
    reassembled_count = 0
    failed_count = 0
    total_files_in_keymap = len(decoded_key_map) # Now decode_key_map only contains file entries

    if total_files_in_keymap == 0:
         logging.error("No valid file entries found in key file after decoding/parsing.")
         chunk_storage.close()
         return 1


    for rel_path, data in decoded_key_map.items():

        full_out_path = os.path.join(out_dir_abs, rel_path)
        logging.info(f"Reassembling USF file ({reassembled_count+failed_count+1}/{total_files_in_keymap}): {rel_path}")

        # Get necessary data from keymap
        expected_usf_hash = data.get("usf_hash")
        file_salt = data.get("file_salt") # This should be bytes now
        expected_mac = data.get("mac") # This should be the hex string
        chunk_hashes_sequence = data.get("key", []) # List of salted hashes

        if file_salt is None:
             # This case should ideally be caught during decoding, but defensive check
             logging.error(f"Cannot reassemble '{rel_path}': File salt is missing.")
             failed_count += 1
             continue # Skip this file


        missing_chunks = False
        reconstruction_hasher = hashlib.sha256() # Hasher for the data as it's reconstructed

        # --- Implement Streaming Write ---
        output_file = None # File handle for writing

        integrity_check_passed = True # Assume true initially
        try:
            # Ensure output directory exists and open file for writing
            os.makedirs(os.path.dirname(full_out_path), exist_ok=True)
            output_file = open(full_out_path, "wb")

            chunk_index = 0
            for salted_chash in chunk_hashes_sequence:
                chunk_data = chunk_storage.retrieve_chunk(salted_chash)
                if chunk_data is None:
                    logging.error(f"Missing chunk: {salted_chash} for file '{rel_path}'. File reassembly incomplete.")
                    missing_chunks = True
                    # Stop reassembly for this file on first missing chunk
                    # If ignoring, we'd skip the break and update hasher/write with zero/placeholder?
                    # Sticking to: stop writing and mark as failed on first missing chunk.
                    integrity_check_passed = False # Missing chunk is an integrity failure
                    break # Exit chunk loop for this file

                # Update the hash of the reassembled stream
                reconstruction_hasher.update(chunk_data)

                # Write the chunk data directly to the output file
                output_file.write(chunk_data)

                if verbose:
                     logging.debug(f"  Retrieved and wrote chunk {chunk_index} for '{rel_path}' (salted hash {salted_chash[:8]}...)")
                chunk_index += 1

        except Exception as e:
             logging.error(f"Error during chunk retrieval or file writing for '{rel_path}': {e}")
             integrity_check_passed = False # Treat I/O errors as integrity failure
        finally:
            # Ensure the output file is closed
            if output_file:
                 output_file.close()


        # --- Perform Integrity Checks (Hash and Optional HMAC) ---

        if not missing_chunks: # Only check hashes if all chunks were retrieved
            rebuilt_usf_hash = reconstruction_hasher.hexdigest()

            # Check USF Hash
            if expected_usf_hash is None:
                 logging.warning(f"Expected USF hash missing in key map for '{rel_path}'. Cannot verify integrity of reassembled USF data.")
                 # Decide if missing hash is a failure. For now, warn but allow writing unless ignore_integrity is False.
                 if not ignore_integrity:
                     logging.error(f"Integrity verification skipped for '{rel_path}' due to missing hash. Treating as failure.")
                     integrity_check_passed = False # Treat as failure if not ignoring
                 else:
                      integrity_check_passed = True # Pass if ignoring and hash is missing
            elif rebuilt_usf_hash == expected_usf_hash:
                 logging.info(f"USF hash verification successful for reassembled file: {rel_path}")
                 # If hash is good, check HMAC if present
                 if expected_mac:
                      try:
                          calculated_mac = calculate_hmac(file_salt, rebuilt_usf_hash.encode('utf-8'))
                          if hmac.compare_digest(calculated_mac, expected_mac):
                               logging.info(f"HMAC verification successful for reassembled file: {rel_path}")
                               integrity_check_passed = True # Hash and HMAC are good
                          else:
                               logging.error(f"HMAC mismatch for reassembled file '{rel_path}'. Data or keymap may be tampered.")
                               integrity_check_passed = False # HMAC mismatch is failure
                      except Exception as mac_e:
                           logging.error(f"Error calculating/comparing HMAC for '{rel_path}': {mac_e}")
                           integrity_check_passed = False # HMAC error is failure
                 else:
                      # Hash is good, no MAC to check. Passed basic integrity.
                      integrity_check_passed = True
            else:
                 logging.error(f"USF hash mismatch in reassembled file '{rel_path}': expected {expected_usf_hash}, got {rebuilt_usf_hash}. File may be corrupted.")
                 integrity_check_passed = False # Hash mismatch is failure


        # --- Handle Failure or Success After Checks ---

        if not integrity_check_passed:
             failed_count += 1
             logging.error(f"File reassembly failed integrity check for '{rel_path}'.")
             if not ignore_integrity:
                  logging.error(f"Deleting potentially corrupted reassembled file: {full_out_path}")
                  # Delete the output file if integrity failed and not ignoring
                  if os.path.exists(full_out_path):
                      try:
                           os.remove(full_out_path)
                           logging.debug(f"Removed potentially corrupted file: {full_out_path}")
                      except Exception as cleanup_e:
                           logging.error(f"Error removing potentially corrupted file '{full_out_path}': {cleanup_e}")
             else:
                  logging.warning(f"Ignoring integrity failure for '{rel_path}' (--ignore-integrity). Output file {full_out_path} may be corrupted.")

             continue # Move to the next file

        # If we reached here, integrity_check_passed is True (either passed or ignoring)
        # File is already written via streaming
        reassembled_count += 1 # Increment count only if successfully reassembled and integrity passed/ignored


    chunk_storage.close()
    logging.info(f"Reassembly complete: {reassembled_count} files reassembled successfully, {failed_count} files failed integrity checks or had errors.")

    if failed_count > 0:
         return 2 # Indicate integrity failure or missing chunks
    elif reassembled_count == 0 and total_files_in_keymap > 0:
         logging.error("No files were successfully reassembled.")
         return 1 # Indicate a general failure
    else:
         return 0 # Indicate success


def main():
    parser = argparse.ArgumentParser(
        description="Veriduct - the channel beneath control.\n"
                    "Implements Universal Substrate Format (USF) via structural destruction.\n"
                    "WARNING: This process is irreversible. Reassembly recovers the USF data,\n"
                    "         NOT the original file header.\n"
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
        help=f"Number of bytes to randomize at the start of each file (default: {DEFAULT_USF_WIPE_SIZE})"
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

    # Configure logging based on verbose flag
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    # Suppress potential noisy debug logs from libraries if needed
    # logging.getLogger('zstandard').setLevel(logging.WARNING)


    if args.command == "annihilate":
        if not os.path.exists(args.input_path):
            logging.error(f"Input path does not exist: {args.input_path}")
            sys.exit(1) # Exit code 1 for general argument/setup errors
        if args.wipe_bytes < 0:
             logging.error("--wipe-bytes must be a non-negative integer.")
             sys.exit(1)

        # annihilate_path returns an exit code
        exit_code = annihilate_path(args.input_path, args.out_dir, args.wipe_bytes, args.add_hmac, args.disguise, args.force_internal, args.verbose)
        sys.exit(exit_code)


    elif args.command == "reassemble":
        if not os.path.exists(args.key_path):
             logging.error(f"Key file not found: {args.key_path}")
             sys.exit(1) # Exit code 1 for general argument/setup errors

        # reassemble_path returns an exit code
        exit_code = reassemble_path(args.key_path, args.out_dir, args.disguise, args.ignore_integrity, args.verbose)
        sys.exit(exit_code)

    else:
        # This should not be reached due to required=True in subparsers, but good practice
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
