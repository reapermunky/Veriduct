Veriduct - 
A Data Framework for Stealth File Encoding and Decoding

Disclaimer: This tool is provided for educational and research purposes only.
It is intended for legal and ethical use. The author is not responsible for any misuse.

Overview - 
Veriduct is a command-line utility designed to chunk and store file data in a “dictionary” of SHA-256–labeled blobs, while generating a compact key file that describes how to reassemble the original files. The key can optionally be:

Disguised in formats like CSV, LOG, or CONF (for obfuscation).

Compressed using Zstandard.

Encrypted with the Python cryptography library’s Fernet (symmetric encryption).

By splitting and disguising file content, Veriduct offers a level of “stealth” that can complement more conventional approaches to data encryption or storage.

Key Features: 

Chunked Storage: Splits files into 4 KB chunks and stores them in a dedicated dictionary (veriduct_dict).

Unique Deduplication: Identical chunks (same SHA-256 hash) are stored only once.

Flexible Key Options: Store the key in a standard Zstandard-compressed JSON file, disguise it, or encrypt it.

Simple CLI: Includes encode and decode commands to simplify usage.

Logging & Error Handling: Robust logging for troubleshooting.


Installation: 
Clone or Download this repository.

Ensure Python 3.6+ is installed.

Install required Python packages:

nginx
Copy
Edit
pip install -r requirements.txt
Dependencies:

cryptography (for Fernet encryption)

zstandard (for fast compression/decompression)

(Optional) Make the script executable on Unix-like systems:

bash
Copy
Edit
chmod +x veriduct.py
Usage
Veriduct provides a CLI with two main commands: encode and decode.

Encode
php-template
Copy
Edit
./veriduct.py encode <file-or-directory> <out-directory> [--disguise <format>] [--encrypt]
Arguments:

file-or-directory
The path to a file or folder you want to encode.

out-directory
Where you want to store the output key (and disguised/encrypted key, if specified).

Options:

--disguise <format>
Disguise the key in one of the supported formats: csv, log, or conf.

--encrypt
Encrypt the key using Fernet instead of leaving it in cleartext or disguised form.

Decode
php-template
Copy
Edit
./veriduct.py decode <key-path> <out-directory> [--disguise <format>] [--decrypt <key>]
Arguments:

key-path
The path to the key file (disguised, encrypted, or raw) produced by encode.

out-directory
Where the reconstructed files should be placed.

Options:

--disguise <format>
Specifies the same format used to disguise the key file (csv, log, or conf) so that Veriduct can parse it.

--decrypt <key>
The Fernet decryption key (Base64-encoded) if the key file was encrypted.

Examples
1. Basic Encoding
bash
Copy
Edit
./veriduct.py encode ~/Documents/my-project ~/output
Splits my-project into chunks in veriduct_dict/.

Produces a compressed key file (veriduct.key.zst) in ~/output.

2. Disguising the Key as a Log File
bash
Copy
Edit
./veriduct.py encode ~/Documents/my-project ~/output --disguise log
Same chunking as before, but the key references are written in a .log file (e.g., veriduct_key.log).

3. Encrypting the Key
bash
Copy
Edit
./veriduct.py encode ~/Documents/my-project ~/output --encrypt
Generates veriduct.key.enc in ~/output.

Prints the encryption key (Base64) to the terminal. Store this key securely!

4. Decoding a Disguised Key
bash
Copy
Edit
./veriduct.py decode ~/output/veriduct_key.log ~/restored --disguise log
Reads the disguised log key.

Fetches chunks from veriduct_dict/ to rebuild the original file(s) in ~/restored.

5. Decoding an Encrypted Key
bash
Copy
Edit
./veriduct.py decode ~/output/veriduct.key.enc ~/restored --decrypt "<your-fernet-key>"
Decrypts the key with the provided Fernet key.

Reconstructs original files in ~/restored.

License - 
This project is distributed under the GNU General Public License (GPL) v3.0

Disclaimer - 
This tool is provided “as is” and is intended only for lawful purposes such as secure data backup and retrieval, proof-of-concept demonstrations, and educational use. The author(s) disclaim all liability for use or misuse of this tool. Please use responsibly.

Contributing - 
Fork the repository on GitHub.

Create a new branch for your changes.

Commit and push your changes.

Open a Pull Request describing your modifications.

All contributions (bug reports, feature suggestions, pull requests) are welcome!
