[![License: Dual - Apache 2.0 & Commercial](https://img.shields.io/badge/license-Apache%202.0%20%26%20Commercial-blue.svg)](LICENSE)

# Veriduct: Stealth File Encoding and Decoding Framework

**Veriduct** is a novel data security framework that employs a technique called "semantic erasure" to encode and decode files.  Instead of simply encrypting data, Veriduct fragments files into numerous meaningless chunks, requiring a specific key to reassemble them. This approach aims to minimize the impact of data breaches by rendering stolen data unusable without the key.

**Key Features:**

* **Semantic Erasure:** The core concept of fragmenting data into meaningless chunks.
* **Chunk Storage:** Secure storage of data fragments (currently implemented using an encrypted SQLite database).
* **Key Management:** Key derivation using PBKDF2 for enhanced security.
* **Key Disguising:** Optional key disguising in various formats (CSV, log, conf).
* **File Reconstruction:** Decoding process to reassemble original files from chunks using the key.
* **Proof of Concept:** This project is a proof-of-concept and is intended for educational and research purposes.

**Technical Details:**

* **Language:** Python
* **Dependencies:**
    * pysqlite3 (for SQLite database)
    * cryptography
    * zstandard
* **Chunking:** Files are split into chunks.
* **Key Generation:** A key is used to map chunks to their original file and order.
* **Key Security:** The key can be encrypted.
* **Storage:** Chunks are stored in a database.

**Disclaimer:**

This tool is for educational and research purposes only.  It is not intended for production use.  The author is not responsible for any misuse.  Security audits and further development are required for real-world applications.

**Current Status:**

This project is under active development.  The current implementation provides a functional proof-of-concept, but further improvements are needed, particularly in:

* Performance optimization
* Enhanced security measures
* Robust error handling
* Comprehensive testing

**License:**

Apache 2.0

**Author:**

reapermunky
