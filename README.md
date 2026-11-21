# 🛡️ Simple Antivirus Scanner

A lightweight, command-line Python security utility designed to recursively scan local directories, detect malicious code signatures in binary/text files, compute cryptographic file hashes, and safely isolate threats into a quarantine folder.

---

## 🚀 Key Features

* **Recursive Directory Traversal:** Uses Python's `os.walk` to inspect deep folder structures while intelligently skipping system and environment directories (`Quarantine`, `venv`, `.git`, `__pycache__`, `node_modules`).
* **Signature-Based Threat Detection:** Reads files in chunks (`CHUNK_SIZE = 4096`) without crashing RAM, matching byte-level malicious signatures (e.g., reverse shells, encoded PowerShell commands).
* **Cryptographic Integrity (SHA-256):** Computes unique SHA-256 hashes for flagged files to assist in forensic analysis and threat intelligence tracking.
* **Interactive Quarantine System:** Automatically creates a `Quarantine` directory and safely relocates infected files with automated duplicate-name handling (e.g., `file_1.txt`).
* **Automated Incident Logging:** Generates a timestamped summary report (`scan_report.txt`) recording total files scanned, threats detected, and actions taken.

---

## 🛠️ Tech Stack & Modules
* **Language:** Python 3.x
* **Core Modules:** `os`, `shutil`, `hashlib`, `datetime`

---

## ⚙️ How to Run

1. **Clone the repository:**
   ```bash
   git clone https://github.com/kajal-yadav3311/simple-antivirus-scanner.git
   cd simple-antivirus-scanner
 
