import os
import shutil
import hashlib
from datetime import datetime

# ==========================
# Configuration
# ==========================

QUARANTINE_FOLDER = "Quarantine"
REPORT_FILE = "scan_report.txt"

SKIP_FOLDERS = {
    "Quarantine",
    "venv",
    ".git",
    "__pycache__",
    "node_modules"
}

SUSPICIOUS_SIGNATURES = [
    b"eval(base64_decode",
    b"cmd.exe",
    b"powershell -enc",
    b"ReverseShell",
]

CHUNK_SIZE = 4096


# ==========================
# Create Quarantine Folder
# ==========================

def setup_quarantine():
    if not os.path.exists(QUARANTINE_FOLDER):
        os.makedirs(QUARANTINE_FOLDER)
        print(f"[+] Created quarantine folder: {QUARANTINE_FOLDER}")


# ==========================
# Calculate SHA256 Hash
# ==========================

def get_sha256(file_path):
    sha = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha.update(chunk)

        return sha.hexdigest()

    except Exception:
        return "Unavailable"


# ==========================
# Scan File
# ==========================

def scan_file(file_path):
    """
    Scan a file without loading the entire file into RAM.
    """

    try:
        with open(file_path, "rb") as file:

            previous = b""

            while True:
                chunk = file.read(CHUNK_SIZE)

                if not chunk:
                    break

                data = previous + chunk

                for signature in SUSPICIOUS_SIGNATURES:
                    if signature in data:
                        return True

                previous = data[-100:]

    except PermissionError:
        print(f"[Permission Denied] {file_path}")

    except Exception as e:
        print(f"[Error] {file_path}")
        print(e)

    return False


# ==========================
# Quarantine File
# ==========================

def quarantine_file(file_path):
    try:

        file_name = os.path.basename(file_path)

        destination = os.path.join(QUARANTINE_FOLDER, file_name)

        counter = 1

        while os.path.exists(destination):
            name, ext = os.path.splitext(file_name)
            destination = os.path.join(
                QUARANTINE_FOLDER,
                f"{name}_{counter}{ext}"
            )
            counter += 1

        shutil.move(file_path, destination)

        print(f"[QUARANTINED] {file_path}")

    except Exception as e:
        print(f"[Failed] {file_path}")
        print(e)


# ==========================
# Save Report
# ==========================

def save_report(report_lines):
    with open(REPORT_FILE, "w", encoding="utf-8") as report:
        report.write("\n".join(report_lines))


# ==========================
# Main Program
# ==========================

def main():

    print("=" * 60)
    print("Simple Antivirus Scanner")
    print("=" * 60)

    directory = input("\nEnter folder to scan: ").strip()

    if not os.path.isdir(directory):
        print("Invalid folder.")
        return

    setup_quarantine()

    files_scanned = 0
    threats_found = 0

    report = []

    report.append("Simple Antivirus Scan Report")
    report.append(f"Time: {datetime.now()}")
    report.append("=" * 60)

    print("\nScanning...\n")

    for root, dirs, files in os.walk(directory):

        dirs[:] = [d for d in dirs if d not in SKIP_FOLDERS]

        for file in files:

            file_path = os.path.join(root, file)

            files_scanned += 1

            print(f"Scanning: {file_path}")

            if scan_file(file_path):

                threats_found += 1

                file_size = os.path.getsize(file_path)

                file_hash = get_sha256(file_path)

                print("\n" + "=" * 50)
                print("THREAT DETECTED")
                print("=" * 50)
                print("File :", file_path)
                print("Size :", file_size, "bytes")
                print("SHA256:", file_hash)

                report.append("")
                report.append(f"Threat: {file_path}")
                report.append(f"Size: {file_size} bytes")
                report.append(f"SHA256: {file_hash}")

                choice = input("\nQuarantine this file? (y/n): ")

                if choice.lower() == "y":
                    quarantine_file(file_path)
                    report.append("Action: Quarantined")

                else:
                    print("Skipped.")
                    report.append("Action: Skipped")

                print()

    report.append("")
    report.append("=" * 60)
    report.append(f"Files Scanned : {files_scanned}")
    report.append(f"Threats Found : {threats_found}")

    save_report(report)

    print("\n")
    print("=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"Files Scanned : {files_scanned}")
    print(f"Threats Found : {threats_found}")
    print(f"Report Saved  : {REPORT_FILE}")


if __name__ == "__main__":
    main()

    print("\n\n❤️Thank you for visiting❤️")