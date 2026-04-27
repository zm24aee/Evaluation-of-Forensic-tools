import json
import os
import hashlib
import datetime

LOG_FILE = r"C:\forensic\logs_json\experiment_log.json"

IMAGES = {
    "benign_run1": r"C:\forensic\Images\benign_run1.mem",
    "benign_run2": r"C:\forensic\Images\benign_run2.mem",
    "benign_run3": r"C:\forensic\Images\benign_run3.mem",
    "fileless_run1": r"C:\forensic\Images\fileless_run1.mem",
    "fileless_run2": r"C:\forensic\Images\fileless_run2.mem",
    "fileless_run3": r"C:\forensic\Images\fileless_run3.mem",
}

def sha256_file(path, chunk_size=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def load_existing_log():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def save_log(entries):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)

def main():
    existing = load_existing_log()
    existing_by_label = {e["label"]: e for e in existing}

    for label, path in IMAGES.items():
        if not os.path.exists(path):
            print(f"[!] Missing image: {path}")
            continue

        entry = {
            "label": label,
            "timestamp": datetime.datetime.now().strftime("%Y%m%d_%H%M%S"),
            "path": path,
            "sha256": sha256_file(path),
        }
        existing_by_label[label] = entry
        print(f"[+] Logged {label}")

    final_entries = [existing_by_label[k] for k in sorted(existing_by_label.keys())]
    save_log(final_entries)
    print(f"[+] Saved log to {LOG_FILE}")

if __name__ == "__main__":
    main()