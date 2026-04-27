import os
import time
import json
import shutil
import subprocess
from datetime import datetime
from ground_truth import GROUND_TRUTH
from evaluation_utils import evaluate_scenario_against_ground_truth, compute_metrics_for_run

MEMPROCFS = r"C:\Forensic\MemProcFS\MemProcFS.exe"
PYTHON_PATH = r"C:\Users\munee\AppData\Local\Python\pythoncore-3.14-64"
OUT_DIR = r"C:\Forensic\MemProcFS_Results"
MOUNT = "M:"

IMAGES = {
    "benign_run1": r"C:\Forensic\Images\benign_run1.mem",
    "benign_run2": r"C:\Forensic\Images\benign_run2.mem",
    "benign_run3": r"C:\Forensic\Images\benign_run3.mem",
    "fileless_run1": r"C:\Forensic\Images\fileless_run1.mem",
    "fileless_run2": r"C:\Forensic\Images\fileless_run2.mem",
    "fileless_run3": r"C:\Forensic\Images\fileless_run3.mem",
}

BENIGN_LABELS = {"benign_run1", "benign_run2", "benign_run3"}


def unmount():
    subprocess.run(["taskkill", "/IM", "MemProcFS.exe", "/F"], capture_output=True)
    time.sleep(3)


def wait_for_forensic(timeout=300):
    progress_file = os.path.join(MOUNT, "forensic", "progress_percent.txt")
    start = time.time()
    while time.time() - start < timeout:
        try:
            with open(progress_file, "r", encoding="utf-8", errors="ignore") as f:
                if f.read().strip() == "100":
                    return True
        except Exception:
            pass
        time.sleep(5)
    return False


def read_file_safe(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""
    # ───────── Analysis ─────────
def analyse(label, image_path):
    scenario_type = "BENIGN" if label in BENIGN_LABELS else "FILELESS"
    out_dir = os.path.join(OUT_DIR, label)
    os.makedirs(out_dir, exist_ok=True)

    print("\n" + "=" * 60)
    print(f"  Analysing : {label}  [{scenario_type}]")
    print(f"  Image     : {image_path}")
    print(f"  Started   : {datetime.now().isoformat()}")
    print("=" * 60)

    results = {
        "label": label,
        "scenario_type": scenario_type,
        "tool": "MemProcFS",
        "image": image_path,
        "timestamp": datetime.now().isoformat(),
        "processes": [],
        "cmdline_hits": {},
        "csv_hits": {},
        "false_positives": [],
        "true_detections": [],
        "ground_truth_eval": {},
        "metrics": {},
    }

    total_start = time.time()

    print("[*] Unmounting previous session...")
    unmount()

    print("[*] Mounting image...")
    subprocess.Popen(
        [MEMPROCFS, "-device", image_path, "-mount", MOUNT, "-pythonpath", PYTHON_PATH],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(8)

    print("[*] Enabling forensic mode...")
    forensic_enable = os.path.join(MOUNT, "forensic", "forensic_enable.txt")
    try:
        with open(forensic_enable, "w") as f:
            f.write("1")
    except Exception:
        pass

    print("[*] Waiting for forensic processing...")
    wait_for_forensic()
    print("[*] Forensic progress: 100%")

    evidence_by_plugin = {
        "windows.cmdline": "",
        "windows.pstree": "",
        "windows.malfind": "",
        "windows.vadinfo": "",
    }

    # Process list
    print("[*] Collecting process list...")
    name_dir = os.path.join(MOUNT, "name")
    if os.path.exists(name_dir):
        results["processes"] = sorted(os.listdir(name_dir))
        print(f"    Found {len(results['processes'])} processes")
        evidence_by_plugin["windows.pstree"] += "\n".join(results["processes"]).lower()

    # CMDLINE
    print("[*] Reading cmdline for suspicious processes...")
    pid_dir = os.path.join(MOUNT, "pid")
    cmd_hits = 0

    if os.path.exists(pid_dir):
        for proc_folder in os.listdir(pid_dir):
            cmdline_path = os.path.join(pid_dir, proc_folder, "cmdline")
            content = read_file_safe(cmdline_path).strip()

            if content:
                results["cmdline_hits"][proc_folder] = content
                evidence_by_plugin["windows.cmdline"] += "\n" + content.lower()

                if any(k in content.lower() for k in ["powershell", "wmic", "invoke"]):
                    cmd_hits += 1

    print(f"    Cmdline suspicious hits: {cmd_hits}")

    # CSV extraction
    print("[*] Collecting forensic CSV outputs...")
    csv_dir = os.path.join(MOUNT, "forensic", "csv")
    csv_out_dir = os.path.join(out_dir, "csv")
    os.makedirs(csv_out_dir, exist_ok=True)

    csv_count = 0

    if os.path.exists(csv_dir):
        for csv_name in os.listdir(csv_dir):
            src = os.path.join(csv_dir, csv_name)
            dst = os.path.join(csv_out_dir, csv_name)

            try:
                shutil.copy2(src, dst)
                csv_count += 1
            except Exception:
                pass

            content = read_file_safe(src).lower()

            if csv_name in {"process.csv", "threads.csv", "handles.csv"}:
                evidence_by_plugin["windows.pstree"] += "\n" + content

            if csv_name in {"findevil.csv", "yara.csv", "modules.csv"}:
                evidence_by_plugin["windows.malfind"] += "\n" + content
                evidence_by_plugin["windows.vadinfo"] += "\n" + content

    print(f"    Collected {csv_count} CSV files")

    # Registry info
    print("[*] Reading registry info...")
    reg_dir = os.path.join(MOUNT, "registry")
    if os.path.exists(reg_dir):
        print(f"    Registry hives found: {len(os.listdir(reg_dir))}")

    # Ground truth evaluation
    scenario_eval = evaluate_scenario_against_ground_truth(label, evidence_by_plugin, GROUND_TRUTH)
    results["ground_truth_eval"] = scenario_eval

    if scenario_type == "FILELESS":
        results["true_detections"] = scenario_eval["recovered"]
        fp_count = 0
    else:
        fp_count = scenario_eval["recovered_count"]
        results["false_positives"] = scenario_eval["recovered"]

    results["metrics"] = compute_metrics_for_run(label, scenario_eval, fp_count)
    results["total_duration_s"] = round(time.time() - total_start, 2)

    print("\n[+] Finished in {:.2f}s".format(results["total_duration_s"]))
    print(f"[+] Processes found : {len(results['processes'])}")
    if scenario_type == "BENIGN":
        print(f"[+] False positives : {len(results['false_positives'])}")
    else:
        print(f"[+] True detections : {len(results['true_detections'])}")
    summary_path = os.path.join(out_dir, "summary.json")
    print(f"[+] Summary saved  : {summary_path}")

    print("[*] Unmounting...")
    unmount()

    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)

    return results
def main():
    print("\n" + "=" * 60)
    print("  PHASE 6 — MEMPROCFS AUTOMATED ANALYSIS")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    all_results = {}

    for label, path in IMAGES.items():
        if not os.path.exists(path):
            print(f"[!] Missing image: {path}")
            continue

        all_results[label] = analyse(label, path)

    master = {
        "phase": "Phase 6 - MemProcFS Analysis",
        "run_timestamp": datetime.now().isoformat(),
        "total_images": len(IMAGES),
        "results": all_results,
    }

    master_path = os.path.join(OUT_DIR, "master_summary.json")

    with open(master_path, "w") as f:
        json.dump(master, f, indent=2)

    print("\n[+] Master summary saved:", master_path)


if __name__ == "__main__":
    main()