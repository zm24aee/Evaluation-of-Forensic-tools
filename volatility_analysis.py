import subprocess
import os
import time
import json
from datetime import datetime
from ground_truth import GROUND_TRUTH
from evaluation_utils import evaluate_scenario_against_ground_truth, compute_metrics_for_run

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
VOL = r"C:\Users\munee\AppData\Local\Python\pythoncore-3.14-64\Scripts\vol.exe"
OUT_DIR = r"C:\Forensic\Volatility"

IMAGES = {
    "benign_run1": r"C:\Forensic\Images\benign_run1.mem",
    "benign_run2": r"C:\Forensic\Images\benign_run2.mem",
    "benign_run3": r"C:\Forensic\Images\benign_run3.mem",
    "fileless_run1": r"C:\Forensic\Images\fileless_run1.mem",
    "fileless_run2": r"C:\Forensic\Images\fileless_run2.mem",
    "fileless_run3": r"C:\Forensic\Images\fileless_run3.mem",
}

PLUGINS = {
    "windows.pslist": "pslist.txt",
    "windows.pstree": "pstree.txt",
    "windows.cmdline": "cmdline.txt",
    "windows.malfind": "malfind.txt",
    "windows.netscan": "netscan.txt",
    "windows.dlllist": "dlllist.txt",
    "windows.vadinfo": "vadinfo.txt",
}

BENIGN_LABELS = {"benign_run1", "benign_run2", "benign_run3"}
# ─────────────────────────────────────────────
# SAFE RUN
# ─────────────────────────────────────────────
def safe_run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "stdout": result.stdout or "",
        "stderr": result.stderr or "",
        "returncode": result.returncode
    }
# ─────────────────────────────────────────────
# ANALYSIS
# ─────────────────────────────────────────────
def analyse(label, image_path):
    out_dir = os.path.join(OUT_DIR, label)
    os.makedirs(out_dir, exist_ok=True)

    scenario_type = "BENIGN" if label in BENIGN_LABELS else "FILELESS"

    results = {
        "label": label,
        "scenario_type": scenario_type,
        "tool": "Volatility3",
        "image": image_path,
        "timestamp": datetime.now().isoformat(),
        "plugins": {},
        "false_positives": [],
        "true_detections": [],
        "ground_truth_eval": {},
        "metrics": {},
    }

    total_start = time.time()
    evidence_by_plugin = {}

    # ───────── HEADER PRINT ─────────
    print("\n" + "="*60)
    print(f"  Analysing : {label}  [{scenario_type}]")
    print(f"  Image     : {image_path}")
    print(f"  Started   : {results['timestamp']}")
    print("="*60)

    # ───────── RUN PLUGINS ─────────
    for plugin, filename in PLUGINS.items():
        print(f"[*] Running {plugin} ... ", end="", flush=True)

        t0 = time.time()
        res = safe_run([VOL, "-f", image_path, plugin])
        elapsed = round(time.time() - t0, 2)

        stdout_text = res["stdout"]
        stderr_text = res["stderr"]
        combined_text = (stdout_text + "\n" + stderr_text).lower()

        evidence_by_plugin[plugin] = combined_text

        out_path = os.path.join(out_dir, filename)
        err_path = os.path.join(out_dir, filename.replace(".txt", "_stderr.txt"))

        with open(out_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(stdout_text)

        with open(err_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(stderr_text)

        # detect suspicious keywords (simple display only)
        suspicious = any(k in combined_text for k in [
            "encodedcommand", "wmiprvse", "reflection", "invoke-", " mz "
        ])

        status = "⚠ suspicious" if suspicious else "✓ clean"

        print(f"done in {elapsed:.2f}s  |  {status}")

        results["plugins"][plugin] = {
            "output_lines": len(stdout_text.splitlines()),
            "stderr_lines": len(stderr_text.splitlines()),
            "duration_s": elapsed,
            "returncode": res["returncode"],
            "output_file": out_path,
            "stderr_file": err_path,
        }

    # ───────── GROUND TRUTH EVAL ─────────
    scenario_eval = evaluate_scenario_against_ground_truth(label, evidence_by_plugin, GROUND_TRUTH)
    results["ground_truth_eval"] = scenario_eval

    if scenario_type == "BENIGN":
        fp_count = scenario_eval["recovered_count"]
        results["false_positives"] = scenario_eval["recovered"]
    else:
        fp_count = 0
        results["true_detections"] = scenario_eval["recovered"]

    results["metrics"] = compute_metrics_for_run(label, scenario_eval, fp_count)

    results["total_duration_s"] = round(time.time() - total_start, 2)

    # ───────── SUMMARY PRINT ─────────
    suspicious_plugins = sum(
        1 for p in evidence_by_plugin.values()
        if any(k in p for k in ["encodedcommand", "wmiprvse", "reflection"])
    )

    print("\n[+] Finished in {:.2f}s".format(results["total_duration_s"]))
    print(f"[+] Suspicious plugins : {suspicious_plugins}/{len(PLUGINS)}")

    if scenario_type == "BENIGN":
        print(f"[+] False positives    : {len(results['false_positives'])}")
    else:
        print(f"[+] True detections    : {len(results['true_detections'])}")

    summary_path = os.path.join(out_dir, "summary.json")
    print(f"[+] Summary saved to   : {summary_path}")

    # save json
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("\n" + "="*60)
    print("  PHASE 5 — VOLATILITY 3 AUTOMATED ANALYSIS")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    all_results = {}

    for label, path in IMAGES.items():
        if not os.path.exists(path):
            print(f"[!] Missing image: {path}")
            continue

        all_results[label] = analyse(label, path)

    master = {
        "phase": "Phase 5 - Volatility3 Analysis",
        "run_timestamp": datetime.now().isoformat(),
        "total_images": len(IMAGES),
        "results": all_results,
    }

    master_path = os.path.join(OUT_DIR, "master_summary.json")

    with open(master_path, "w", encoding="utf-8") as f:
        json.dump(master, f, indent=2)

    print("\n[+] Master summary saved:", master_path)


if __name__ == "__main__":
    main()