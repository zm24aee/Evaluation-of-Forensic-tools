# disagreement_analysis.py
import json

VOL_PATH = r"C:\Forensic\Volatility\master_summary.json"
MEM_PATH = r"C:\Forensic\MemProcFS_Results\master_summary.json"

with open(VOL_PATH, "r", encoding="utf-8") as f:
    vol = json.load(f)["results"]
with open(MEM_PATH, "r", encoding="utf-8") as f:
    mem = json.load(f)["results"]
for run in sorted(vol.keys()):
    vol_found = {x["artefact_id"] for x in vol[run].get("true_detections", []) if "artefact_id" in x}
    mem_found = {x["artefact_id"] for x in mem[run].get("true_detections", []) if "artefact_id" in x}

    print("\n" + "=" * 50)
    print(run)
    print("Both found      :", sorted(vol_found & mem_found))
    print("Volatility only :", sorted(vol_found - mem_found))
    print("MemProcFS only  :", sorted(mem_found - vol_found))
    print("Missed by both  :", "derive from ground truth separately")
