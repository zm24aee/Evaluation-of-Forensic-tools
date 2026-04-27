import matplotlib.pyplot as plt
import numpy as np
import json
import os

# ─────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────
VOL_PATH = r"C:\Forensic\Volatility\master_summary.json"
MEM_PATH = r"C:\Forensic\MemProcFS_Results\master_summary.json"
OUT_DIR  = r"C:\Forensic\Charts_Publication"
os.makedirs(OUT_DIR, exist_ok=True)

# ─────────────────────────────────────────────
# STYLE (Publication quality)
# ─────────────────────────────────────────────
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.titlesize": 14,
    "axes.labelsize": 12,
    "legend.fontsize": 10,
})

VOL_COLOR = "#2C7BB6"
MEM_COLOR = "#D7191C"

# ─────────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────────
with open(VOL_PATH) as f:
    vol = json.load(f)["results"]

with open(MEM_PATH) as f:
    mem = json.load(f)["results"]

runs = list(vol.keys())

def extract(metric):
    return (
        [vol[r]["metrics"].get(metric, 0) for r in runs],
        [mem[r]["metrics"].get(metric, 0) for r in runs],
    )

vol_rec, mem_rec = extract("recovered_artefacts")
vol_acc, mem_acc = extract("detection_accuracy_pct")
vol_fp, mem_fp   = extract("false_positive_count")

vol_time = [vol[r]["total_duration_s"] for r in runs]
mem_time = [mem[r]["total_duration_s"] for r in runs]

labels = [
    "Benign 1", "Benign 2", "Benign 3",
    "Fileless 1", "Fileless 2", "Fileless 3"
]

x = np.arange(len(labels))
w = 0.35

# ─────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────
def style(ax):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15)

def save(fig, name):
    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, name), dpi=300)
    plt.close(fig)

# ─────────────────────────────────────────────
# FIGURE 1 — DETECTION
# ─────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(10, 5))

ax.bar(x - w/2, vol_rec, w, label="Volatility 3", color=VOL_COLOR)
ax.bar(x + w/2, mem_rec, w, label="MemProcFS", color=MEM_COLOR)

ax.set_title("Figure 1: Artefact Recovery Across Scenarios")
ax.set_ylabel("Number of Recovered Artefacts")
ax.set_xlabel("Scenario")
ax.legend()

style(ax)
save(fig, "fig1_detection.png")

# ─────────────────────────────────────────────
# FIGURE 2 — ACCURACY
# ─────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(10, 5))

ax.bar(x - w/2, vol_acc, w, label="Volatility 3", color=VOL_COLOR)
ax.bar(x + w/2, mem_acc, w, label="MemProcFS", color=MEM_COLOR)

ax.set_title("Figure 2: Detection Accuracy Comparison")
ax.set_ylabel("Accuracy (%)")
ax.set_xlabel("Scenario")
ax.set_ylim(0, 110)
ax.legend()

style(ax)
save(fig, "fig2_accuracy.png")

# ─────────────────────────────────────────────
# FIGURE 3 — FALSE POSITIVES
# ─────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(10, 5))

ax.bar(x - w/2, vol_fp, w, label="Volatility 3", color=VOL_COLOR)
ax.bar(x + w/2, mem_fp, w, label="MemProcFS", color=MEM_COLOR)

ax.set_title("Figure 3: False Positive Comparison")
ax.set_ylabel("False Positives")
ax.set_xlabel("Scenario")
ax.legend()

style(ax)
save(fig, "fig3_false_positives.png")

# ─────────────────────────────────────────────
# FIGURE 4 — ANALYSIS TIME
# ─────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(10, 5))

ax.bar(x - w/2, vol_time, w, label="Volatility 3", color=VOL_COLOR)
ax.bar(x + w/2, mem_time, w, label="MemProcFS", color=MEM_COLOR)

ax.set_title("Figure 4: Analysis Time Comparison")
ax.set_ylabel("Time (seconds)")
ax.set_xlabel("Scenario")
ax.legend()

style(ax)
save(fig, "fig4_time.png")

print(f"[+] Publication-quality figures saved to: {OUT_DIR}")