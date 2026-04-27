import json
import csv
import statistics
import pandas as pd
import streamlit as st

VOL_PATH = r"C:\Forensic\Volatility\master_summary.json"
MEM_PATH = r"C:\Forensic\MemProcFS_Results\master_summary.json"

with open(VOL_PATH, "r", encoding="utf-8") as f:
    vol_data = json.load(f)["results"]

with open(MEM_PATH, "r", encoding="utf-8") as f:
    mem_data = json.load(f)["results"]

def get_run_metrics(run_obj):
    m = run_obj.get("metrics", {})
    return {
        "expected": m.get("expected_artefacts", 0),
        "recovered": m.get("recovered_artefacts", 0),
        "missed": m.get("missed_artefacts", 0),
        "fp": m.get("false_positive_count", 0),
        "precision": m.get("precision"),
        "recall": m.get("recall"),
        "accuracy_pct": m.get("detection_accuracy_pct", 0.0),
        "time_s": run_obj.get("total_duration_s", 0.0),
    }

def build_comparison(vol_data, mem_data):
    rows = []
    for run in sorted(vol_data.keys()):
        vol = get_run_metrics(vol_data[run])
        mem = get_run_metrics(mem_data[run])

        rows.append({
            "run": run,
            "vol_expected": vol["expected"],
            "vol_recovered": vol["recovered"],
            "vol_fp": vol["fp"],
            "vol_precision": vol["precision"],
            "vol_recall": vol["recall"],
            "vol_accuracy_pct": vol["accuracy_pct"],
            "vol_time_s": vol["time_s"],
            "mem_expected": mem["expected"],
            "mem_recovered": mem["recovered"],
            "mem_fp": mem["fp"],
            "mem_precision": mem["precision"],
            "mem_recall": mem["recall"],
            "mem_accuracy_pct": mem["accuracy_pct"],
            "mem_time_s": mem["time_s"],
        })
    return pd.DataFrame(rows)

def summarise(df):
    return {
        "vol_mean_accuracy": round(df["vol_accuracy_pct"].mean(), 2),
        "mem_mean_accuracy": round(df["mem_accuracy_pct"].mean(), 2),
        "vol_mean_fp": round(df["vol_fp"].mean(), 2),
        "mem_mean_fp": round(df["mem_fp"].mean(), 2),
        "vol_mean_time": round(df["vol_time_s"].mean(), 2),
        "mem_mean_time": round(df["mem_time_s"].mean(), 2),
        "vol_std_time": round(df["vol_time_s"].std(ddof=0), 2),
        "mem_std_time": round(df["mem_time_s"].std(ddof=0), 2),
    }

def repeatability_check(df, prefix):
    fileless = df[df["run"].str.contains("fileless")][f"{prefix}_recovered"].tolist()
    return {
        "counts": fileless,
        "variance": max(fileless) - min(fileless) if fileless else 0,
        "consistent": len(set(fileless)) == 1 if fileless else False
    }

def export_csv(df, path=r"C:\Forensic\phase7_full_comparison.csv"):
    df.to_csv(path, index=False)
    print(f"[+] Saved comparison CSV to {path}")

def dashboard(df, summary, vol_rep, mem_rep):
    st.title("Memory Forensics Comparison Dashboard")

    st.subheader("Run-level Results")
    st.dataframe(df)

    summary_df = pd.DataFrame([
        {"Metric": "Mean detection accuracy (%)", "Volatility3": summary["vol_mean_accuracy"], "MemProcFS": summary["mem_mean_accuracy"]},
        {"Metric": "Mean false positives", "Volatility3": summary["vol_mean_fp"], "MemProcFS": summary["mem_mean_fp"]},
        {"Metric": "Mean analysis time (s)", "Volatility3": summary["vol_mean_time"], "MemProcFS": summary["mem_mean_time"]},
        {"Metric": "Analysis time std dev", "Volatility3": summary["vol_std_time"], "MemProcFS": summary["mem_std_time"]},
    ])
    st.subheader("Summary")
    st.dataframe(summary_df)
    st.bar_chart(summary_df.set_index("Metric"))

    st.subheader("Repeatability")
    st.write({"Volatility3": vol_rep, "MemProcFS": mem_rep})

df = build_comparison(vol_data, mem_data)
summary = summarise(df)
vol_rep = repeatability_check(df, "vol")
mem_rep = repeatability_check(df, "mem")

print(df)
print(summary)
print({"vol_repeatability": vol_rep, "mem_repeatability": mem_rep})

export_csv(df)
dashboard(df, summary, vol_rep, mem_rep)