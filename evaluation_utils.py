"""
evaluation_utils.py
==================
Handles:
- keyword matching
- ground truth evaluation
- metric computation
"""

from typing import Dict, List, Any


# ─────────────────────────────────────────────
# NORMALISE TEXT
# ─────────────────────────────────────────────
def normalise_text(text: str) -> str:
    return text.lower() if text else ""


# ─────────────────────────────────────────────
# KEYWORD MATCHING
# ─────────────────────────────────────────────
def match_keywords(text: str, keywords: List[str]) -> List[str]:
    text = normalise_text(text)
    matches = []

    for kw in keywords:
        if kw.lower() in text:
            matches.append(kw)

    return matches


# ─────────────────────────────────────────────
# GROUND TRUTH EVALUATION
# ─────────────────────────────────────────────
def evaluate_scenario_against_ground_truth(
    label: str,
    evidence_by_plugin: Dict[str, str],
    ground_truth: Dict[str, Any]
) -> Dict[str, Any]:

    scenario = ground_truth[label]
    expected = scenario["expected_artefacts"]

    recovered = []
    missed = []

    for artefact in expected:

        matched_keywords = []

        # ✅ check across ALL expected plugins
        for plugin_name in artefact.expected_plugins:
            plugin_output = evidence_by_plugin.get(plugin_name, "")

            matches = match_keywords(
                plugin_output,
                artefact.strong_keywords + artefact.weak_keywords
            )

            if matches:
                matched_keywords.extend(matches)

        result = {
            "artefact_id": artefact.artefact_id,
            "artefact_type": artefact.artefact_type,
            "description": artefact.description,
            "expected_plugins": artefact.expected_plugins,
            "expected_keywords": artefact.strong_keywords + artefact.weak_keywords,
            "matched_keywords": list(set(matched_keywords)),
            "matched": len(matched_keywords) > 0,
        }

        if result["matched"]:
            recovered.append(result)
        else:
            missed.append(result)

    return {
        "scenario_type": scenario["scenario_type"],
        "expected_count": len(expected),
        "recovered_count": len(recovered),
        "missed_count": len(missed),
        "recovered": recovered,
        "missed": missed,
    }


# ─────────────────────────────────────────────
# METRIC COMPUTATION
# ─────────────────────────────────────────────
def compute_metrics_for_run(
    label: str,
    scenario_eval: Dict[str, Any],
    false_positive_count: int
) -> Dict[str, Any]:

    expected = scenario_eval["expected_count"]
    recovered = scenario_eval["recovered_count"]

    if expected == 0:
        # BENIGN CASE
        precision = 1.0 if false_positive_count == 0 else 0.0
        recall = None
        detection_accuracy = 100.0 if false_positive_count == 0 else 0.0
    else:
        precision = recovered / max(recovered + false_positive_count, 1)
        recall = recovered / expected
        detection_accuracy = recall * 100.0

    return {
        "label": label,
        "expected_artefacts": expected,
        "recovered_artefacts": recovered,
        "missed_artefacts": scenario_eval["missed_count"],
        "false_positive_count": false_positive_count,
        "precision": round(precision, 3) if precision is not None else None,
        "recall": round(recall, 3) if recall is not None else None,
        "detection_accuracy_pct": round(detection_accuracy, 2),
    }