"""
ground_truth.py
===============
Defines expected forensic artefacts per scenario with
multi-level evidence for robust evaluation.
"""

from dataclasses import dataclass
from typing import List, Dict


# ─────────────────────────────────────────────
# DATA STRUCTURE
# ─────────────────────────────────────────────
@dataclass
class ArtefactSpec:
    artefact_id: str
    artefact_type: str
    description: str

    # where we expect to find it
    expected_plugins: List[str]

    # STRONG indicators (high confidence)
    strong_keywords: List[str]

    # WEAK indicators (contextual support)
    weak_keywords: List[str]

    # Optional MITRE mapping
    mitre_technique: str = ""

    # Explanation (for report use)
    notes: str = ""


# ─────────────────────────────────────────────
# GROUND TRUTH
# ─────────────────────────────────────────────
GROUND_TRUTH: Dict = {

    # ─────────────────────────────────────────
    # BENIGN SCENARIOS
    # ─────────────────────────────────────────
    "benign_run1": {
        "scenario_type": "benign",
        "description": "Normal system idle + basic applications.",
        "expected_artefacts": []
    },

    "benign_run2": {
        "scenario_type": "benign",
        "description": "Notepad typing + browser usage.",
        "expected_artefacts": []
    },

    "benign_run3": {
        "scenario_type": "benign",
        "description": "Python script performing file I/O operations.",
        "expected_artefacts": []
    },


    # ─────────────────────────────────────────
    # FILELESS SCENARIO 1 — ENCODED POWERSHELL
    # ─────────────────────────────────────────
    "fileless_run1": {
        "scenario_type": "fileless",
        "description": "Base64-encoded PowerShell execution.",
        "technique": "T1059.001",

        "expected_artefacts": [

            ArtefactSpec(
                artefact_id="FA-01",
                artefact_type="EncodedCommand",
                description="Encoded PowerShell command in process cmdline",

                expected_plugins=["windows.cmdline"],

                strong_keywords=[
                    "-encodedcommand",
                    "-enc",
                ],

                weak_keywords=[
                    "powershell",
                ],

                mitre_technique="T1059.001",

                notes="Primary detection vector for encoded execution"
            ),

            ArtefactSpec(
                artefact_id="FA-02",
                artefact_type="SuspiciousProcess",
                description="Presence of PowerShell process executing payload",

                expected_plugins=["windows.pslist", "windows.pstree"],

                strong_keywords=[
                    "powershell.exe"
                ],

                weak_keywords=[],

                notes="Used to confirm execution context"
            ),

            ArtefactSpec(
                artefact_id="FA-03",
                artefact_type="MemoryExecution",
                description="Executable memory region consistent with script execution",

                expected_plugins=["windows.malfind", "windows.vadinfo"],

                strong_keywords=[
                    "execute",
                ],

                weak_keywords=[
                    "private",
                    "write"
                ],

                notes="May not always appear depending on payload"
            )
        ]
    },


    # ─────────────────────────────────────────
    # FILELESS SCENARIO 2 — WMI EXECUTION
    # ─────────────────────────────────────────
    "fileless_run2": {
        "scenario_type": "fileless",
        "description": "WMI-based remote execution spawning process.",
        "technique": "T1047",

        "expected_artefacts": [

            ArtefactSpec(
                artefact_id="FA-04",
                artefact_type="WMIProcess",
                description="WmiPrvSE spawning process",

                expected_plugins=["windows.pstree"],

                strong_keywords=[
                    "wmiprvse"
                ],

                weak_keywords=[],

                mitre_technique="T1047",

                notes="Key parent process in WMI execution"
            ),

            ArtefactSpec(
                artefact_id="FA-05",
                artefact_type="WMICommand",
                description="WMI execution command in cmdline",

                expected_plugins=["windows.cmdline"],

                strong_keywords=[
                    "invoke-wmimethod",
                    "wmic"
                ],

                weak_keywords=[
                    "invoke-"
                ],

                notes="Command-level evidence"
            ),

            ArtefactSpec(
                artefact_id="FA-06",
                artefact_type="ProcessAnomaly",
                description="Unexpected process chain or execution path",

                expected_plugins=["windows.pstree"],

                strong_keywords=[],

                weak_keywords=[
                    "cmd.exe",
                    "powershell"
                ],

                notes="Used as supporting context"
            )
        ]
    },


    # ─────────────────────────────────────────
    # FILELESS SCENARIO 3 — REFLECTIVE INJECTION
    # ─────────────────────────────────────────
    "fileless_run3": {
        "scenario_type": "fileless",
        "description": "Reflective in-memory injection via PowerShell.",
        "technique": "T1620",

        "expected_artefacts": [

            ArtefactSpec(
                artefact_id="FA-07",
                artefact_type="ReflectiveInjection",
                description="Indicators of in-memory .NET / reflective loading",

                expected_plugins=["windows.cmdline"],

                strong_keywords=[
                    "reflection",
                    "assembly"
                ],

                weak_keywords=[
                    "add-type"
                ],

                mitre_technique="T1620",

                notes="Primary behavioural indicator"
            ),

            ArtefactSpec(
                artefact_id="FA-08",
                artefact_type="InjectedMemory",
                description="Memory region with PE header (MZ)",

                expected_plugins=["windows.malfind"],

                strong_keywords=[
                    "mz"
                ],

                weak_keywords=[],

                notes="Classic injection signature"
            ),

            ArtefactSpec(
                artefact_id="FA-09",
                artefact_type="ExecutableVAD",
                description="Private executable memory region",

                expected_plugins=["windows.vadinfo"],

                strong_keywords=[
                    "execute"
                ],

                weak_keywords=[
                    "private"
                ],

                notes="Supports injection detection"
            )
        ]
    }
}


# ─────────────────────────────────────────────
# OPTIONAL: PRETTY PRINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("GROUND TRUTH SCENARIOS (ENHANCED)")
    print("=" * 60)

    for scenario, data in GROUND_TRUTH.items():
        print(f"\nScenario: {scenario}")
        print(f"Type: {data['scenario_type']}")
        print(f"Description: {data['description']}")

        if "technique" in data:
            print(f"MITRE Technique: {data['technique']}")

        artefacts = data["expected_artefacts"]

        if not artefacts:
            print("Expected Artefacts: None (Benign)")
        else:
            print("Expected Artefacts:")
            for art in artefacts:
                print(f"  [{art.artefact_id}] {art.artefact_type}")
                print(f"     Plugins        : {', '.join(art.expected_plugins)}")
                print(f"     Strong keywords: {', '.join(art.strong_keywords)}")
                print(f"     Weak keywords  : {', '.join(art.weak_keywords)}")

    print("\n" + "=" * 60)
    print("DONE")