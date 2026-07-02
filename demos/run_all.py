"""Run every demo scenario end to end.

    python demos/run_all.py

Each scenario is self-contained, builds its own in-memory ledger, and needs no
network, so they can be run in any order or on their own. They double as smoke
tests: every one prints narrated output and exits 0.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SCENARIOS = [
    "01_agent_flight_recorder",
    "02_tamper_evident_audit",
    "03_offline_evidence_bundle",
    "04_key_rotation_and_pqc",
    "05_threshold_and_siem",
    "06_query_the_ledger",
    "07_merkle_inclusion_proof",
    "08_exporters_for_tooling",
    "09_retention_and_checkpoint",
]


def main() -> None:
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        mod.main()
    print("\n" + "=" * 70)
    print("  All demo scenarios completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
