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
    "06_denied_directive_trail",
    "07_persistent_ledger",
    "08_external_doctrine_gate",
    "09_hmac_offline_only",
    "10_outcome_correlation",
    "11_jsonl_siem_feed",
    "12_tamper_after_export",
    "13_hybrid_pqc_migration",
    "14_approval_allowlist",
    "15_multi_agent_pipeline",
    "16_independent_verifier",
    "17_key_compromise_response",
    "18_callable_sink_alerting",
    "19_cross_algorithm_audit",
    "20_cli_walkthrough",
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
