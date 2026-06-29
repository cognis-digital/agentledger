"""Smoke-test every demo scenario: it must import, run main(), and not raise.

The demos use the real public API, so running them here guarantees the README's
"Demos" section stays truthful as the code evolves.
"""
import importlib
import os
import sys

import pytest

DEMOS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demos")
sys.path.insert(0, DEMOS_DIR)

SCENARIOS = [
    "01_agent_flight_recorder",
    "02_tamper_evident_audit",
    "03_offline_evidence_bundle",
    "04_key_rotation_and_pqc",
    "05_threshold_and_siem",
]


@pytest.mark.parametrize("name", SCENARIOS)
def test_demo_runs(name, capsys):
    mod = importlib.import_module(name)
    mod.main()
    out = capsys.readouterr().out
    assert "verify" in out.lower()


def test_run_all_lists_every_scenario():
    run_all = importlib.import_module("run_all")
    assert run_all.SCENARIOS == SCENARIOS
