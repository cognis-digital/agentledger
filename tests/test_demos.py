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

# the canonical list lives in run_all.py; sourcing it here keeps the two in sync
SCENARIOS = importlib.import_module("run_all").SCENARIOS


@pytest.mark.parametrize("name", SCENARIOS)
def test_demo_runs(name, capsys):
    mod = importlib.import_module(name)
    mod.main()
    out = capsys.readouterr().out
    assert "verify" in out.lower()


def test_demo_files_match_scenarios():
    # every listed scenario has a matching file, and vice versa
    on_disk = {f[:-3] for f in os.listdir(DEMOS_DIR)
               if f[0].isdigit() and f.endswith(".py")}
    assert set(SCENARIOS) == on_disk


def test_every_demo_exits_cleanly(capsys):
    # smoke: importing+running each main() must not raise
    for name in SCENARIOS:
        importlib.import_module(name).main()
        capsys.readouterr()
