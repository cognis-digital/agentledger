# Demos

Five runnable scenarios live in [`../demos/`](../demos/), each aimed at a
different audience and exercising the **real** public API. Every scenario builds
its own in-memory ledger, needs no network, and prints clear narrated output —
so they double as smoke tests (`tests/test_demos.py` runs all five under
`pytest`).

```bash
python demos/run_all.py                  # all five, end to end
python demos/03_offline_evidence_bundle.py   # or just one
```

> On Windows, run with `PYTHONUTF8=1` set (the consoles default to cp1252). The
> demos also self-configure UTF-8 output, so a direct run won't crash on the box
> characters either way.

## The scenarios

| # | Demo | Audience | What it shows |
|---|------|----------|---------------|
| 1 | [`01_agent_flight_recorder.py`](../demos/01_agent_flight_recorder.py) | AI-agent builders | Wrap any agent: gate a directive, run the agent on allow, record the outcome — and record the *denied* directive too. The agent framework is untouched. |
| 2 | [`02_tamper_evident_audit.py`](../demos/02_tamper_evident_audit.py) | Security & compliance | Edit one row directly in SQLite (bypassing the signed API) and watch `verify()` catch it and report the exact sequence where history was altered. |
| 3 | [`03_offline_evidence_bundle.py`](../demos/03_offline_evidence_bundle.py) | Auditors / regulators / insurers | Export a self-contained evidence bundle, re-load it as an outside party, verify it offline with no key and no network — then show a single edited field failing the check. |
| 4 | [`04_key_rotation_and_pqc.py`](../demos/04_key_rotation_and_pqc.py) | Platform & security engineers | Rotate a live ledger from Ed25519 to post-quantum ML-DSA-65 in place; verification holds across the boundary, and an entry signed with an *unauthorized* key is rejected by continuity. |
| 5 | [`05_threshold_and_siem.py`](../demos/05_threshold_and_siem.py) | SRE / platform operations | Require two distinct operators to sign off (m-of-n, duplicate key counts once) before a prod migration is authorized, while forwarding the whole feed to a SIEM sink in real time. |

---

Each demo prints narrated output and exits 0, so they double as living
documentation: if the public API changes, the demo run (and the matching
`pytest`) breaks immediately.
