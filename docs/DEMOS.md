# Demos

Nine runnable scenarios live in [`../demos/`](../demos/), each aimed at a
different audience and exercising the **real** public API. Every scenario builds
its own in-memory ledger, needs no network, and prints clear narrated output —
so they double as smoke tests (`tests/test_demos.py` runs all nine under
`pytest`).

```bash
python demos/run_all.py                  # all nine, end to end
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
| 6 | [`06_query_the_ledger.py`](../demos/06_query_the_ledger.py) | Auditors / on-call | Read an already-trusted, append-only ledger with a chainable, read-only `Query`: every denied directive, one actor's actions, a directive's outcomes, and a one-line aggregate — without mutating the chain. |
| 7 | [`07_merkle_inclusion_proof.py`](../demos/07_merkle_inclusion_proof.py) | Compliance / privacy | Publish a single Merkle root, then produce an O(log n) inclusion proof for one entry that verifies against the root without revealing the other entries; a forged entry hash can't reproduce the root. |
| 8 | [`08_exporters_for_tooling.py`](../demos/08_exporters_for_tooling.py) | Platform / DevSecOps | Project the ledger into the formats other tools speak: SARIF 2.1.0 (denials as CI results), OpenTelemetry OTLP/JSON spans, CSV/JSONL, and a signed, self-contained HTML attestation report that verifies offline. |
| 9 | [`09_retention_and_checkpoint.py`](../demos/09_retention_and_checkpoint.py) | Data governance | Seal an old prefix into a signed evidence-bundle archive plus a signed checkpoint (archived head hash + Merkle root); the live tail is untouched and any single archived entry stays provable against the checkpoint root. |

---

Each demo prints narrated output and exits 0, so they double as living
documentation: if the public API changes, the demo run (and the matching
`pytest`) breaks immediately.
