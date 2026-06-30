# Demos

Twenty runnable scenarios live in [`../demos/`](../demos/), each aimed at a
real audience and exercising the **real** public API. Every scenario builds its
own ledger (in-memory unless it explicitly writes to a temp file), needs no
network, and prints clear narrated output — so they double as smoke tests
(`tests/test_demos.py` runs all of them under `pytest`).

```bash
python demos/run_all.py                       # all twenty, end to end
python demos/03_offline_evidence_bundle.py    # or just one
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
| 6 | [`06_denied_directive_trail.py`](../demos/06_denied_directive_trail.py) | Governance / risk | A batch of directives against a layered policy (glob deny, predicate deny, external doctrine); every refusal — and the rule that caused it — lands in the same signed chain. |
| 7 | [`07_persistent_ledger.py`](../demos/07_persistent_ledger.py) | Operators of long-lived services | Write to a SQLite file, "restart the process", reopen the same file with the same key, append more, and verify one unbroken chain across the restart. |
| 8 | [`08_external_doctrine_gate.py`](../demos/08_external_doctrine_gate.py) | Security architects | Delegate the decision to an external evaluator (OPA / a central policy service / `sentinel-policy`) while still recording *who decided what* as part of the evidence. |
| 9 | [`09_hmac_offline_only.py`](../demos/09_hmac_offline_only.py) | Air-gapped / stdlib-only deployments | Run with no dependencies via HMAC-SHA256; the chain validates offline without the secret, signatures validate with it, a wrong secret is rejected — and the bundle honestly says it isn't third-party verifiable. |
| 10 | [`10_outcome_correlation.py`](../demos/10_outcome_correlation.py) | Incident responders | A directive with a failed-then-succeeded retry; reconstruct the whole story by following `ref` links from directive to its outcomes. |
| 11 | [`11_jsonl_siem_feed.py`](../demos/11_jsonl_siem_feed.py) | SOC engineers | Attach a `JSONLinesSink`, record activity, then tail the file back as a log shipper would and confirm it mirrors the signed ledger exactly. |
| 12 | [`12_tamper_after_export.py`](../demos/12_tamper_after_export.py) | Auditors | Every category of bundle tampering — edit, delete, reorder, insert, flip a signature, hand it garbage — each rejected by `verify_bundle()` without ever crashing on malformed input. |
| 13 | [`13_hybrid_pqc_migration.py`](../demos/13_hybrid_pqc_migration.py) | Crypto-agility planners | Sign with Ed25519 **and** ML-DSA-65 at once (a break in either alone can't forge a directive); degrades honestly to the available backend with an identical API. |
| 14 | [`14_approval_allowlist.py`](../demos/14_approval_allowlist.py) | Controls / separation-of-duties | m-of-n approval restricted to an allowlist of authorized approver keys: an outsider's valid-but-unauthorized signature is ignored, a duplicate counts once. |
| 15 | [`15_multi_agent_pipeline.py`](../demos/15_multi_agent_pipeline.py) | Orchestrators | A plan → build → review → publish pipeline recorded as one signed chain across agent boundaries, including a blocked premature publish. |
| 16 | [`16_independent_verifier.py`](../demos/16_independent_verifier.py) | Regulators who won't install your software | A verifier re-implemented from scratch with only the standard library + the public Ed25519 primitive, proving the bundle's independence is real. |
| 17 | [`17_key_compromise_response.py`](../demos/17_key_compromise_response.py) | Incident response | Respond to a suspected key compromise by rotating with a continuity proof; a rogue append under a never-authorized key is rejected even though its signature is valid in isolation. |
| 18 | [`18_callable_sink_alerting.py`](../demos/18_callable_sink_alerting.py) | Detection engineers | Inline detection: a `CallableSink` raises alerts on denied directives and high-value transfers in real time, while a deliberately broken sink proves recording is never blocked. |
| 19 | [`19_cross_algorithm_audit.py`](../demos/19_cross_algorithm_audit.py) | Long-lived audit | A ledger spanning multiple algorithms across rotations exports a bundle that still verifies offline — selecting a verifier *per entry* (the exact path that surfaced and fixed a real verifier bug). |
| 20 | [`20_cli_walkthrough.py`](../demos/20_cli_walkthrough.py) | Shell / CI users | The full lifecycle driven through the `agentledger` CLI in-process — keygen, submit, outcome, rotate, verify, export, verify-bundle — with exit codes asserted. |

---

Each demo prints narrated output and exits 0, so they double as living
documentation: if the public API changes, the demo run (and the matching
`pytest`) breaks immediately.
