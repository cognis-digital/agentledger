# agentledger

**A vendor-neutral flight recorder for AI agents. Every operator directive: signed, hash-chained, policy-gated, and exportable as offline-verifiable evidence.**

The hard question in production AI isn't "does the model hallucinate." It's: *an agent did something — who authorized it, and can you prove it?* That's a question for your board, your auditor, and your insurer, and most agent stacks can't answer it.

`agentledger` answers it for **any** agent framework. It sits in front of your agents and writes down what happened, in a form that can't be quietly rewritten:

- **Signed directives.** Every operator instruction is signed — **Ed25519** when `cryptography` is installed (asymmetric, so anyone can verify origin), or **HMAC-SHA256** on the standard library alone.
- **Hash-chained ledger.** Each entry commits to the previous one. Reorder, edit, or delete any entry and the chain breaks at that point — `verify()` tells you exactly where.
- **Policy at the gate.** Directives pass a policy gate *before* being recorded as allowed, so "what was permitted, and under which rule" is part of the evidence — including denied attempts.
- **Offline evidence bundles.** Export the whole history to one JSON file a third party can validate with no database and no call back to any vendor.
- **Framework-agnostic and dependency-light.** It knows nothing about how your agents run. Pure standard library, with Ed25519 as an optional extra.

## Install

```bash
pip install -e .                  # HMAC signing, zero dependencies
pip install -e ".[ed25519]"       # adds Ed25519 (recommended)
```

## Use it around any agent

```python
from agentledger import Recorder, PolicyGate

# An operator policy: prod deploys need change-control; everything else is fine.
gate = PolicyGate(default_allow=True).deny(
    "deploy", when=lambda d: d["params"].get("env") == "prod",
    reason="prod deploys require change-control", name="no-prod-deploy",
)
rec = Recorder(gate=gate)

decision, entry = rec.submit("alice", "deploy", {"env": "prod"})
if decision.allowed:
    result = run_your_agent(...)
    rec.record_outcome(entry.seq, "agent:deployer", "success", {"build": 421})
else:
    print("blocked:", decision.reason)        # recorded either way

# Prove it
ok, broken = rec.verify()                       # chain + signatures
bundle = rec.export_evidence("evidence.json")   # hand this to an auditor
```

### See it work

```bash
python demo.py
```

```
signing algorithm: ed25519 (third-party verifiable offline: True)
[1] alice -> rotate-keys : default allowed=True
[3] mallory -> deploy(prod) : no-prod-deploy allowed=False (prod deploys require change-control)
== ledger integrity ==
  verify() -> intact=True first_broken=None
== evidence bundle (what you hand an auditor) ==
  offline verify_bundle() -> True  (3 entries, head 1fdaa035807b…)
== tamper attempt ==
  after editing entry 2: verify_bundle() -> intact=False first_broken=2
```

## How it fits together

| Component | Role |
|-----------|------|
| **`Recorder`** | The high-level API: `submit` a directive (gated + recorded), `record_outcome`, `verify`, `export_evidence`. |
| **`PolicyGate`** | Glob/predicate allow-deny rules, plus a `.use()` hook to delegate to an external doctrine (e.g. [`sentinel-policy`](https://github.com/cognis-digital/sentinel-policy)). |
| **`Ledger`** | The SQLite-backed, signed, hash-chained entry store. |
| **`Signer` / `Verifier`** | Pluggable backends: `Ed25519` (asymmetric, offline-verifiable) or `HMAC-SHA256` (stdlib). |
| **`evidence`** | `export()` to a self-contained bundle; `verify_bundle()` validates it standalone. |

### Why Ed25519 matters here

With Ed25519, the public key travels inside each entry and the evidence bundle. An auditor verifies the signatures with **only the bundle** — no shared secret, no live service. HMAC still gives you tamper-evidence, but checking signatures then requires the signing secret (the bundle declares `third_party_verifiable: false` so there's no ambiguity).

## Composition

`agentledger` records and proves; it doesn't try to be your whole governance doctrine. Point its policy gate at [`sentinel-policy`](https://github.com/cognis-digital/sentinel-policy) for a full rule set, and feed directives in front of agents on any framework.

## Testing

```bash
pip install -e ".[dev]"
pytest -q          # 23 tests
```

## License

Apache-2.0. © Cognis Digital.

> Status: v0.1 — runnable and tested. Roadmap: persistent signing keys + key rotation with continuity proofs, post-quantum signatures (ML-DSA) behind the same `Signer` interface, and an append-only syslog/SIEM sink.
