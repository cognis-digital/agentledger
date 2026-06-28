# agentledger

[![CI](https://github.com/cognis-digital/agentledger/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/agentledger/actions/workflows/ci.yml)

> Part of the **[Accountable AI Engineering suite](https://github.com/cognis-digital/accountable-ai-suite)** — provable governance for AI agents on infrastructure you own.

**A vendor-neutral flight recorder for AI agents. Every operator directive: signed, hash-chained, policy-gated, and exportable as offline-verifiable evidence.**

The hard question in production AI isn't "does the model hallucinate." It's: *an agent did something — who authorized it, and can you prove it?* That's a question for your board, your auditor, and your insurer, and most agent stacks can't answer it.

`agentledger` answers it for **any** agent framework. It sits in front of your agents and writes down what happened, in a form that can't be quietly rewritten:

- **Signed directives.** Every operator instruction is signed — **Ed25519** (asymmetric, anyone can verify origin), **HMAC-SHA256** on the standard library alone, or **post-quantum ML-DSA-65 (FIPS 204)** when you need signatures that survive a quantum adversary.
- **Hash-chained ledger.** Each entry commits to the previous one. Reorder, edit, or delete any entry and the chain breaks at that point — `verify()` tells you exactly where.
- **Policy at the gate.** Directives pass a policy gate *before* being recorded as allowed, so "what was permitted, and under which rule" is part of the evidence — including denied attempts.
- **Offline evidence bundles.** Export the whole history to one JSON file a third party can validate with no database and no call back to any vendor.
- **Framework-agnostic and dependency-light.** It knows nothing about how your agents run. Pure standard library, with Ed25519 as an optional extra.

## Install

```bash
pip install -e .                  # HMAC signing, zero dependencies
pip install -e ".[ed25519]"       # adds Ed25519 (recommended)
```

## Command line

```bash
agentledger keygen --algorithm ed25519 --out agent.key
agentledger submit --action deploy --actor alice --param env=prod --ledger l.db --key agent.key
agentledger outcome --ref 1 --actor agent:deployer --status success --ledger l.db --key agent.key
agentledger rotate --algorithm hybrid --out new.key --ledger l.db --key agent.key   # upgrade to PQC
agentledger verify --ledger l.db                       # chain + signatures + continuity
agentledger export --ledger l.db --out evidence.json
agentledger verify-bundle evidence.json                # offline, no key needed for ed25519/ml-dsa/hybrid
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

### Post-quantum signing (shipped, not roadmap)

Evidence you produce today may need to stay verifiable for years — long enough for "harvest now, verify later" to matter. Pick the **ML-DSA-65** backend (NIST FIPS 204) and the directive signatures become quantum-resistant, while everything else — the hash chain, the offline bundle, third-party verification — works identically:

```python
from agentledger import Recorder, PolicyGate
from agentledger.signing import new_signer

rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer(prefer="ml-dsa"))
# bundle["algorithm"] == "ml-dsa-65"; verify_bundle(bundle) still works offline
```

Available when your `cryptography` build includes ML-DSA; otherwise pick `ed25519` or `hmac`. For a conservative migration, `new_signer(prefer="hybrid")` signs with **both Ed25519 and ML-DSA-65** — a break in either algorithm alone can't forge a directive.

### Key lifecycle: persistence and rotation with continuity proofs

Keys outlive processes and need to be rotated. Both are first-class:

```python
from agentledger import Recorder, new_signer, save_key, load_key

save_key(signer, "agent.key");  signer = load_key("agent.key")   # persist / reload

rec = Recorder(signer=load_key("agent.key"))
rec.submit("alice", "deploy", {"env": "prod"})
rec.rotate_key(new_signer("hybrid"))      # upgrade to post-quantum, in place
rec.submit("alice", "deploy", {"env": "prod"})
ok, _ = rec.verify()                       # still valid across the rotation
```

Rotation isn't just "start using a new key." `rotate_key` writes a **`key_rotation` entry signed by the *outgoing* key** that names the incoming public key. Verification then enforces **continuity**: a new signing key is accepted only if the previous (already-authorized) key introduced it. An attacker who appends entries with their own key produces individually valid-looking signatures — but the chain rejects the key because nothing authorized it. That's the difference between "each entry is signed" and "the whole history descends from one root of trust."

## Composition

`agentledger` records and proves; it doesn't try to be your whole governance doctrine. Point its policy gate at [`sentinel-policy`](https://github.com/cognis-digital/sentinel-policy) for a full rule set, and feed directives in front of agents on any framework.

## Testing

```bash
pip install -e ".[dev]"
pytest -q          # 35 tests
```

## License

Apache-2.0. © Cognis Digital.

> Status: v0.1 — runnable and tested. Shipped: post-quantum ML-DSA-65 signing, hybrid Ed25519+ML-DSA signatures, persistent keys, key rotation with continuity proofs, and a CLI. Roadmap: an append-only syslog/SIEM sink and threshold (m-of-n) operator approval.
