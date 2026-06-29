"""Scenario 3 - auditors, regulators, insurers.

Months after an incident, can a third party who has never seen your systems
prove what your agents were authorized to do? Hand them one JSON file. With
Ed25519 the public key travels inside the bundle, so they validate the entire
history — chain integrity and every signature — with no database, no shared
secret, and no call back to any vendor.

This exports such a bundle to a temp file, re-reads it as an outside party
would, verifies it offline, then shows that a single edited field is caught.
"""
import json
import os
import tempfile

from _common import fresh_recorder, rule, step
from agentledger import PolicyGate
from agentledger.evidence import verify_bundle


def main() -> None:
    rule("OFFLINE EVIDENCE BUNDLE  -  one file an auditor can verify, no vendor")

    gate = PolicyGate(default_allow=True).deny(
        "wire-transfer", when=lambda d: d["params"].get("amount", 0) > 10000,
        reason="transfers over $10k need dual control", name="aml-threshold",
    )
    rec = fresh_recorder(gate=gate)

    step(1, "Produce the history an auditor will later ask about.")
    _, d1 = rec.submit("agent:treasury", "wire-transfer", {"amount": 2500, "to": "vendor-7"})
    rec.record_outcome(d1.seq, "agent:treasury", "success", {"confirmation": "WT-88120"})
    rec.submit("agent:treasury", "wire-transfer", {"amount": 50000, "to": "unknown"})  # denied
    print(f"   {len(rec.entries())} entries recorded "
          f"(signed with {rec.signer.algorithm}).")

    step(2, "Export a self-contained evidence bundle (the artifact you hand over).")
    path = os.path.join(tempfile.mkdtemp(prefix="agentledger_demo_"), "evidence.json")
    rec.export_evidence(path)
    size = os.path.getsize(path)
    print(f"   wrote {path}  ({size} bytes)")

    step(3, "Now act as the auditor: load the file standalone and verify it.")
    with open(path, "r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    print(f"   bundle format={bundle['format']!r}  algorithm={bundle['algorithm']!r}")
    print(f"   third_party_verifiable={bundle['third_party_verifiable']}  "
          f"entries={bundle['entry_count']}  head={bundle['head_hash'][:12]}...")
    ok, broken = verify_bundle(bundle)
    print(f"   verify_bundle() -> intact={ok}  first_broken_seq={broken}  (no key, no network)")

    step(4, "Someone tries to launder the $50k denial into an approval.")
    bundle["entries"][2]["decision"] = {"allowed": True, "rule": "aml-threshold", "reason": ""}
    ok, broken = verify_bundle(bundle)
    print(f"   verify_bundle() after the edit -> intact={ok}  first_broken_seq={broken}")
    print("\nThe bundle is evidence precisely because anyone can check it and a single")
    print("altered byte fails the check — independence is the whole point.")


if __name__ == "__main__":
    main()
