#!/usr/bin/env python3
"""End-to-end demo: gate two directives, record outcomes, export an evidence
bundle, verify it offline, then show that tampering is caught.

    python demo.py
"""

import json

from agentledger import PolicyGate, Recorder
from agentledger.evidence import verify_bundle


def main() -> None:
    # An operator policy: prod deploys are denied; everything else allowed.
    gate = (
        PolicyGate(default_allow=True)
        .deny("deploy", when=lambda d: d["params"].get("env") == "prod",
              reason="prod deploys require change-control", name="no-prod-deploy")
    )
    rec = Recorder(gate=gate)
    print(f"signing algorithm: {rec.signer.algorithm} "
          f"(third-party verifiable offline: {rec.signer.third_party_verifiable})\n")

    # 1) an allowed directive + its outcome
    decision, entry = rec.submit("alice", "rotate-keys", {"scope": "ci"})
    print(f"[{entry.seq}] alice -> rotate-keys : {decision.rule} allowed={decision.allowed}")
    rec.record_outcome(entry.seq, "agent:ops", "success", {"rotated": 4})

    # 2) a denied directive — recorded anyway, with the reason
    decision, entry = rec.submit("mallory", "deploy", {"env": "prod"})
    print(f"[{entry.seq}] mallory -> deploy(prod) : {decision.rule} "
          f"allowed={decision.allowed} ({decision.reason})")

    print("\n== ledger integrity ==")
    ok, broken = rec.verify()
    print(f"  verify() -> intact={ok} first_broken={broken}")

    print("\n== evidence bundle (what you hand an auditor) ==")
    bundle = rec.export_evidence()
    ok, _ = verify_bundle(bundle)
    print(f"  offline verify_bundle() -> {ok}  ({bundle['entry_count']} entries, "
          f"head {bundle['head_hash'][:12]}…)")

    print("\n== tamper attempt ==")
    bundle["entries"][1]["params"] = {"env": "dev"}  # try to rewrite history
    ok, broken = verify_bundle(bundle)
    print(f"  after editing entry 2: verify_bundle() -> intact={ok} first_broken={broken}")


if __name__ == "__main__":
    main()
