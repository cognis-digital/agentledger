"""Scenario 6 - governance / risk.

A refusal is evidence too. When an agent is *told* to do something dangerous and
policy stops it, the attempt and the rule that stopped it should be on the
permanent record — so "we blocked that" is provable, not a claim.

This submits a batch of directives against a layered policy (a glob deny, a
predicate deny, an external doctrine) and shows the allow/deny trail, including
every refusal, landing in the same signed chain.
"""
from _common import fresh_recorder, rule, step
from agentledger import PolicyGate
from agentledger.policy import Decision


def org_doctrine(directive: dict):
    if directive["action"] == "exfiltrate":
        return Decision(False, "doctrine:no-exfil", "exfiltration is never permitted")
    return None


def main() -> None:
    rule("DENIED-DIRECTIVE TRAIL  -  every refusal is a signed fact")

    gate = (PolicyGate(default_allow=True)
            .use(org_doctrine)
            .deny("delete.*", reason="destructive ops gated", name="no-delete")
            .deny("deploy", when=lambda d: d["params"].get("env") == "prod",
                  reason="prod needs change-control", name="no-prod-deploy"))
    rec = fresh_recorder(gate=gate)

    step(1, "An agent is fed a batch of directives; some are dangerous.")
    batch = [
        ("alice", "read", {"table": "metrics"}),
        ("agent", "deploy", {"env": "staging"}),
        ("agent", "deploy", {"env": "prod"}),          # denied: predicate
        ("mallory", "delete.table", {"name": "audit"}),  # denied: glob
        ("mallory", "exfiltrate", {"to": "evil.example"}),  # denied: doctrine
    ]
    for actor, action, params in batch:
        d, e = rec.submit(actor, action, params)
        tag = "ALLOW" if d.allowed else "DENY "
        print(f"   #{e.seq} [{tag}] {actor:<8} {action:<14} rule={d.rule!r}")

    step(2, "Count what was refused, straight from the signed ledger.")
    denials = [e for e in rec.entries() if not e.decision.get("allowed", True)]
    print(f"   {len(denials)} of {len(rec.entries())} directives were denied:")
    for e in denials:
        print(f"     - {e.action!r} blocked by {e.decision['rule']!r}: {e.decision['reason']}")

    ok, broken = rec.verify()
    print(f"\nverify() -> intact={ok}  first_broken_seq={broken}")
    print("The refusals can't be quietly dropped later -- they're in the chain.")


if __name__ == "__main__":
    main()
