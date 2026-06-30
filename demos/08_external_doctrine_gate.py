"""Scenario 8 - security architects integrating an org-wide doctrine.

agentledger's gate is deliberately small. The real value is that you can
delegate the decision to an external evaluator (a full policy engine, an OPA
sidecar, a `sentinel-policy` doctrine) and still get the decision recorded as
part of the evidence. The first external evaluator to return a Decision wins.

This wires a toy "doctrine" function in front of local glob rules and shows the
precedence order, then verifies the recorded decisions.
"""
from _common import fresh_recorder, rule, step
from agentledger import PolicyGate
from agentledger.policy import Decision


def main() -> None:
    rule("EXTERNAL DOCTRINE GATE  -  delegate the decision, keep the evidence")

    # Pretend this calls out to a central policy service / OPA / sentinel-policy.
    def doctrine(directive: dict):
        action = directive["action"]
        if action.startswith("payment") and directive["params"].get("amount", 0) > 1000:
            return Decision(False, "doctrine:payment-cap",
                            "payments over $1000 require human sign-off")
        if action == "rotate-secrets":
            return Decision(True, "doctrine:rotate-ok", "secret rotation always allowed")
        return None  # no opinion -> fall through to local rules

    gate = (PolicyGate(default_allow=True)
            .use(doctrine)
            .deny("payment.*", reason="local default: payments gated", name="local-payment"))
    rec = fresh_recorder(gate=gate)

    cases = [
        ("agent:fin", "payment.send", {"amount": 50}),     # doctrine None -> local deny
        ("agent:fin", "payment.send", {"amount": 5000}),   # doctrine deny (cap)
        ("agent:sec", "rotate-secrets", {}),               # doctrine allow (overrides)
        ("agent:ops", "read", {"what": "status"}),         # no rule -> default allow
    ]
    step(1, "Submit directives; watch which layer decided each.")
    for actor, action, params in cases:
        d, e = rec.submit(actor, action, params)
        tag = "ALLOW" if d.allowed else "DENY "
        print(f"   #{e.seq} [{tag}] {action:<16} decided by {d.rule!r}")

    step(2, "The deciding rule is recorded with each directive.")
    for e in rec.entries():
        print(f"     #{e.seq} {e.action:<16} -> rule={e.decision['rule']!r}")

    ok, broken = rec.verify()
    print(f"\nverify() -> intact={ok}. Who-decided-what is part of the signed record.")


if __name__ == "__main__":
    main()
