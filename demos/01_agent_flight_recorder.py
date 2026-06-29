"""Scenario 1 - AI agent builders.

You're wrapping an autonomous agent. Before it acts you want a signed record of
*what it was told to do* and *whether policy allowed it*; after it acts you want
a signed record of *what happened*. agentledger sits in front of the agent and
writes both down — and it knows nothing about how your agent runs.

This plays the recorder's side of a real agent loop: an allowed directive that
the agent executes, and a denied directive that never should. Both land in the
same signed, hash-chained ledger.
"""
from _common import fresh_recorder, rule, step
from agentledger import PolicyGate


def run_your_agent(action: str, params: dict) -> dict:
    """Stand-in for whatever framework actually drives the agent."""
    return {"action": action, "ran": True, "artifacts": 1}


def main() -> None:
    rule("AGENT FLIGHT RECORDER  -  gate, act, record, around any agent")

    # An operator policy the agent runs under: prod deploys need change-control.
    gate = PolicyGate(default_allow=True).deny(
        "deploy", when=lambda d: d["params"].get("env") == "prod",
        reason="prod deploys require change-control", name="no-prod-deploy",
    )
    rec = fresh_recorder(gate=gate)
    print(f"\nSigning backend: {rec.signer.algorithm} "
          f"(verifiable offline by a third party: {rec.signer.third_party_verifiable})")
    print("The recorder wraps the agent; the agent framework stays untouched.")

    step(1, "Operator directive: summarize the incident channel.")
    decision, directive = rec.submit("alice", "summarize",
                                     {"channel": "#incident-42", "max_tokens": 800})
    print(f"   submit() -> seq={directive.seq}  rule={decision.rule!r}  allowed={decision.allowed}")
    if decision.allowed:
        result = run_your_agent(directive.action, directive.params)
        outcome = rec.record_outcome(directive.seq, "agent:summarizer", "success", result)
        print(f"   agent ran -> outcome seq={outcome.seq} refs directive {outcome.ref}")

    step(2, "Operator directive: deploy to prod (this one should be stopped).")
    decision, blocked = rec.submit("mallory", "deploy", {"env": "prod", "service": "billing"})
    print(f"   submit() -> seq={blocked.seq}  rule={decision.rule!r}  allowed={decision.allowed}")
    print(f"   reason recorded: {decision.reason!r}")
    print("   NOTE: the agent is NOT run, but the blocked attempt is still on the record.")

    step(3, "The whole loop, as the signed ledger now sees it:")
    for e in rec.entries():
        tag = "ALLOW" if (e.kind != "directive" or e.decision.get("allowed")) else "DENY "
        ref = f" (re: #{e.ref})" if e.ref else ""
        print(f"   #{e.seq} [{tag}] {e.kind:<9} {e.actor:<16} {e.action}{ref}")

    ok, broken = rec.verify()
    print(f"\nverify() -> intact={ok}  first_broken_seq={broken}")
    print("Every directive AND every refusal is now a signed, ordered fact you own.")


if __name__ == "__main__":
    main()
