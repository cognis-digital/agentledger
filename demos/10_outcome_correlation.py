"""Scenario 10 - incident responders reconstructing what an agent did.

Every directive can have one or more outcomes referencing it. Long after the
fact you want to walk the ledger and answer "this directive was issued -- what
actually happened?" by following the ref links.

This records a directive with a retry (two outcomes: a failure then a success)
and reconstructs the full story from the signed chain.
"""
from _common import fresh_recorder, rule, step
from agentledger import PolicyGate


def main() -> None:
    rule("OUTCOME CORRELATION  -  follow ref links to reconstruct the story")

    rec = fresh_recorder(gate=PolicyGate(default_allow=True))

    step(1, "An operator directs a deploy; the agent fails, retries, succeeds.")
    _, directive = rec.submit("alice", "deploy", {"service": "billing", "version": "1.4.2"})
    rec.record_outcome(directive.seq, "agent:deployer", "failure",
                       {"error": "image pull backoff", "attempt": 1})
    rec.record_outcome(directive.seq, "agent:deployer", "success",
                       {"attempt": 2, "pods": 6})
    # an unrelated directive, to prove correlation is by ref, not by time
    rec.submit("bob", "read", {"what": "logs"})

    step(2, "Reconstruct: directive -> all outcomes that reference it.")
    outcomes = rec.ledger.entries_referencing(directive.seq, kind="outcome")
    print(f"   directive #{directive.seq}: {directive.action} {directive.params}")
    for o in outcomes:
        print(f"     -> #{o.seq} {o.action:<8} by {o.actor}: {o.params}")
    print(f"   {len(outcomes)} outcome(s) correlated to directive #{directive.seq}.")

    step(3, "The unrelated directive has no outcomes referencing it.")
    other = [e for e in rec.entries() if e.action == "read"][0]
    print(f"   directive #{other.seq} ({other.action}) -> "
          f"{len(rec.ledger.entries_referencing(other.seq, kind='outcome'))} outcomes")

    ok, broken = rec.verify()
    print(f"\nverify() -> intact={ok}. The cause-and-effect trail is signed and ordered.")


if __name__ == "__main__":
    main()
