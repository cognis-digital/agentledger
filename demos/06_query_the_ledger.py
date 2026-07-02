"""Scenario 6 - reading an already-trusted ledger.

Integrity (chain + signatures) tells you the record wasn't altered. But an
auditor's next question is always "show me the interesting parts": every denied
directive, everything one actor did, the outcomes for a directive, a window of
time. `Query` is a small, chainable, read-only view that answers those without
re-implementing filters or risking an off-by-one on the time window. It never
mutates the ledger.
"""
from _common import fresh_recorder, rule, step
from agentledger import PolicyGate
from agentledger.query import Query


def main() -> None:
    rule("QUERY / FILTER  -  ask questions of a trusted, append-only ledger")

    gate = PolicyGate(default_allow=True).deny(
        "delete-*", reason="destructive; needs a change ticket", name="deny:delete")
    rec = fresh_recorder(gate=gate)

    step(1, "Record a mix of directives (some denied) and outcomes.")
    _, d1 = rec.submit("alice", "deploy", {"env": "prod"})
    rec.record_outcome(d1.seq, "agent:deployer", "success", {"build": 421})
    rec.submit("bob", "delete-bucket", {"bucket": "prod-data"})   # denied
    _, d3 = rec.submit("alice", "deploy", {"env": "staging"})
    rec.record_outcome(d3.seq, "agent:deployer", "failed", {"err": "timeout"})
    rec.submit("carol", "delete-user", {"id": 7})                 # denied
    print(f"   {len(rec.entries())} entries recorded.")

    q = Query(rec.ledger)

    step(2, "Every DENIED directive (what policy stopped):")
    for e in q.denied():
        print(f"   -> seq={e.seq} {e.actor} tried '{e.action}' "
              f"(rule={e.decision['rule']})")

    step(3, "Everything one actor did:")
    for e in q.actor("alice"):
        print(f"   -> seq={e.seq} {e.kind}:{e.action}")

    step(4, "The outcomes recorded against directive seq={}:".format(d1.seq))
    for e in q.refers_to(d1.seq):
        print(f"   -> {e.action} {e.params}")

    step(5, "A one-line aggregate for the report header:")
    summary = q.summary()
    for k, v in summary.items():
        print(f"   {k:<20} {v}")

    print("\nQuery is read-only: the signed chain is untouched by any of this.")
    ok, _ = rec.verify()
    print(f"verify() -> intact={ok}")


if __name__ == "__main__":
    main()
