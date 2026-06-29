"""Scenario 2 - security & compliance.

"If someone edited the audit log, would you know — or just hope?" This demo
shows the hash chain doing its one job: record a few directives, verify the
chain, then reach *past* the API and rewrite a row directly in the database
(the move an insider or a compromised host would make) — and watch verify()
catch it and report the exact sequence where the history was altered.
"""
from _common import fresh_recorder, rule, step
from agentledger import PolicyGate


def main() -> None:
    rule("TAMPER-EVIDENT AUDIT  -  edit one row, the chain breaks there")

    gate = PolicyGate(default_allow=True).deny(
        "delete", when=lambda d: d["params"].get("scope") == "all",
        reason="bulk delete forbidden", name="no-bulk-delete",
    )
    rec = fresh_recorder(gate=gate)

    step(1, "Record a normal sequence of agent activity.")
    decisions = [
        ("alice", "read", {"table": "customers"}),
        ("agent:etl", "transform", {"rows": 12000}),
        ("mallory", "delete", {"scope": "all"}),     # denied, but recorded
        ("alice", "export", {"dest": "s3://reports"}),
    ]
    for actor, action, params in decisions:
        d, e = rec.submit(actor, action, params)
        print(f"   #{e.seq} {actor:<10} {action:<10} allowed={d.allowed}")

    step(2, "Verify the chain as recorded.")
    ok, broken = rec.verify()
    print(f"   verify() -> intact={ok}  first_broken_seq={broken}")

    step(3, "An insider rewrites history: flip the denied delete to 'allowed'")
    print("   directly in SQLite, bypassing the signed append() path entirely.")
    rec.ledger.conn.execute(
        "UPDATE entries SET decision=? WHERE action='delete'",
        ('{"allowed": true, "rule": "no-bulk-delete", "reason": ""}',),
    )
    rec.ledger.conn.commit()

    step(4, "Verify again.")
    ok, broken = rec.verify()
    print(f"   verify() -> intact={ok}  first_broken_seq={broken}")
    tampered = rec.ledger.get(broken)
    print(f"   The chain breaks at seq {broken}: {tampered.actor} / {tampered.action}.")
    print("   You cannot quietly change what was permitted after the fact —")
    print("   the next entry's hash no longer matches, and verify() points right at it.")


if __name__ == "__main__":
    main()
