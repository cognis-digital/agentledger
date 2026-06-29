"""Scenario 5 - SRE / platform operations.

Two operational realities: some actions shouldn't ride on one person's say-so,
and your SOC wants the feed in real time, not after the incident.

  * Threshold approval (m-of-n): a high-blast-radius directive counts as
    authorized only when m *distinct* operators each sign its hash with their
    own key — real multi-signature, not a checkbox.
  * Real-time sinks: attach a sink and every entry is pushed out the moment it's
    recorded, with an independent copy outside the ledger's own database. Sinks
    are best-effort — a flaky collector can never block or break recording.

This requires two approvals before a prod database migration is satisfied, and
forwards the whole feed to an in-process sink standing in for a SIEM.
"""
from _common import best_signer, fresh_recorder, rule, step
from agentledger import CallableSink, PolicyGate, Recorder


def main() -> None:
    rule("THRESHOLD APPROVAL + SIEM FEED  -  m-of-n, and a live copy out the door")

    # A live feed standing in for syslog/Splunk/an HTTP collector. In production
    # this would be SyslogSink(...) or HttpSink("https://splunk.../collector").
    siem: list[dict] = []
    sink = CallableSink(lambda entry: siem.append(entry))
    rec = Recorder(gate=PolicyGate(default_allow=True),
                   signer=best_signer("ed25519"), sinks=[sink])

    step(1, "Submit a high-blast-radius directive: migrate the prod database.")
    _, directive = rec.submit("alice", "db-migrate", {"env": "prod", "down_minutes": 5})
    print(f"   directive seq={directive.seq}; threshold = 2 distinct operators required.")

    step(2, "Each operator approves by signing the directive's hash with their OWN key.")
    operators = {"alice": best_signer("ed25519"), "bob": best_signer("ed25519")}
    rec.approve(directive.seq, "alice", operators["alice"])
    status = rec.approval_status(directive.seq, threshold=2)
    print(f"   after alice:        approvals={len(status.approver_keys)}  satisfied={status.satisfied}")

    # Same operator signing twice must NOT count as two distinct approvals.
    rec.approve(directive.seq, "alice", operators["alice"])
    status = rec.approval_status(directive.seq, threshold=2)
    print(f"   after alice again:  approvals={len(status.approver_keys)}  satisfied={status.satisfied}"
          "   (duplicate key counts once)")

    rec.approve(directive.seq, "bob", operators["bob"])
    status = rec.approval_status(directive.seq, threshold=2)
    print(f"   after bob:          approvals={len(status.approver_keys)}  satisfied={status.satisfied}")

    step(3, "Now that m-of-n is satisfied, run it and record the outcome.")
    if status.satisfied:
        outcome = rec.record_outcome(directive.seq, "agent:dba", "success", {"migrated": 38})
        print(f"   outcome seq={outcome.seq} recorded.")

    step(4, "What the SIEM saw, in real time, as each entry was recorded:")
    for e in siem:
        print(f"   -> {e['kind']:<10} {e['actor']:<8} {e['action']:<12} hash={e['entry_hash'][:12]}...")
    print(f"   {len(siem)} events forwarded; the signed ledger remains the source of truth.")

    ok, _ = rec.verify()
    print(f"\nverify() -> intact={ok}. Approvals and outcome all live in the same signed chain.")


if __name__ == "__main__":
    main()
