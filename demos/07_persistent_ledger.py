"""Scenario 7 - operators running a long-lived service.

A flight recorder is only useful if it survives process restarts. The ledger
persists to SQLite; reopen the same file with the same key and the chain is
intact and still appends from where it left off.

This writes to a temp database, closes it, reopens it as a *new process would*,
appends more, and verifies the whole chain across the "restart".
"""
import os
import tempfile

from _common import best_signer, rule, step
from agentledger import Ledger, PolicyGate, Recorder


def main() -> None:
    rule("PERSISTENT LEDGER  -  survive a restart, keep one unbroken chain")

    signer = best_signer("ed25519")
    db = os.path.join(tempfile.mkdtemp(prefix="agentledger_demo_"), "ledger.db")
    print(f"\nLedger database: {db}")

    step(1, "Process A records two directives, then exits.")
    recA = Recorder(gate=PolicyGate(default_allow=True), signer=signer, db_path=db)
    recA.submit("alice", "provision", {"cluster": "prod-us-east"})
    _, d = recA.submit("agent:ops", "scale", {"replicas": 8})
    recA.record_outcome(d.seq, "agent:ops", "success", {"now": 8})
    print(f"   recorded {len(recA.entries())} entries, head ends the process.")
    recA.ledger.conn.close()   # simulate process exit

    step(2, "Process B reopens the SAME file with the SAME key and continues.")
    recB = Recorder(gate=PolicyGate(default_allow=True), signer=signer, db_path=db)
    print(f"   reopened with {len(recB.entries())} pre-existing entries.")
    recB.submit("alice", "provision", {"cluster": "prod-eu-west"})
    print(f"   appended one more -> {len(recB.entries())} total.")

    step(3, "Verify the chain across the restart boundary.")
    ok, broken = recB.verify()
    print(f"   verify() -> intact={ok}  first_broken_seq={broken}")
    for e in recB.entries():
        print(f"     #{e.seq} {e.kind:<9} {e.actor:<10} {e.action}")
    print("\nThe restart is invisible to the chain: one continuous, signed history.")


if __name__ == "__main__":
    main()
