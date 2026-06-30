"""Scenario 11 - SOC engineers wiring a real-time feed to disk.

The JSONLinesSink is the simplest durable feed: one JSON object per line,
appended the moment each entry is recorded -- an independent copy outside the
ledger's own database that log shippers (Fluent Bit, Vector, Filebeat) can tail
straight into a SIEM.

This attaches a JSONLinesSink, records activity, then tails the file back as a
shipper would and confirms it mirrors the signed ledger.
"""
import json
import os
import tempfile

from _common import best_signer, rule, step
from agentledger import JSONLinesSink, PolicyGate, Recorder


def main() -> None:
    rule("JSONL SIEM FEED  -  one line per entry, tailed straight into a SIEM")

    feed = os.path.join(tempfile.mkdtemp(prefix="agentledger_demo_"), "audit.jsonl")
    rec = Recorder(gate=PolicyGate(default_allow=True),
                   signer=best_signer("ed25519"), sinks=[JSONLinesSink(feed)])
    print(f"\nLive feed file: {feed}")

    step(1, "Record a short burst of agent activity.")
    _, d = rec.submit("alice", "deploy", {"env": "prod"})
    rec.record_outcome(d.seq, "agent:deployer", "success", {"pods": 4})
    rec.submit("bob", "scale", {"replicas": 12})
    print(f"   {len(rec.entries())} entries recorded; each was streamed to the feed.")

    step(2, "Tail the feed back, as a log shipper would.")
    lines = [json.loads(x) for x in open(feed, encoding="utf-8").read().splitlines()]
    for line in lines:
        print(f"   -> {line['kind']:<10} {line['actor']:<8} {line['action']:<10} "
              f"hash={line['entry_hash'][:12]}...")

    step(3, "The feed mirrors the signed ledger exactly.")
    ledger_hashes = [e.entry_hash for e in rec.entries()]
    feed_hashes = [line["entry_hash"] for line in lines]
    print(f"   feed lines={len(lines)}  ledger entries={len(ledger_hashes)}  "
          f"match={feed_hashes == ledger_hashes}")

    ok, _ = rec.verify()
    print(f"\nverify() -> intact={ok}. The feed is a live copy; the chain stays canonical.")


if __name__ == "__main__":
    main()
