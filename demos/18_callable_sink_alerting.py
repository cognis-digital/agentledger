"""Scenario 18 - detection engineers alerting on the live feed.

A sink is just a callable, so you can run detection logic inline: every entry is
handed to your function the instant it's recorded. This wires a CallableSink
that raises an alert on denied directives and high-value transfers -- real-time
detection driven by the same signed feed that becomes the evidence.

A deliberately broken sink is included to show isolation: a failing sink can
never block or break recording.
"""
from _common import best_signer, rule, step
from agentledger import CallableSink, PolicyGate, Recorder
from agentledger.sinks import Sink


def main() -> None:
    rule("CALLABLE SINK ALERTING  -  detect in real time on the signed feed")

    alerts: list[str] = []

    def detector(entry: dict) -> None:
        if entry["kind"] == "directive" and not entry["decision"].get("allowed", True):
            alerts.append(f"DENIED {entry['action']!r} by {entry['actor']} "
                          f"(rule {entry['decision']['rule']!r})")
        amount = entry.get("params", {}).get("amount", 0)
        if isinstance(amount, (int, float)) and amount >= 10000:
            alerts.append(f"HIGH-VALUE {entry['action']!r} amount={amount}")

    class FlakyCollector(Sink):
        def emit(self, entry):
            raise RuntimeError("collector unreachable")

    gate = PolicyGate(default_allow=True).deny(
        "delete.*", reason="destructive op", name="no-delete")
    rec = Recorder(gate=gate, signer=best_signer("ed25519"),
                   sinks=[CallableSink(detector), FlakyCollector()])

    step(1, "Record a mix of normal and alert-worthy activity.")
    events = [
        ("alice", "read", {"table": "metrics"}),
        ("agent:fin", "wire-transfer", {"amount": 25000}),     # high-value alert
        ("mallory", "delete.table", {"name": "audit"}),        # denied -> alert
        ("agent:ops", "scale", {"replicas": 3}),
    ]
    for actor, action, params in events:
        d, e = rec.submit(actor, action, params)
        print(f"   #{e.seq} {action:<16} allowed={d.allowed}")

    step(2, "What the inline detector raised, in real time:")
    for a in alerts:
        print(f"   [ALERT] {a}")
    print(f"   {len(alerts)} alert(s) raised; the flaky collector failed silently and")
    print("   recording continued -- the signed ledger is unaffected.")

    ok, _ = rec.verify()
    print(f"\nverify() -> intact={ok}. Detection and evidence are the same stream.")


if __name__ == "__main__":
    main()
