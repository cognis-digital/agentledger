"""Scenario 12 - auditors handed a bundle that was edited in transit.

An evidence bundle is only as good as its ability to reject a forgery. This
walks every category of tampering an adversary might attempt on the exported
JSON -- editing a field, deleting an entry, reordering, inserting a fake entry,
flipping a signature -- and shows verify_bundle() rejecting each, pointing at the
first broken sequence, without ever crashing on malformed input.
"""
import copy

from _common import fresh_recorder, rule, step
from agentledger import PolicyGate
from agentledger.evidence import verify_bundle


def main() -> None:
    rule("TAMPER AFTER EXPORT  -  every forgery on the bundle is rejected")

    rec = fresh_recorder(gate=PolicyGate(default_allow=True))
    _, d = rec.submit("agent:treasury", "wire-transfer", {"amount": 2500})
    rec.record_outcome(d.seq, "agent:treasury", "success", {"conf": "WT-1"})
    rec.submit("agent:treasury", "wire-transfer", {"amount": 9000})
    rec.submit("alice", "close-books", {"period": "Q3"})
    base = rec.export_evidence()

    step(1, "Baseline: the untouched bundle verifies.")
    print(f"   verify_bundle(clean) -> {verify_bundle(copy.deepcopy(base))}")

    step(2, "Edit a field (change a transfer amount).")
    b = copy.deepcopy(base)
    b["entries"][0]["params"]["amount"] = 999999
    print(f"   edited amount        -> {verify_bundle(b)}")

    step(3, "Delete a middle entry.")
    b = copy.deepcopy(base)
    del b["entries"][1]
    print(f"   deleted entry        -> {verify_bundle(b)}")

    step(4, "Reorder two entries.")
    b = copy.deepcopy(base)
    b["entries"][1], b["entries"][2] = b["entries"][2], b["entries"][1]
    print(f"   reordered entries    -> {verify_bundle(b)}")

    step(5, "Insert a fabricated entry.")
    b = copy.deepcopy(base)
    forged = copy.deepcopy(b["entries"][1])
    forged["action"] = "wire-transfer"
    forged["params"] = {"amount": 1_000_000}
    b["entries"].insert(1, forged)
    print(f"   inserted fake entry  -> {verify_bundle(b)}")

    step(6, "Flip a signature to nonsense.")
    b = copy.deepcopy(base)
    b["entries"][0]["signature"] = "00" * (len(b["entries"][0]["signature"]) // 2)
    print(f"   flipped signature    -> {verify_bundle(b)}")

    step(7, "Hand it garbage (truncated JSON object).")
    print(f"   missing fields       -> {verify_bundle({'format': base['format'], 'entries': [{'seq': 1}]})}")
    print(f"   not even a dict      -> {verify_bundle('corrupt')}")

    print("\nEvery forgery is rejected (and malformed input never crashes the verifier).")
    print("Independence is the whole point: anyone can run this check.")


if __name__ == "__main__":
    main()
