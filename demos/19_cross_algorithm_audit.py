"""Scenario 19 - a years-long ledger that outlived an algorithm migration.

Long-lived evidence spans crypto migrations. A single ledger can contain entries
signed under different algorithms across rotations -- ed25519 early on, hybrid or
ML-DSA later. The exported bundle must still verify offline, picking the right
verifier *per entry*, not one for the whole file.

(This is the exact case that revealed a real bug: an earlier verify_bundle pinned
one verifier to the bundle header algorithm and mis-rejected the older entries.
It now selects a verifier per entry. This demo exercises that path end to end.)
"""
from _common import best_signer, rule, step
from agentledger import PolicyGate, Recorder
from agentledger.evidence import verify_bundle
from agentledger.signing import _HAVE_ED25519, _HAVE_MLDSA


def main() -> None:
    rule("CROSS-ALGORITHM AUDIT  -  one bundle, multiple signature algorithms")

    rec = Recorder(gate=PolicyGate(default_allow=True), signer=best_signer("ed25519"))

    step(1, "Year 1: record under the original ed25519 key.")
    rec.submit("alice", "provision", {"cluster": "prod"})
    rec.submit("agent:ops", "scale", {"replicas": 4})

    step(2, "Year 2: rotate to a NEW ed25519 key (continuity proof).")
    rec.rotate_key(best_signer("ed25519"))
    rec.submit("alice", "provision", {"cluster": "prod-eu"})

    if _HAVE_MLDSA:
        upgrade = "hybrid" if _HAVE_ED25519 else "ml-dsa"
        step(3, f"Year 3: rotate to post-quantum {upgrade!r} as the threat evolves.")
        rec.rotate_key(best_signer(upgrade))
        rec.submit("agent:ops", "rotate-secrets", {"scope": "prod"})
    else:
        step(3, "(No ML-DSA in this build; staying on ed25519 for the final segment.)")
        rec.rotate_key(best_signer("ed25519"))
        rec.submit("agent:ops", "rotate-secrets", {"scope": "prod"})

    step(4, "Export and verify offline -- entries span multiple algorithms.")
    bundle = rec.export_evidence()
    algos = sorted({e["algorithm"] for e in bundle["entries"]})
    print(f"   algorithms present in this one bundle: {algos}")
    ok, broken = verify_bundle(bundle)
    print(f"   verify_bundle() -> intact={ok}  first_broken_seq={broken}")

    step(5, "Tamper an OLD (first-algorithm) entry; still caught.")
    bundle["entries"][0]["action"] = "exfiltrate"
    ok, broken = verify_bundle(bundle)
    print(f"   after editing entry #1 -> intact={ok}  first_broken_seq={broken}")
    print("\nA verifier is chosen per entry, so a migration never invalidates the past.")


if __name__ == "__main__":
    main()
