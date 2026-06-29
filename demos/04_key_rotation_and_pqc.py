"""Scenario 4 - platform & security engineers.

Keys outlive processes, and evidence you sign today may need to verify for years
— long enough that "harvest now, verify later" against a future quantum adversary
is a real threat to long-lived records. Two capabilities answer this:

  * key rotation with a *continuity proof* — the outgoing key signs a rotation
    entry naming the incoming key, so the whole history descends from one root
    of trust (an attacker appending with their own key is rejected); and
  * post-quantum signing (ML-DSA-65 / FIPS 204) you can rotate *into* in place.

This rotates a live ledger from a classical key to a post-quantum one and shows
verification still holds across the boundary — then shows an unauthorized key
being rejected.
"""
from _common import best_signer, fresh_recorder, rule, step
from agentledger.signing import _HAVE_MLDSA


def main() -> None:
    rule("KEY ROTATION + POST-QUANTUM  -  one root of trust, across algorithms")

    rec = fresh_recorder(prefer="ed25519")
    print(f"\nStarting signer: {rec.signer.algorithm}")

    step(1, "Record activity under the original key.")
    rec.submit("alice", "provision", {"cluster": "prod-us-east"})
    rec.submit("agent:ops", "scale", {"replicas": 12})
    print(f"   public key in force: {rec.signer.public_bytes().hex()[:24]}...")

    target = "ml-dsa" if _HAVE_MLDSA else "ed25519"
    step(2, f"Rotate the signing key to {target!r} in place (continuity proof written).")
    new = best_signer(target)
    rotation = rec.rotate_key(new)
    print(f"   rotation entry seq={rotation.seq}, signed by the OUTGOING key,")
    print(f"   naming the new key {new.public_bytes().hex()[:24]}...")

    step(3, "Keep recording under the new key.")
    rec.submit("alice", "provision", {"cluster": "prod-eu-west"})
    print(f"   now signing with: {rec.signer.algorithm}")

    step(4, "Verify the whole chain across the rotation boundary.")
    ok, broken = rec.verify()
    print(f"   verify(check_continuity=True) -> intact={ok}  first_broken_seq={broken}")

    step(5, "An attacker appends an entry signed with their OWN, unauthorized key.")
    rogue = best_signer("ed25519")
    rec.ledger.signer = rogue          # swap the signer WITHOUT a rotation entry
    rec.ledger.append("directive", "mallory", "exfiltrate", {"target": "secrets"})
    ok, broken = rec.verify()
    print(f"   verify() -> intact={ok}  first_broken_seq={broken}")
    print("   The signature on that row is valid in isolation, but NOTHING authorized")
    print("   the key — continuity verification rejects it. 'Each entry is signed' is")
    print("   not enough; 'the whole history descends from one root of trust' is.")


if __name__ == "__main__":
    main()
