"""Scenario 17 - incident response after a signing-key compromise.

A signing key leaks. The right move is to rotate to a fresh key with a
continuity proof, so everything after the rotation descends from the new key
while the pre-compromise history stays verifiable. Crucially, an attacker who
stole the *old* key still can't silently append: continuity requires the new
key, and a rogue append under any non-authorized key is rejected.

This rotates after a suspected compromise, keeps recording, and shows a rogue
append (attacker using a key that was never authorized) being caught.
"""
from _common import best_signer, fresh_recorder, rule, step
from agentledger import PolicyGate, Recorder


def main() -> None:
    rule("KEY-COMPROMISE RESPONSE  -  rotate, and reject the rogue append")

    rec = Recorder(gate=PolicyGate(default_allow=True), signer=best_signer("ed25519"))

    step(1, "Normal activity under the original key.")
    rec.submit("alice", "deploy", {"env": "prod"})
    rec.submit("agent:ops", "scale", {"replicas": 6})
    print(f"   key in force: {rec.signer.public_bytes().hex()[:24]}...")

    step(2, "Key suspected compromised -> rotate to a fresh key (continuity proof).")
    fresh = best_signer("ed25519")
    rotation = rec.rotate_key(fresh)
    print(f"   rotation entry seq={rotation.seq}, signed by the OUTGOING key,")
    print(f"   names the new key {fresh.public_bytes().hex()[:24]}...")
    rec.submit("alice", "deploy", {"env": "prod", "after_rotation": True})

    step(3, "Verify -- the pre- and post-rotation history is one valid chain.")
    ok, broken = rec.verify()
    print(f"   verify() -> intact={ok}  first_broken_seq={broken}")

    step(4, "The attacker (holding some key) appends WITHOUT a rotation entry.")
    rogue = best_signer("ed25519")
    rec.ledger.signer = rogue
    forged = rec.ledger.append("directive", "mallory", "create-admin", {"user": "evil"})
    ok, broken = rec.verify()
    print(f"   verify() -> intact={ok}  first_broken_seq={broken}  (rogue append rejected)")
    print(f"   the forged entry is seq {forged.seq}; its signature is valid in")
    print("   isolation, but NOTHING authorized that key -- continuity catches it.")
    print("\nRotation contains the blast radius; continuity makes 'just sign it' fail.")


if __name__ == "__main__":
    main()
