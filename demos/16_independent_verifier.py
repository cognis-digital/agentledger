"""Scenario 16 - a regulator who refuses to install your software.

The strongest property of an Ed25519 bundle: you don't need agentledger at all
to verify it. Everything required -- the hash function (BLAKE2b), the public key
per entry, the chain rule -- is standard. This demo re-implements the verifier
from scratch using only the standard library + the public Ed25519 primitive, to
prove the bundle's independence is real and not a marketing claim.
"""
import hashlib
import json

from _common import fresh_recorder, rule, step
from agentledger import PolicyGate

GENESIS = "0" * 64


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def recompute_hash(prev_hash: str, payload: dict) -> str:
    h = hashlib.blake2b(digest_size=32)
    h.update(prev_hash.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical(payload))
    return h.hexdigest()


def independent_verify(bundle: dict) -> bool:
    """A from-scratch verifier; no agentledger code involved."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception:
        print("   (cryptography not installed; checking the hash chain only)")
        Ed25519PublicKey = None

    prev = GENESIS
    for d in bundle["entries"]:
        payload = {k: d[k] for k in ("seq", "ts", "kind", "actor", "action",
                                     "params", "decision", "ref", "prev_hash")}
        if d["prev_hash"] != prev:
            return False
        if recompute_hash(d["prev_hash"], payload) != d["entry_hash"]:
            return False
        if Ed25519PublicKey is not None and d["algorithm"] == "ed25519":
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(d["public_key"])).verify(
                    bytes.fromhex(d["signature"]), d["entry_hash"].encode("ascii"))
            except Exception:
                return False
        prev = d["entry_hash"]
    return bundle.get("head_hash", prev) == prev


def main() -> None:
    rule("INDEPENDENT VERIFIER  -  re-implemented from scratch, no agentledger")

    rec = fresh_recorder(gate=PolicyGate(default_allow=True))
    _, d = rec.submit("agent:treasury", "wire-transfer", {"amount": 2500})
    rec.record_outcome(d.seq, "agent:treasury", "success")
    rec.submit("alice", "close-books", {"period": "Q3"})
    bundle = rec.export_evidence()

    step(1, "Verify the bundle with a verifier written here, not imported.")
    print(f"   independent_verify(clean) -> {independent_verify(bundle)}")

    step(2, "Tamper one field; the from-scratch verifier rejects it too.")
    bundle["entries"][0]["params"]["amount"] = 999999
    print(f"   independent_verify(edited) -> {independent_verify(bundle)}")

    print("\nThe bundle is independently checkable with standard primitives alone.")
    print("That's what makes it evidence rather than a log you have to trust.")


if __name__ == "__main__":
    main()
