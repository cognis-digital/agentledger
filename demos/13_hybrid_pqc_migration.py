"""Scenario 13 - crypto-agility planners.

"Harvest now, decrypt later" makes long-lived evidence a target for a future
quantum adversary. The conservative migration isn't to throw away Ed25519 -- it's
to sign with Ed25519 AND ML-DSA-65 at once, so a break in *either* algorithm
alone can't forge a directive. A hybrid verifier requires both.

This signs a ledger with the hybrid backend (degrading to whatever is available),
verifies offline, and shows that corrupting the bundle is still caught. On a
build without ML-DSA it explains the fallback honestly instead of failing.
"""
from _common import best_signer, rule, step
from agentledger import PolicyGate, Recorder
from agentledger.evidence import verify_bundle
from agentledger.signing import _HAVE_ED25519, _HAVE_MLDSA


def main() -> None:
    rule("HYBRID PQC MIGRATION  -  classical AND post-quantum, both required")

    hybrid_available = _HAVE_ED25519 and _HAVE_MLDSA
    prefer = "hybrid" if hybrid_available else "ed25519"
    signer = best_signer(prefer)
    print(f"\nRequested 'hybrid'; using {signer.algorithm!r} "
          f"(hybrid backend available: {hybrid_available})")
    if not hybrid_available:
        print("   This build lacks ML-DSA, so we demonstrate with the available")
        print("   backend. Install a 'cryptography' with FIPS 204 for true hybrid.")

    rec = Recorder(gate=PolicyGate(default_allow=True), signer=signer)

    step(1, "Record activity signed under the chosen backend.")
    _, d = rec.submit("alice", "sign-release", {"artifact": "fw-2.1.bin"})
    rec.record_outcome(d.seq, "agent:signer", "success", {"sha": "abc123"})
    print(f"   {len(rec.entries())} entries signed with {rec.signer.algorithm!r}.")

    step(2, "Export and verify offline (no secret needed for asymmetric).")
    bundle = rec.export_evidence()
    ok, broken = verify_bundle(bundle)
    print(f"   verify_bundle() -> intact={ok}  third_party_verifiable="
          f"{bundle['third_party_verifiable']}")

    step(3, "A single edited byte still fails, regardless of algorithm.")
    bundle["entries"][0]["action"] = "sign-malware"
    ok, broken = verify_bundle(bundle)
    print(f"   after edit -> intact={ok}  first_broken_seq={broken}")

    if hybrid_available:
        print("\nThe hybrid signature binds BOTH an Ed25519 and an ML-DSA-65 signature;")
        print("forging a directive would require breaking both at once.")
    else:
        print("\nThe API is identical whichever backend is present -- rotate into hybrid")
        print("the moment a FIPS 204 build is available, with no code changes.")


if __name__ == "__main__":
    main()
