"""Scenario 9 - air-gapped / stdlib-only deployments.

Not every box can install `cryptography`. agentledger still runs on the standard
library alone using HMAC-SHA256. The trade-off is honest and explicit: HMAC is
symmetric, so a third party needs the shared secret to verify, and the evidence
bundle *says so* (third_party_verifiable=False).

This builds an HMAC ledger, shows the chain validates offline WITHOUT the secret
(integrity), and that signatures only validate WITH the secret (authenticity).
"""
from _common import rule, step
from agentledger import PolicyGate, Recorder
from agentledger.evidence import verify_bundle
from agentledger.signing import HmacSigner


def main() -> None:
    rule("HMAC, STDLIB-ONLY  -  works with no dependencies, honestly labelled")

    secret = b"shared-collector-secret-0000000000"[:32]
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=HmacSigner(secret))
    print(f"\nSigning backend: {rec.signer.algorithm} "
          f"(third_party_verifiable={rec.signer.third_party_verifiable})")

    step(1, "Record some activity (no 'cryptography' package required).")
    _, d = rec.submit("alice", "deploy", {"env": "prod"})
    rec.record_outcome(d.seq, "agent", "success", {"build": 77})
    print(f"   {len(rec.entries())} entries recorded.")

    step(2, "Export a bundle; note it's labelled NOT third-party verifiable.")
    bundle = rec.export_evidence()
    print(f"   bundle algorithm={bundle['algorithm']!r}  "
          f"third_party_verifiable={bundle['third_party_verifiable']}")

    step(3, "An outside party with NO secret can still check chain integrity.")
    ok, broken = verify_bundle(bundle)
    print(f"   verify_bundle(no secret) -> intact={ok}  (hash chain only)")

    step(4, "With the shared secret, signatures verify too.")
    ok, broken = verify_bundle(bundle, secret=secret)
    print(f"   verify_bundle(+secret)   -> intact={ok}  (chain + signatures)")

    step(5, "A wrong secret is rejected.")
    ok, broken = verify_bundle(bundle, secret=b"x" * 32)
    print(f"   verify_bundle(bad secret)-> intact={ok}  first_broken_seq={broken}")
    print("\nHMAC is the honest fallback: it runs anywhere, and the bundle never")
    print("pretends to offer offline third-party verification it can't deliver.")


if __name__ == "__main__":
    main()
