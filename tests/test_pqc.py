import pytest

from agentledger import PolicyGate, Recorder
from agentledger.evidence import verify_bundle
from agentledger.signing import _HAVE_MLDSA, new_signer

pytestmark = pytest.mark.skipif(not _HAVE_MLDSA, reason="ML-DSA not available in this cryptography build")


def test_mldsa_sign_verify_roundtrip():
    signer = new_signer(prefer="ml-dsa")
    assert signer.algorithm == "ml-dsa-65"
    assert signer.third_party_verifiable
    msg = b"directive-hash"
    sig = signer.sign(msg)
    assert signer.verifier().verify(msg, sig, signer.public_bytes())
    assert not signer.verifier().verify(b"tampered", sig, signer.public_bytes())


def test_mldsa_ledger_and_offline_bundle():
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer(prefer="ml-dsa"))
    _, e = rec.submit("alice", "deploy", {"env": "prod"})
    rec.record_outcome(e.seq, "agent:deployer", "success")
    ok, broken = rec.verify()
    assert ok and broken is None

    bundle = rec.export_evidence()
    assert bundle["algorithm"] == "ml-dsa-65"
    assert bundle["third_party_verifiable"] is True
    # post-quantum signatures verify offline from the bundle alone (no secret)
    ok, _ = verify_bundle(bundle)
    assert ok
    # tamper is still caught
    bundle["entries"][0]["action"] = "exfiltrate"
    ok, broken = verify_bundle(bundle)
    assert not ok and broken == bundle["entries"][0]["seq"]
