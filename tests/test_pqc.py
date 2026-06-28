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


def test_hybrid_sign_verify_and_both_required():
    signer = new_signer(prefer="hybrid")
    assert signer.algorithm == "hybrid-ed25519-ml-dsa-65"
    msg = b"directive-hash"
    sig = signer.sign(msg)
    assert signer.verifier().verify(msg, sig, signer.public_bytes())
    # corrupting either component signature breaks verification
    assert not signer.verifier().verify(b"other", sig, signer.public_bytes())


def test_hybrid_save_load_and_bundle(tmp_path):
    from agentledger import load_key, save_key
    s = new_signer(prefer="hybrid")
    path = str(tmp_path / "hk.json")
    save_key(s, path)
    s2 = load_key(path)
    assert s.public_bytes() == s2.public_bytes()

    rec = Recorder(gate=PolicyGate(default_allow=True), signer=s2)
    rec.submit("alice", "deploy", {"env": "prod"})
    ok, _ = verify_bundle(rec.export_evidence())
    assert ok


def test_rotate_from_ed25519_to_hybrid():
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    rec.submit("alice", "x")
    rec.rotate_key(new_signer("hybrid"))   # upgrade classical -> hybrid PQC
    rec.submit("alice", "y")
    ok, broken = rec.verify()
    assert ok and broken is None
