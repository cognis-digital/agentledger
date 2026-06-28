import json

from agentledger import PolicyGate, Recorder
from agentledger.evidence import verify_bundle
from agentledger.signing import HmacSigner


def make_recorder(**kw):
    rec = Recorder(gate=PolicyGate(default_allow=True), **kw)
    _, e1 = rec.submit("alice", "deploy", {"env": "prod"})
    rec.record_outcome(e1.seq, "agent:deployer", "success")
    rec.submit("bob", "rotate-keys", {})
    return rec


def test_export_bundle_shape():
    rec = make_recorder()
    bundle = rec.export_evidence()
    assert bundle["format"] == "agentledger-evidence/1"
    assert bundle["entry_count"] == 3
    assert len(bundle["entries"]) == 3
    assert bundle["head_hash"] == bundle["entries"][-1]["entry_hash"]


def test_verify_bundle_ok_offline():
    rec = make_recorder()  # default signer (ed25519 here) -> offline-verifiable
    bundle = rec.export_evidence()
    ok, broken = verify_bundle(bundle)  # no secret needed for ed25519
    assert ok and broken is None


def test_verify_bundle_detects_tamper():
    rec = make_recorder()
    bundle = rec.export_evidence()
    bundle["entries"][1]["action"] = "exfiltrate-everything"
    ok, broken = verify_bundle(bundle)
    assert not ok
    assert broken == bundle["entries"][1]["seq"]


def test_bundle_roundtrips_through_json(tmp_path):
    rec = make_recorder()
    path = tmp_path / "evidence.json"
    rec.export_evidence(str(path))
    loaded = json.loads(path.read_text())
    ok, _ = verify_bundle(loaded)
    assert ok


def test_hmac_bundle_chain_only_without_secret():
    secret = b"k" * 32
    rec = make_recorder(signer=HmacSigner(secret))
    bundle = rec.export_evidence()
    assert bundle["third_party_verifiable"] is False
    # chain validates without the secret...
    ok, _ = verify_bundle(bundle)
    assert ok
    # ...and signatures validate when the secret is supplied
    ok2, _ = verify_bundle(bundle, secret=secret)
    assert ok2
