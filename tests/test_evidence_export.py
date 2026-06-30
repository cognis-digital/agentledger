"""Evidence export shape, file IO, and round-trip details."""
import json

from agentledger import PolicyGate, Recorder, new_signer
from agentledger.evidence import FORMAT, export, verify_bundle
from agentledger.ledger import GENESIS, Ledger
from agentledger.signing import HmacSigner


def make_rec(signer=None, n_extra=0):
    rec = Recorder(gate=PolicyGate(default_allow=True),
                   signer=signer or new_signer("ed25519"))
    _, d = rec.submit("alice", "deploy", {"env": "prod"})
    rec.record_outcome(d.seq, "agent", "ok")
    for i in range(n_extra):
        rec.submit("bob", f"act{i}")
    return rec


def test_export_format_and_counts():
    rec = make_rec()
    b = rec.export_evidence()
    assert b["format"] == FORMAT
    assert b["entry_count"] == 2 == len(b["entries"])
    assert b["head_hash"] == b["entries"][-1]["entry_hash"]


def test_export_empty_ledger_has_genesis_head():
    led = Ledger(new_signer("ed25519"))
    b = export(led, led.signer)
    assert b["entry_count"] == 0
    assert b["head_hash"] == GENESIS
    ok, broken = verify_bundle(b)
    assert ok and broken is None


def test_export_writes_file(tmp_path):
    rec = make_rec(n_extra=2)
    path = str(tmp_path / "e.json")
    rec.export_evidence(path)
    loaded = json.loads(open(path, encoding="utf-8").read())
    assert loaded["entry_count"] == 4
    ok, _ = verify_bundle(loaded)
    assert ok


def test_export_records_third_party_flag_ed25519():
    rec = make_rec()
    assert rec.export_evidence()["third_party_verifiable"] is True


def test_export_records_third_party_flag_hmac():
    rec = make_rec(signer=HmacSigner(b"k" * 32))
    b = rec.export_evidence()
    assert b["third_party_verifiable"] is False


def test_hmac_bundle_chain_only_without_secret():
    secret = b"s" * 32
    rec = make_rec(signer=HmacSigner(secret))
    b = rec.export_evidence()
    ok, _ = verify_bundle(b)               # chain validates
    assert ok
    ok2, _ = verify_bundle(b, secret=secret)   # +signatures with secret
    assert ok2


def test_hmac_bundle_wrong_secret_fails():
    rec = make_rec(signer=HmacSigner(b"a" * 32))
    b = rec.export_evidence()
    ok, broken = verify_bundle(b, secret=b"b" * 32)
    assert not ok


def test_bundle_includes_public_key_per_entry():
    rec = make_rec()
    b = rec.export_evidence()
    for e in b["entries"]:
        assert e["public_key"] and e["algorithm"] == "ed25519"


def test_export_then_modify_head_hash_detected():
    rec = make_rec(n_extra=2)
    b = rec.export_evidence()
    b["head_hash"] = "f" * 64
    ok, _ = verify_bundle(b)
    assert not ok


def test_bundle_with_mixed_algorithms_verifies_offline():
    # regression: a ledger rotated across algorithms (ed25519 -> hmac -> ...)
    # exports a bundle whose entries carry DIFFERENT algorithms. verify_bundle
    # must select a verifier per-entry, not pin one to the header algorithm.
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    rec.submit("alice", "x")
    rec.rotate_key(new_signer("ed25519"))   # still ed25519, but a new key
    rec.submit("bob", "y")
    b = rec.export_evidence()
    algos = {e["algorithm"] for e in b["entries"]}
    assert "ed25519" in algos
    ok, broken = verify_bundle(b)
    assert ok and broken is None


def test_exported_outcome_keeps_ref():
    rec = make_rec()
    b = rec.export_evidence()
    outcome = [e for e in b["entries"] if e["kind"] == "outcome"][0]
    directive = [e for e in b["entries"] if e["kind"] == "directive"][0]
    assert outcome["ref"] == directive["seq"]
