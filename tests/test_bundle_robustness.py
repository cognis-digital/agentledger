"""verify_bundle must treat malformed / hostile input as invalid evidence,
never crash. An auditor feeds it whatever file they were handed.
"""
import copy

from agentledger import PolicyGate, Recorder, new_signer
from agentledger.evidence import verify_bundle


def good_bundle(n=3):
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    _, d = rec.submit("alice", "deploy", {"env": "prod"})
    rec.record_outcome(d.seq, "agent", "ok")
    rec.submit("bob", "scale", {"replicas": 3})
    return rec.export_evidence()


def test_not_a_dict_is_invalid():
    ok, broken = verify_bundle("not a bundle")
    assert ok is False and broken is None


def test_wrong_format_is_invalid():
    b = good_bundle()
    b["format"] = "something-else/9"
    assert verify_bundle(b) == (False, None)


def test_entries_not_a_list_is_invalid():
    b = good_bundle()
    b["entries"] = {"seq": 1}
    assert verify_bundle(b) == (False, None)


def test_entry_missing_required_field_is_invalid_not_crash():
    b = good_bundle()
    del b["entries"][0]["prev_hash"]
    ok, broken = verify_bundle(b)
    assert ok is False
    assert broken == b["entries"][0]["seq"]


def test_entry_not_a_dict_is_invalid():
    b = good_bundle()
    b["entries"][1] = "corrupt"
    ok, broken = verify_bundle(b)
    assert ok is False


def test_non_hex_signature_is_invalid_not_crash():
    b = good_bundle()
    b["entries"][0]["signature"] = "zzzz-not-hex"
    ok, broken = verify_bundle(b)
    assert ok is False and broken == b["entries"][0]["seq"]


def test_non_hex_public_key_is_invalid_not_crash():
    b = good_bundle()
    b["entries"][0]["public_key"] = "xyz"
    ok, broken = verify_bundle(b)
    assert ok is False and broken == b["entries"][0]["seq"]


def test_unknown_algorithm_header_is_invalid():
    b = good_bundle()
    b["algorithm"] = "rot13"
    ok, broken = verify_bundle(b)
    assert ok is False and broken is None


def test_truncated_chain_head_hash_mismatch():
    b = good_bundle()
    # drop the last entry but leave head_hash pointing past it
    b["entries"] = b["entries"][:-1]
    ok, broken = verify_bundle(b)
    assert ok is False


def test_reordered_entries_break_chain():
    b = good_bundle()
    b["entries"][0], b["entries"][1] = b["entries"][1], b["entries"][0]
    ok, broken = verify_bundle(b)
    assert ok is False


def test_empty_entries_bundle_is_trivially_valid():
    b = good_bundle()
    b["entries"] = []
    b["head_hash"] = "0" * 64
    ok, broken = verify_bundle(b)
    assert ok is True and broken is None


def test_deepcopy_roundtrip_still_valid():
    b = good_bundle()
    ok, _ = verify_bundle(copy.deepcopy(b))
    assert ok is True


def test_inserted_entry_breaks_chain():
    b = good_bundle()
    forged = copy.deepcopy(b["entries"][1])
    forged["action"] = "exfiltrate"
    b["entries"].insert(1, forged)
    ok, broken = verify_bundle(b)
    assert ok is False
