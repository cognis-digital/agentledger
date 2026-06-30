"""Key-rotation and continuity edge cases.

Continuity is the property that the whole history descends from one root of
trust: a new signing key is only accepted if a prior key_rotation entry, signed
by the *previous* authorized key, names it.
"""
import pytest

from agentledger import PolicyGate, Recorder, new_signer
from agentledger.evidence import verify_bundle
from agentledger.signing import _HAVE_MLDSA


def rec_with(prefer="ed25519"):
    return Recorder(gate=PolicyGate(default_allow=True), signer=new_signer(prefer))


def test_single_rotation_verifies():
    rec = rec_with()
    rec.submit("alice", "x")
    rec.rotate_key(new_signer("ed25519"))
    rec.submit("alice", "y")
    ok, broken = rec.verify()
    assert ok and broken is None


def test_multiple_rotations_verify():
    rec = rec_with()
    for i in range(4):
        rec.submit("alice", f"act{i}")
        rec.rotate_key(new_signer("ed25519"))
    rec.submit("alice", "final")
    ok, broken = rec.verify()
    assert ok and broken is None


def test_rotation_as_first_entry():
    rec = rec_with()
    rec.rotate_key(new_signer("ed25519"))   # rotate before any directive
    rec.submit("alice", "x")
    ok, broken = rec.verify()
    assert ok and broken is None


def test_unauthorized_key_swap_rejected():
    rec = rec_with()
    rec.submit("alice", "x")
    rec.ledger.signer = new_signer("ed25519")     # no rotation entry
    forged = rec.ledger.append("directive", "mallory", "sneak", {})
    ok, broken = rec.verify()
    assert not ok and broken == forged.seq


def test_unauthorized_swap_passes_without_continuity_check():
    rec = rec_with()
    rec.submit("alice", "x")
    rec.ledger.signer = new_signer("ed25519")
    rec.ledger.append("directive", "mallory", "sneak", {})
    ok, _ = rec.verify(check_continuity=False)
    assert ok   # each per-entry signature is self-consistent


def test_forged_rotation_entry_naming_attacker_key_still_chains_but_is_self_authorized():
    # An attacker who controls the DB could *write* a key_rotation entry naming
    # their own key, but only by signing it with the previous authorized key.
    # If they only had their own key, the rotation entry itself is signed by an
    # unauthorized key and continuity rejects at the rotation entry.
    rec = rec_with()
    rec.submit("alice", "x")
    rogue = new_signer("ed25519")
    rec.ledger.signer = rogue
    # append a key_rotation naming rogue, but signed by rogue (not the real key)
    rot = rec.ledger.append("key_rotation", "mallory", "rotate",
                            {"new_algorithm": rogue.algorithm,
                             "new_public_key": rogue.public_bytes().hex()})
    ok, broken = rec.verify()
    assert not ok and broken == rot.seq


def test_rotation_continuity_holds_in_offline_bundle():
    rec = rec_with()
    _, e = rec.submit("alice", "x")
    rec.record_outcome(e.seq, "agent", "ok")
    rec.rotate_key(new_signer("ed25519"))
    rec.submit("bob", "y")
    ok, broken = verify_bundle(rec.export_evidence())
    assert ok and broken is None


def test_rotation_entry_is_signed_by_outgoing_key():
    rec = rec_with()
    rec.submit("alice", "x")
    old_pub = rec.signer.public_bytes().hex()
    rot = rec.rotate_key(new_signer("ed25519"))
    assert rot.public_key == old_pub        # signed by the OUTGOING key
    assert rot.params["new_public_key"] != old_pub


def test_rotate_to_hmac_then_back_to_ed25519():
    rec = rec_with()
    rec.submit("alice", "x")
    rec.rotate_key(new_signer("hmac"))
    rec.submit("alice", "y")
    rec.rotate_key(new_signer("ed25519"))
    rec.submit("alice", "z")
    ok, broken = rec.verify()
    assert ok and broken is None


@pytest.mark.skipif(not _HAVE_MLDSA, reason="ML-DSA not available")
def test_rotate_classical_to_pqc_and_verify_bundle():
    rec = rec_with("ed25519")
    rec.submit("alice", "x")
    rec.rotate_key(new_signer("ml-dsa"))
    rec.submit("alice", "y")
    ok, _ = verify_bundle(rec.export_evidence())
    assert ok
