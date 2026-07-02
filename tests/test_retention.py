import json

import pytest

from agentledger import (
    PolicyGate, Recorder, RetentionPolicy, seal_segment, verify_checkpoint,
)
from agentledger.evidence import verify_bundle
from agentledger.merkle import MerkleTree, verify_proof
from agentledger.retention import Checkpoint


def _rec(n=6):
    rec = Recorder(gate=PolicyGate(default_allow=True))
    for i in range(n):
        rec.ledger.append("directive", "actor", f"act{i}", {"i": i}, ts=100.0 + i)
    return rec


def test_keep_last_seals_the_prefix():
    rec = _rec(6)
    res = seal_segment(rec.ledger, rec.signer, RetentionPolicy(keep_last=2))
    assert res is not None
    assert res.checkpoint.entry_count == 4
    assert res.checkpoint.segment_start_seq == 1
    assert res.checkpoint.segment_end_seq == 4
    # live ledger untouched (sealing is export + attest, not delete)
    assert len(rec.entries()) == 6


def test_max_age_seals_only_old_entries():
    rec = _rec(6)  # ts 100..105
    policy = RetentionPolicy(max_age_seconds=1.0)
    # now = 104 -> threshold 103 -> entries with ts < 103 are 100,101,102 => seqs 1-3
    res = seal_segment(rec.ledger, rec.signer, policy, now=104.0)
    assert res.checkpoint.segment_end_seq == 3
    assert res.checkpoint.entry_count == 3


def test_nothing_eligible_returns_none():
    rec = _rec(3)
    assert seal_segment(rec.ledger, rec.signer, RetentionPolicy(keep_last=10)) is None
    assert seal_segment(rec.ledger, rec.signer, RetentionPolicy()) is None


def test_archive_bundle_is_offline_verifiable(tmp_path):
    rec = _rec(5)
    path = str(tmp_path / "archive.json")
    res = seal_segment(rec.ledger, rec.signer, RetentionPolicy(keep_last=1),
                       archive_path=path)
    bundle = json.load(open(path, encoding="utf-8"))
    ok, broken = verify_bundle(bundle)
    assert ok and broken is None
    assert bundle["entry_count"] == 4


def test_checkpoint_signature_verifies_and_detects_tamper():
    rec = _rec(4)
    res = seal_segment(rec.ledger, rec.signer, RetentionPolicy(keep_last=1))
    cp = res.checkpoint
    assert verify_checkpoint(cp) is True
    # tamper with the merkle root -> signature no longer matches the payload
    forged = Checkpoint.from_dict({**cp.as_dict(), "merkle_root": "0" * 64})
    assert verify_checkpoint(forged) is False


def test_checkpoint_roundtrips_through_dict():
    rec = _rec(4)
    cp = seal_segment(rec.ledger, rec.signer, RetentionPolicy(keep_last=1)).checkpoint
    restored = Checkpoint.from_dict(cp.as_dict())
    assert restored == cp
    assert verify_checkpoint(restored)


def test_sealed_entry_still_provable_against_checkpoint_root():
    rec = _rec(6)
    res = seal_segment(rec.ledger, rec.signer, RetentionPolicy(keep_last=2))
    # rebuild the tree over the sealed entries and prove one against the
    # checkpoint's committed root -> a single archived entry stays provable
    tree = MerkleTree(res.sealed)
    assert tree.root() == res.checkpoint.merkle_root
    proof = tree.prove(res.sealed[0].seq)
    assert verify_proof(proof, expected_root=res.checkpoint.merkle_root)


def test_keep_last_negative_rejected():
    rec = _rec(3)
    with pytest.raises(ValueError):
        RetentionPolicy(keep_last=-1).eligible(rec.entries())


def test_wrong_format_checkpoint_rejected():
    rec = _rec(3)
    cp = seal_segment(rec.ledger, rec.signer, RetentionPolicy(keep_last=1)).checkpoint
    bad = Checkpoint.from_dict({**cp.as_dict(), "format": "not-a-checkpoint"})
    assert verify_checkpoint(bad) is False
