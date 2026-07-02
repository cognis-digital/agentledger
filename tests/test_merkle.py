import pytest

from agentledger import PolicyGate, Recorder
from agentledger.merkle import (
    InclusionProof, MerkleTree, leaf_hash, verify_proof,
)


def _rec(n=5):
    rec = Recorder(gate=PolicyGate(default_allow=True))
    for i in range(n):
        rec.submit("actor", f"act{i}", {"i": i})
    return rec


def test_root_is_stable_and_deterministic():
    rec = _rec(4)
    t1 = MerkleTree.from_ledger(rec.ledger)
    t2 = MerkleTree.from_ledger(rec.ledger)
    assert t1.root() == t2.root()
    assert t1.size == 4


def test_prove_and_verify_every_entry():
    rec = _rec(7)  # odd count exercises the promotion path
    tree = MerkleTree.from_ledger(rec.ledger)
    root = tree.root()
    for e in rec.entries():
        proof = tree.prove(e.seq)
        assert verify_proof(proof, expected_root=root)
        assert proof.entry_hash == e.entry_hash


def test_proof_fails_against_wrong_root():
    tree = MerkleTree.from_ledger(_rec(5).ledger)
    proof = tree.prove(3)
    assert verify_proof(proof, expected_root="a" * 64) is False


def test_tampered_entry_hash_breaks_proof():
    tree = MerkleTree.from_ledger(_rec(5).ledger)
    proof = tree.prove(2)
    forged = InclusionProof(
        seq=proof.seq, leaf_index=proof.leaf_index,
        entry_hash="f" * 64, root=proof.root, tree_size=proof.tree_size,
        steps=proof.steps)
    assert verify_proof(forged, expected_root=proof.root) is False


def test_proof_roundtrips_through_dict():
    tree = MerkleTree.from_ledger(_rec(6).ledger)
    proof = tree.prove(4)
    restored = InclusionProof.from_dict(proof.as_dict())
    assert restored == proof
    assert verify_proof(restored, expected_root=tree.root())


def test_single_entry_tree():
    tree = MerkleTree.from_ledger(_rec(1).ledger)
    proof = tree.prove(1)
    # single leaf: root is just the leaf hash, no steps
    assert proof.steps == []
    assert tree.root() == leaf_hash(proof.entry_hash)
    assert verify_proof(proof, expected_root=tree.root())


def test_unknown_seq_and_empty_tree():
    tree = MerkleTree.from_ledger(_rec(3).ledger)
    with pytest.raises(KeyError):
        tree.prove(99)
    empty = MerkleTree([])
    assert empty.size == 0
    with pytest.raises(KeyError):
        empty.prove(1)


def test_leaf_and_node_domain_separation():
    # a leaf hash must differ from a raw entry hash (0x00 prefix applied)
    rec = _rec(1)
    e = rec.entries()[0]
    assert leaf_hash(e.entry_hash) != e.entry_hash
