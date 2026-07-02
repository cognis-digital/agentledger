"""Scenario 7 - proving ONE entry without revealing the rest.

The hash chain proves the whole ledger is intact, but to prove a single entry
belongs to a committed ledger you'd otherwise hand over every entry. A Merkle
tree gives a compact alternative: publish one root hash, then produce an
O(log n) inclusion proof for any single entry that verifies against that root
without disclosing the other entries. Useful when you must show a regulator
"this one directive is in the record" while keeping everything else private.
"""
from _common import fresh_recorder, rule, step
from agentledger.merkle import MerkleTree, verify_proof


def main() -> None:
    rule("MERKLE INCLUSION PROOF  -  prove one entry, disclose nothing else")

    rec = fresh_recorder()
    step(1, "Record several directives.")
    for i, action in enumerate(["deploy", "scale-up", "rotate-secret",
                                 "patch", "rollback"]):
        rec.submit("alice", action, {"n": i})
    print(f"   {len(rec.entries())} entries recorded.")

    step(2, "Build a Merkle tree over the entries and publish the ROOT only.")
    tree = MerkleTree.from_ledger(rec.ledger)
    root = tree.root()
    print(f"   published root = {root}")
    print(f"   tree size      = {tree.size}")

    step(3, "Produce a compact inclusion proof for a single entry (seq=3).")
    proof = tree.prove(3)
    print(f"   entry_hash  = {proof.entry_hash[:24]}...")
    print(f"   proof steps = {len(proof.steps)}  (O(log n), not the whole ledger)")

    step(4, "A verifier checks the proof against the published root alone.")
    ok = verify_proof(proof, expected_root=root)
    print(f"   verify_proof(proof, root) -> {ok}")

    step(5, "A forged entry hash cannot reproduce the root.")
    from agentledger.merkle import InclusionProof
    forged = InclusionProof(seq=proof.seq, leaf_index=proof.leaf_index,
                            entry_hash="f" * 64, root=proof.root,
                            tree_size=proof.tree_size, steps=proof.steps)
    print(f"   verify_proof(forged, root) -> {verify_proof(forged, expected_root=root)}")

    print("\nThe proof reveals only sibling hashes, never the other entries' contents.")


if __name__ == "__main__":
    main()
