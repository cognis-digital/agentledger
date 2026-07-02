"""Scenario 9 - archiving old history without losing the proof.

An append-only ledger grows forever. Eventually you seal off old history into a
signed archive and keep a smaller active tail - without breaking the ability to
prove the old history was intact. `seal_segment` exports the eligible prefix as
a signed evidence bundle, computes a Merkle root over it, and returns a signed
checkpoint anchoring (archived head hash + Merkle root). Even after the entries
leave cold storage, the checkpoint proves what they were, and any single
archived entry stays provable via its Merkle proof against the checkpoint root.
"""
from _common import fresh_recorder, rule, step
from agentledger import RetentionPolicy, seal_segment, verify_checkpoint
from agentledger.evidence import verify_bundle
from agentledger.merkle import MerkleTree, verify_proof


def main() -> None:
    rule("RETENTION + CHECKPOINT  -  seal old history, keep it provable")

    rec = fresh_recorder()
    step(1, "Record a long-running ledger (12 directives).")
    for i in range(12):
        rec.submit("agent", f"act{i}", {"i": i})
    print(f"   {len(rec.entries())} entries live.")

    step(2, "Seal everything but the newest 4 into a signed archive + checkpoint.")
    result = seal_segment(rec.ledger, rec.signer, RetentionPolicy(keep_last=4))
    cp = result.checkpoint
    print(f"   sealed seqs {cp.segment_start_seq}..{cp.segment_end_seq} "
          f"({cp.entry_count} entries)")
    print(f"   archived_head_hash = {cp.archived_head_hash[:24]}...")
    print(f"   merkle_root        = {cp.merkle_root[:24]}...")
    print(f"   live ledger still intact: {len(rec.entries())} entries "
          "(sealing is export + attest, not delete)")

    step(3, "The checkpoint is signed - verify it offline.")
    print(f"   verify_checkpoint(cp) -> {verify_checkpoint(cp)}")

    step(4, "The archive bundle verifies on its own, no live ledger needed.")
    ok, _ = verify_bundle(result.bundle)
    print(f"   verify_bundle(archive) -> {ok}")

    step(5, "A single archived entry stays provable against the checkpoint root.")
    tree = MerkleTree(result.sealed)
    proof = tree.prove(result.sealed[0].seq)
    matches = tree.root() == cp.merkle_root
    print(f"   rebuilt root == checkpoint root: {matches}")
    print(f"   verify_proof(entry, checkpoint_root) -> "
          f"{verify_proof(proof, expected_root=cp.merkle_root)}")

    print("\nOld history can go to cold storage; the checkpoint keeps it accountable.")


if __name__ == "__main__":
    main()
