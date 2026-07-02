"""Merkle tree over ledger entries + single-entry inclusion proofs.

The hash chain already makes the ledger tamper-evident *as a whole* — but to
prove a *single* entry belongs to a committed ledger you would otherwise have to
hand over every entry. A Merkle tree gives you a compact alternative: publish
one root hash (e.g. anchor it in another system, a transparency log, or a
notarized document), then for any entry produce an O(log n) inclusion proof that
verifies against that root without revealing the other entries.

Design notes:
  * Leaves commit to each entry's `entry_hash` (already a blake2b-256 digest of
    the entry's canonical payload + prev_hash), domain-separated with a 0x00
    prefix. Internal nodes use a 0x01 prefix. This standard leaf/node domain
    separation prevents second-preimage attacks that swap a leaf for an internal
    node.
  * Odd nodes at a level are promoted (duplicated) — the common, simple
    convention. The tree is built left-to-right over entries in seq order.
  * Everything is blake2b-256 to match the rest of the ledger; no dependencies.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import List, Optional

from .ledger import Entry

_LEAF = b"\x00"
_NODE = b"\x01"


def _h(*chunks: bytes) -> str:
    d = hashlib.blake2b(digest_size=32)
    for c in chunks:
        d.update(c)
    return d.hexdigest()


def leaf_hash(entry_hash: str) -> str:
    """Domain-separated leaf digest for one entry's `entry_hash` (hex)."""
    return _h(_LEAF, bytes.fromhex(entry_hash))


def _node_hash(left: str, right: str) -> str:
    return _h(_NODE, bytes.fromhex(left), bytes.fromhex(right))


@dataclass(frozen=True)
class ProofStep:
    """One sibling on the path from a leaf to the root."""
    sibling: str          # hex digest of the sibling node
    is_right: bool        # True if the sibling sits to the RIGHT of our node

    def as_dict(self) -> dict:
        return {"sibling": self.sibling, "is_right": self.is_right}


@dataclass(frozen=True)
class InclusionProof:
    """A compact proof that one entry is in a tree with a given root."""
    seq: int
    leaf_index: int
    entry_hash: str
    root: str
    tree_size: int
    steps: List[ProofStep]

    def as_dict(self) -> dict:
        return {
            "format": "agentledger-merkle-proof/1",
            "seq": self.seq,
            "leaf_index": self.leaf_index,
            "entry_hash": self.entry_hash,
            "root": self.root,
            "tree_size": self.tree_size,
            "steps": [s.as_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "InclusionProof":
        return cls(
            seq=d["seq"], leaf_index=d["leaf_index"], entry_hash=d["entry_hash"],
            root=d["root"], tree_size=d["tree_size"],
            steps=[ProofStep(s["sibling"], s["is_right"]) for s in d["steps"]],
        )


class MerkleTree:
    """A Merkle tree over ledger entries, in seq order."""

    def __init__(self, entries: List[Entry]):
        self._entries = list(entries)
        self._entry_hashes = [e.entry_hash for e in self._entries]
        self._leaves = [leaf_hash(h) for h in self._entry_hashes]
        # levels[0] = leaves; levels[-1] = [root]
        self._levels: List[List[str]] = self._build(self._leaves)

    @staticmethod
    def _build(leaves: List[str]) -> List[List[str]]:
        if not leaves:
            # Empty-tree convention: root is the digest of nothing, domain-sep'd.
            return [[_h(_LEAF)]]
        levels = [list(leaves)]
        cur = leaves
        while len(cur) > 1:
            nxt: List[str] = []
            for i in range(0, len(cur), 2):
                left = cur[i]
                right = cur[i + 1] if i + 1 < len(cur) else cur[i]  # promote odd
                nxt.append(_node_hash(left, right))
            levels.append(nxt)
            cur = nxt
        return levels

    @classmethod
    def from_ledger(cls, ledger) -> "MerkleTree":
        return cls(list(ledger))

    @property
    def size(self) -> int:
        return len(self._entries)

    def root(self) -> str:
        return self._levels[-1][0]

    def _index_for_seq(self, seq: int) -> int:
        for i, e in enumerate(self._entries):
            if e.seq == seq:
                return i
        raise KeyError(f"seq {seq} is not in this tree")

    def prove(self, seq: int) -> InclusionProof:
        """Build an inclusion proof for the entry with the given `seq`."""
        if self.size == 0:
            raise KeyError("cannot prove inclusion in an empty tree")
        idx = self._index_for_seq(seq)
        steps: List[ProofStep] = []
        pos = idx
        for level in self._levels[:-1]:  # every level except the root
            if pos % 2 == 0:  # we're a left child; sibling is to the right
                sib_idx = pos + 1 if pos + 1 < len(level) else pos  # promoted odd
                steps.append(ProofStep(level[sib_idx], is_right=True))
            else:             # we're a right child; sibling is to the left
                steps.append(ProofStep(level[pos - 1], is_right=False))
            pos //= 2
        return InclusionProof(
            seq=seq, leaf_index=idx, entry_hash=self._entry_hashes[idx],
            root=self.root(), tree_size=self.size, steps=steps)


def verify_proof(proof: InclusionProof, *, expected_root: Optional[str] = None) -> bool:
    """Recompute the root from a proof and compare it.

    If `expected_root` is given, the proof must reproduce exactly that root
    (this is the real check: you trust a root you obtained out-of-band and ask
    whether the entry is under it). Otherwise the proof is checked for internal
    consistency against its own embedded `root`.
    """
    try:
        acc = leaf_hash(proof.entry_hash)
        for step in proof.steps:
            if step.is_right:
                acc = _node_hash(acc, step.sibling)
            else:
                acc = _node_hash(step.sibling, acc)
    except (ValueError, TypeError):
        return False
    target = expected_root if expected_root is not None else proof.root
    # constant-time compare on the hex digests
    return hmac.compare_digest(acc, target)
