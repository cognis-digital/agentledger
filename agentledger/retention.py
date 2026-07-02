"""Retention & segment-rotation policy for the append-only ledger.

An append-only, hash-chained ledger grows forever. In production you eventually
need to archive old history and start a fresh, smaller active segment — without
breaking the ability to prove the old history was intact and that the new
segment continues from it.

This module does that safely:

  * `RetentionPolicy` decides *which* entries are eligible to be sealed off
    (by age or by count), never touching anything you might still need live.
  * `seal_segment` exports the eligible prefix as a signed evidence bundle
    (the archive), computes a Merkle root over it, and returns a `Checkpoint`
    that commits to the archived head hash + Merkle root. The checkpoint is the
    tamper-evident anchor: even after the entries leave the active ledger, the
    checkpoint proves what they were, and any single archived entry can still be
    proven included via its Merkle proof against the checkpoint root.

Crucially this does NOT delete from the live ledger's chain — deleting a prefix
would orphan `prev_hash` links and fail `verify()`. Sealing is *export +
attest*; pruning the physical rows is an operator decision made against the
archive, out of scope for the signed core. We give you the archive and the
proof; what you do with cold storage is your policy.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import List, Optional

from . import evidence
from .ledger import Entry
from .merkle import MerkleTree
from .signing import Signer


@dataclass(frozen=True)
class RetentionPolicy:
    """Which entries are eligible to be sealed into an archive segment.

    Provide at most one of `max_age_seconds` (seal entries older than this) or
    `keep_last` (keep the newest N live, seal the rest). If neither is set,
    nothing is eligible.
    """
    max_age_seconds: Optional[float] = None
    keep_last: Optional[int] = None

    def eligible(self, entries: List[Entry], *, now: Optional[float] = None) -> List[Entry]:
        """The contiguous prefix of `entries` eligible for sealing.

        We only ever seal a *prefix* (oldest-first, contiguous in seq): the
        chain is linear, so an archive must be a prefix to remain independently
        verifiable and to leave the live tail continuous.
        """
        if not entries:
            return []
        ordered = sorted(entries, key=lambda e: e.seq)
        if self.keep_last is not None:
            if self.keep_last < 0:
                raise ValueError("keep_last must be >= 0")
            cutoff = max(0, len(ordered) - self.keep_last)
            return ordered[:cutoff]
        if self.max_age_seconds is not None:
            now = time.time() if now is None else now
            threshold = now - self.max_age_seconds
            prefix: List[Entry] = []
            for e in ordered:
                if e.ts < threshold:
                    prefix.append(e)
                else:
                    break  # stop at the first still-fresh entry (prefix only)
            return prefix
        return []


CHECKPOINT_FORMAT = "agentledger-checkpoint/1"


@dataclass(frozen=True)
class Checkpoint:
    """A signed anchor over a sealed segment (archive prefix)."""
    format: str
    created_at: float
    segment_start_seq: int
    segment_end_seq: int
    entry_count: int
    archived_head_hash: str
    merkle_root: str
    algorithm: str
    public_key: str
    signature: str

    def payload(self) -> dict:
        return {
            "format": self.format, "created_at": self.created_at,
            "segment_start_seq": self.segment_start_seq,
            "segment_end_seq": self.segment_end_seq,
            "entry_count": self.entry_count,
            "archived_head_hash": self.archived_head_hash,
            "merkle_root": self.merkle_root,
            "algorithm": self.algorithm,
        }

    def as_dict(self) -> dict:
        d = self.payload()
        d.update({"public_key": self.public_key, "signature": self.signature})
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Checkpoint":
        return cls(
            format=d["format"], created_at=d["created_at"],
            segment_start_seq=d["segment_start_seq"],
            segment_end_seq=d["segment_end_seq"], entry_count=d["entry_count"],
            archived_head_hash=d["archived_head_hash"],
            merkle_root=d["merkle_root"], algorithm=d["algorithm"],
            public_key=d["public_key"], signature=d["signature"],
        )


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class SealResult:
    checkpoint: Checkpoint
    bundle: dict
    sealed: List[Entry]


def seal_segment(ledger, signer: Signer, policy: RetentionPolicy, *,
                 archive_path: Optional[str] = None,
                 now: Optional[float] = None) -> Optional[SealResult]:
    """Seal the policy-eligible prefix into a signed archive + checkpoint.

    Returns None if nothing is eligible. Otherwise returns a `SealResult` with
    the signed evidence bundle (optionally written to `archive_path`), a signed
    checkpoint anchoring the archived head hash + Merkle root, and the list of
    sealed entries. The live ledger is not modified.
    """
    entries = list(ledger)
    eligible = policy.eligible(entries, now=now)
    if not eligible:
        return None

    # Build an evidence bundle over exactly the sealed prefix. We reuse the
    # canonical bundle format by exporting the prefix as its own entry list.
    prefix_dicts = [e.as_dict() for e in eligible]
    from .ledger import GENESIS
    bundle = {
        "format": evidence.FORMAT,
        "exported_at": time.time() if now is None else now,
        "algorithm": signer.algorithm,
        "third_party_verifiable": signer.third_party_verifiable,
        "entry_count": len(prefix_dicts),
        "head_hash": prefix_dicts[-1]["entry_hash"] if prefix_dicts else GENESIS,
        "entries": prefix_dicts,
    }
    if archive_path:
        with open(archive_path, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, indent=2)

    tree = MerkleTree(eligible)
    created = time.time() if now is None else now
    payload = {
        "format": CHECKPOINT_FORMAT, "created_at": created,
        "segment_start_seq": eligible[0].seq,
        "segment_end_seq": eligible[-1].seq,
        "entry_count": len(eligible),
        "archived_head_hash": eligible[-1].entry_hash,
        "merkle_root": tree.root(),
        "algorithm": signer.algorithm,
    }
    signature = signer.sign(_canonical(payload)).hex()
    checkpoint = Checkpoint(
        **payload, public_key=signer.public_bytes().hex(), signature=signature)
    return SealResult(checkpoint=checkpoint, bundle=bundle, sealed=list(eligible))


def verify_checkpoint(checkpoint: Checkpoint, *, secret: Optional[bytes] = None) -> bool:
    """Verify a checkpoint's signature over its canonical payload (offline)."""
    from .signing import verifier_for

    if checkpoint.format != CHECKPOINT_FORMAT:
        return False
    try:
        verifier = verifier_for(checkpoint.algorithm, secret)
    except (RuntimeError, ValueError):
        return False
    try:
        return verifier.verify(
            _canonical(checkpoint.payload()),
            bytes.fromhex(checkpoint.signature),
            bytes.fromhex(checkpoint.public_key))
    except (ValueError, TypeError):
        return False
