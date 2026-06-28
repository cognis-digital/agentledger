"""The signed, hash-chained intent ledger.

Each entry records one event — a directive being submitted (with its policy
decision) or an outcome being reported. Two integrity mechanisms stack:

  1. Hash chaining: an entry's `entry_hash` commits to the canonical contents
     plus the previous entry's hash, so reordering, editing, or deleting any
     entry breaks the chain from that point.
  2. Signature: the signer signs `entry_hash`, binding the entry to a key.
     With Ed25519 the public key in the entry lets anyone verify origin offline.

`verify()` replays both and returns the first sequence number that fails.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Iterator, Optional

from .signing import Signer, Verifier, verifier_for

GENESIS = "0" * 64


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_hash(prev_hash: str, payload: dict) -> str:
    h = hashlib.blake2b(digest_size=32)
    h.update(prev_hash.encode("ascii"))
    h.update(b"\x00")
    h.update(_canonical(payload))
    return h.hexdigest()


@dataclass(frozen=True)
class Entry:
    seq: int
    ts: float
    kind: str            # directive | outcome
    actor: str
    action: str
    params: dict
    decision: dict       # policy decision (empty for outcomes)
    ref: Optional[int]   # for outcomes, the directive seq it refers to
    prev_hash: str
    entry_hash: str
    algorithm: str
    public_key: str      # hex
    signature: str       # hex

    def payload(self) -> dict:
        return {
            "seq": self.seq, "ts": self.ts, "kind": self.kind, "actor": self.actor,
            "action": self.action, "params": self.params, "decision": self.decision,
            "ref": self.ref, "prev_hash": self.prev_hash,
        }

    def as_dict(self) -> dict:
        d = self.payload()
        d.update({"entry_hash": self.entry_hash, "algorithm": self.algorithm,
                  "public_key": self.public_key, "signature": self.signature})
        return d


class Ledger:
    def __init__(self, signer: Signer, db_path: str = ":memory:"):
        self.signer = signer
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         REAL NOT NULL,
                kind       TEXT NOT NULL,
                actor      TEXT NOT NULL,
                action     TEXT NOT NULL,
                params     TEXT NOT NULL,
                decision   TEXT NOT NULL,
                ref        INTEGER,
                prev_hash  TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                algorithm  TEXT NOT NULL,
                public_key TEXT NOT NULL,
                signature  TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def _last_hash(self) -> str:
        row = self.conn.execute(
            "SELECT entry_hash FROM entries ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS

    def append(self, kind: str, actor: str, action: str, params: dict,
               decision: Optional[dict] = None, ref: Optional[int] = None,
               *, ts: Optional[float] = None) -> Entry:
        ts = time.time() if ts is None else ts
        prev_hash = self._last_hash()
        row = self.conn.execute("SELECT COALESCE(MAX(seq),0) FROM entries").fetchone()
        seq = int(row[0]) + 1
        payload = {
            "seq": seq, "ts": ts, "kind": kind, "actor": actor, "action": action,
            "params": params, "decision": decision or {}, "ref": ref, "prev_hash": prev_hash,
        }
        entry_hash = compute_hash(prev_hash, payload)
        signature = self.signer.sign(entry_hash.encode("ascii")).hex()
        public_key = self.signer.public_bytes().hex()
        self.conn.execute(
            "INSERT INTO entries (seq, ts, kind, actor, action, params, decision, ref, "
            "prev_hash, entry_hash, algorithm, public_key, signature) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (seq, ts, kind, actor, action, json.dumps(params), json.dumps(decision or {}),
             ref, prev_hash, entry_hash, self.signer.algorithm, public_key, signature),
        )
        self.conn.commit()
        return self._row(self.conn.execute(
            "SELECT * FROM entries WHERE seq=?", (seq,)).fetchone())

    @staticmethod
    def _row(r) -> Entry:
        return Entry(
            seq=r[0], ts=r[1], kind=r[2], actor=r[3], action=r[4],
            params=json.loads(r[5]), decision=json.loads(r[6]), ref=r[7],
            prev_hash=r[8], entry_hash=r[9], algorithm=r[10],
            public_key=r[11], signature=r[12],
        )

    def __iter__(self) -> Iterator[Entry]:
        for r in self.conn.execute("SELECT * FROM entries ORDER BY seq ASC"):
            yield self._row(r)

    def all(self) -> list[Entry]:
        return list(self)

    def verify(self, verifier: Optional[Verifier] = None,
               check_continuity: bool = True) -> tuple[bool, Optional[int]]:
        """Replay hash chain + signatures (+ key continuity). Returns (ok, seq).

        Continuity: a per-entry signature only proves the entry is internally
        consistent — an attacker who appends with their own key would pass that
        check. So we also require that any change of signing key is introduced by
        a `key_rotation` entry signed by the *previous* (authorized) key that
        names the new public key. Without that, a new key is rejected.
        """
        entries = self.all()
        prev = GENESIS
        authorized: Optional[str] = None
        for i, e in enumerate(entries):
            if e.prev_hash != prev:
                return False, e.seq
            if compute_hash(e.prev_hash, e.payload()) != e.entry_hash:
                return False, e.seq

            v = verifier
            sig_checkable = True
            if v is None or v.algorithm != e.algorithm:
                try:
                    v = self._verifier_for_entry(e)
                except RuntimeError:
                    # can't verify signature offline (e.g. hmac without secret);
                    # chain + continuity below still validate
                    sig_checkable = False
            if sig_checkable and not v.verify(
                    e.entry_hash.encode("ascii"),
                    bytes.fromhex(e.signature), bytes.fromhex(e.public_key)):
                return False, e.seq

            if check_continuity:
                if authorized is None:
                    authorized = e.public_key
                elif e.public_key != authorized:
                    prev_e = entries[i - 1]
                    if not (prev_e.kind == "key_rotation"
                            and prev_e.params.get("new_public_key") == e.public_key):
                        return False, e.seq
                    authorized = e.public_key

            prev = e.entry_hash
        return True, None

    def _verifier_for_entry(self, e: Entry) -> Verifier:
        # the live signer can always verify its own algorithm
        if e.algorithm == self.signer.algorithm:
            return self.signer.verifier()
        return verifier_for(e.algorithm)
