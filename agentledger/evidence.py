"""Evidence bundles: self-contained, offline-verifiable exports.

An evidence bundle is a single JSON document containing every ledger entry plus
the metadata needed to check it without the original database or any network
call. `verify_bundle` reconstructs the hash chain and (for Ed25519) the
signatures from the bundle alone — the property that lets you hand a regulator
or an insurer a file they can independently validate.
"""

from __future__ import annotations

import json
import time
from typing import Optional, Tuple

from .ledger import GENESIS, Entry, compute_hash
from .signing import Signer, verifier_for

FORMAT = "agentledger-evidence/1"


def export(ledger, signer: Signer, path: Optional[str] = None) -> dict:
    entries = [e.as_dict() for e in ledger]
    bundle = {
        "format": FORMAT,
        "exported_at": time.time(),
        "algorithm": signer.algorithm,
        "third_party_verifiable": signer.third_party_verifiable,
        "entry_count": len(entries),
        "head_hash": entries[-1]["entry_hash"] if entries else GENESIS,
        "entries": entries,
    }
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, indent=2)
    return bundle


def _payload_from_dict(d: dict) -> dict:
    return {
        "seq": d["seq"], "ts": d["ts"], "kind": d["kind"], "actor": d["actor"],
        "action": d["action"], "params": d["params"], "decision": d["decision"],
        "ref": d["ref"], "prev_hash": d["prev_hash"],
    }


def verify_bundle(bundle: dict, secret: Optional[bytes] = None) -> Tuple[bool, Optional[int]]:
    """Validate a bundle with no access to the original ledger.

    Returns (ok, first_broken_seq). For HMAC bundles, pass the signing `secret`
    to also check signatures; without it, only the hash chain is validated.
    """
    if bundle.get("format") != FORMAT:
        return False, None
    entries = bundle.get("entries", [])
    algorithm = bundle.get("algorithm", "")

    verifier = None
    try:
        verifier = verifier_for(algorithm, secret)
    except RuntimeError:
        verifier = None  # can't check signatures offline; chain-only

    prev = GENESIS
    authorized = None
    for i, d in enumerate(entries):
        if d["prev_hash"] != prev:
            return False, d["seq"]
        if compute_hash(d["prev_hash"], _payload_from_dict(d)) != d["entry_hash"]:
            return False, d["seq"]
        if verifier is not None:
            ok = verifier.verify(
                d["entry_hash"].encode("ascii"),
                bytes.fromhex(d["signature"]),
                bytes.fromhex(d["public_key"]),
            )
            if not ok:
                return False, d["seq"]
        # key-continuity: a new signing key must be introduced by a prior
        # key_rotation entry that names it (see Ledger.verify for rationale)
        if authorized is None:
            authorized = d["public_key"]
        elif d["public_key"] != authorized:
            prev_d = entries[i - 1]
            if not (prev_d.get("kind") == "key_rotation"
                    and prev_d.get("params", {}).get("new_public_key") == d["public_key"]):
                return False, d["seq"]
            authorized = d["public_key"]
        prev = d["entry_hash"]

    if bundle.get("head_hash") and entries and bundle["head_hash"] != prev:
        return False, entries[-1]["seq"]
    return True, None
