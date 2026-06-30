"""The flight recorder: the one object most callers use.

Typical flow around any agent:

    rec = Recorder(gate=my_gate)
    decision, entry = rec.submit("alice", "deploy", {"env": "prod"})
    if decision.allowed:
        result = run_the_agent(...)
        rec.record_outcome(entry.seq, "agent:deployer", "success", {"build": 421})

Denied directives are still recorded (with the decision) — refusing to write
them down would defeat the purpose. The caller decides whether to execute; the
recorder guarantees there's a signed, chained record either way.
"""

from __future__ import annotations

from typing import Optional, Tuple

from dataclasses import dataclass

from . import evidence
from .ledger import Entry, Ledger
from .policy import Decision, PolicyGate
from .signing import Signer, new_signer, verifier_for
from .sinks import Sink


@dataclass(frozen=True)
class ApprovalStatus:
    directive_seq: int
    threshold: int
    approver_keys: list           # distinct public keys with a valid approval signature
    satisfied: bool

    def as_dict(self) -> dict:
        return {"directive_seq": self.directive_seq, "threshold": self.threshold,
                "approvals": len(self.approver_keys), "satisfied": self.satisfied,
                "approver_keys": self.approver_keys}


class Recorder:
    def __init__(self, gate: Optional[PolicyGate] = None,
                 signer: Optional[Signer] = None, db_path: str = ":memory:",
                 sinks: Optional[list[Sink]] = None):
        self.gate = gate or PolicyGate()
        self.signer = signer or new_signer()
        self.ledger = Ledger(self.signer, db_path, sinks=sinks)

    def submit(self, actor: str, action: str, params: Optional[dict] = None) -> Tuple[Decision, Entry]:
        """Evaluate a directive against the policy gate and record it (signed)."""
        params = params or {}
        directive = {"actor": actor, "action": action, "params": params}
        decision = self.gate.evaluate(directive)
        entry = self.ledger.append("directive", actor, action, params, decision.as_dict())
        return decision, entry

    def record_outcome(self, ref_seq: int, actor: str, status: str,
                       detail: Optional[dict] = None) -> Entry:
        """Record what happened when an agent acted on a directive.

        `ref_seq` must name an entry that already exists; recording an outcome
        against a directive that was never submitted would leave a dangling
        reference in the evidence, so it raises instead.
        """
        if self.ledger.get(ref_seq) is None:
            raise ValueError(
                f"cannot record outcome: no directive with seq {ref_seq}")
        return self.ledger.append("outcome", actor, status, detail or {}, ref=ref_seq)

    def rotate_key(self, new_signer: Signer, actor: str = "operator") -> Entry:
        """Rotate the signing key, leaving a continuity proof in the ledger.

        The *outgoing* key signs a `key_rotation` entry that names the new
        public key, so verification can prove the new key was authorized by the
        old one. Subsequent entries are signed by the new key.
        """
        entry = self.ledger.append(
            "key_rotation", actor, "rotate",
            {"new_algorithm": new_signer.algorithm,
             "new_public_key": new_signer.public_bytes().hex()},
        )
        self.signer = new_signer
        self.ledger.signer = new_signer
        return entry

    def approve(self, directive_seq: int, approver: str, signer: Signer) -> Entry:
        """Record one operator's approval of a directive (m-of-n multi-sig).

        The approver signs the directive's `entry_hash` with their *own* key; the
        signature and public key go into an `approval` entry. Because the
        signature is over the directive's hash, it can't be replayed onto a
        different directive, and distinct keys count as distinct approvers.
        """
        target = self.ledger.get(directive_seq)
        if target is None:
            raise ValueError(f"no entry with seq {directive_seq}")
        signature = signer.sign(target.entry_hash.encode("ascii")).hex()
        detail = {
            "approver": approver,
            "algorithm": signer.algorithm,
            "public_key": signer.public_bytes().hex(),
            "signature": signature,
            "over": target.entry_hash,
        }
        return self.ledger.append("approval", approver, "approve", detail, ref=directive_seq)

    def approval_status(self, directive_seq: int, threshold: int,
                        allowed_keys: Optional[set] = None) -> ApprovalStatus:
        """Whether a directive has `threshold` distinct valid approvals.

        Each approval's signature is verified against the directive's hash. Only
        distinct public keys with a valid signature count; if `allowed_keys` is
        given, approvals from keys outside that allowlist are ignored.
        """
        target = self.ledger.get(directive_seq)
        if target is None:
            raise ValueError(f"no entry with seq {directive_seq}")
        valid: set = set()
        for e in self.ledger.entries_referencing(directive_seq, kind="approval"):
            d = e.params
            try:
                v = verifier_for(d["algorithm"])
            except (RuntimeError, KeyError):
                continue  # e.g. hmac (no third-party verification) — skip
            ok = v.verify(target.entry_hash.encode("ascii"),
                          bytes.fromhex(d["signature"]), bytes.fromhex(d["public_key"]))
            if ok and (allowed_keys is None or d["public_key"] in allowed_keys):
                valid.add(d["public_key"])
        return ApprovalStatus(directive_seq, threshold, sorted(valid), len(valid) >= threshold)

    def verify(self, check_continuity: bool = True) -> Tuple[bool, Optional[int]]:
        return self.ledger.verify(check_continuity=check_continuity)

    def entries(self) -> list[Entry]:
        return self.ledger.all()

    def export_evidence(self, path: Optional[str] = None) -> dict:
        return evidence.export(self.ledger, self.signer, path)
