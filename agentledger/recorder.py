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

from . import evidence
from .ledger import Entry, Ledger
from .policy import Decision, PolicyGate
from .signing import Signer, new_signer
from .sinks import Sink


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
        """Record what happened when an agent acted on a directive."""
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

    def verify(self, check_continuity: bool = True) -> Tuple[bool, Optional[int]]:
        return self.ledger.verify(check_continuity=check_continuity)

    def entries(self) -> list[Entry]:
        return self.ledger.all()

    def export_evidence(self, path: Optional[str] = None) -> dict:
        return evidence.export(self.ledger, self.signer, path)
