"""agentledger — a vendor-neutral flight recorder for AI agents.

The question that actually keeps enterprises up at night is not "does the model
hallucinate" — it's "an agent did something; who authorized it, and can we
prove it." agentledger answers that, for *any* agent framework, by recording
every operator directive in a cryptographically-signed, hash-chained ledger:

  * each directive is signed (Ed25519 when available, HMAC fallback) so its
    origin can't be forged;
  * each entry's hash commits to the previous one, so the history can't be
    silently edited or reordered;
  * directives pass through a policy gate before they're recorded as allowed,
    so "what was permitted" is part of the record, not an afterthought;
  * the whole ledger exports to a self-contained evidence bundle that a third
    party can verify offline, with no call back to any vendor.

It deliberately knows nothing about how your agents run. It sits in front of
them and writes down what happened.
"""

from .signing import (
    Signer, Verifier, new_signer, signer_from, save_key, load_key,
)
from .policy import Decision, PolicyGate
from .ledger import Entry, Ledger
from .recorder import ApprovalStatus, Recorder
from .sinks import (
    Sink, JSONLinesSink, CallableSink, SyslogSink, HttpSink,
    SplunkHecSink, ElasticSink, SignedWebhookSink,
)
from .query import Query
from .merkle import MerkleTree, InclusionProof, ProofStep, verify_proof
from .retention import (
    RetentionPolicy, Checkpoint, SealResult, seal_segment, verify_checkpoint,
)
from . import exporters

__version__ = "0.2.0"
__all__ = [
    "Recorder", "ApprovalStatus", "Ledger", "Entry", "PolicyGate", "Decision",
    "Signer", "Verifier", "new_signer", "signer_from", "save_key", "load_key",
    "Sink", "JSONLinesSink", "CallableSink", "SyslogSink", "HttpSink",
    "SplunkHecSink", "ElasticSink", "SignedWebhookSink",
    "Query", "MerkleTree", "InclusionProof", "ProofStep", "verify_proof",
    "RetentionPolicy", "Checkpoint", "SealResult", "seal_segment",
    "verify_checkpoint", "exporters",
    "__version__",
]
