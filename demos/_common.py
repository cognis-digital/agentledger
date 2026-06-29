"""Shared helpers for the demo scenarios.

Every scenario builds its own in-memory Recorder so the demos are independent,
need no network, leave nothing on disk (unless a scenario explicitly writes a
bundle to a temp file), and can run in any order or on their own.
"""
from __future__ import annotations

import os
import sys

# Windows consoles default to cp1252; force UTF-8 so narrated output with box
# characters never raises UnicodeEncodeError when a demo is run directly.
os.environ.setdefault("PYTHONUTF8", "1")
try:  # reconfigure already-open streams (PYTHONUTF8 only affects new ones)
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:  # pragma: no cover - older Pythons / non-TTY
    pass

# allow `python demos/NN_xxx.py` from anywhere
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentledger import PolicyGate, Recorder  # noqa: E402
from agentledger.signing import _HAVE_ED25519, _HAVE_MLDSA, new_signer  # noqa: E402


def rule(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def step(n: int, text: str) -> None:
    print(f"\n{n}) {text}")


def best_signer(prefer: str = "ed25519"):
    """Return a signer for `prefer`, degrading gracefully on minimal installs.

    The demos prefer asymmetric, offline-verifiable signatures, but must still
    run (and exit 0) on a stdlib-only box where only HMAC is available.
    """
    if prefer in ("ml-dsa", "mldsa") and not _HAVE_MLDSA:
        prefer = "ed25519"
    if prefer == "hybrid" and not (_HAVE_ED25519 and _HAVE_MLDSA):
        prefer = "ed25519"
    if prefer == "ed25519" and not _HAVE_ED25519:
        prefer = "hmac"
    return new_signer(prefer)


def fresh_recorder(gate: PolicyGate | None = None, prefer: str = "ed25519") -> Recorder:
    """A throwaway in-memory Recorder, no network, nothing persisted."""
    return Recorder(gate=gate or PolicyGate(default_allow=True),
                    signer=best_signer(prefer))
