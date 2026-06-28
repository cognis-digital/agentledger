"""Pluggable signing backends.

Ed25519 is the default and the point of the design: it is asymmetric, so an
auditor can verify a directive's origin offline using only the public key
embedded in the evidence bundle — no shared secret, no vendor call. When the
`cryptography` package isn't installed, we fall back to HMAC-SHA256 so the
ledger still functions; HMAC is symmetric, so third-party verification then
requires the signing secret (the bundle says so honestly).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Optional

try:  # real asymmetric signatures when available
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _HAVE_ED25519 = True
except Exception:  # pragma: no cover - exercised only on minimal installs
    _HAVE_ED25519 = False

try:  # post-quantum signatures (ML-DSA / FIPS 204) on newer cryptography
    from cryptography.hazmat.primitives.asymmetric.mldsa import (
        MLDSA65PrivateKey,
        MLDSA65PublicKey,
    )

    _HAVE_MLDSA = True
except Exception:  # pragma: no cover - older cryptography without PQC
    _HAVE_MLDSA = False


def _lp(b: bytes) -> bytes:
    """Length-prefix a byte string (4-byte big-endian length + payload)."""
    return len(b).to_bytes(4, "big") + b


def _unlp(data: bytes) -> tuple[bytes, bytes]:
    """Split off one length-prefixed chunk; return (chunk, remainder)."""
    n = int.from_bytes(data[:4], "big")
    return data[4:4 + n], data[4 + n:]


class Signer:
    """Signs messages and exposes the public material needed to verify them."""

    algorithm: str = "abstract"
    third_party_verifiable: bool = False

    def sign(self, message: bytes) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def public_bytes(self) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def private_bytes(self) -> bytes:  # pragma: no cover - interface
        """Raw private key material, for persisting and reloading the signer."""
        raise NotImplementedError

    def verifier(self) -> "Verifier":  # pragma: no cover - interface
        raise NotImplementedError


class Verifier:
    algorithm: str = "abstract"

    def verify(self, message: bytes, signature: bytes, public_bytes: bytes) -> bool:  # pragma: no cover
        raise NotImplementedError


# ---- Ed25519 (preferred) -------------------------------------------------
class Ed25519Signer(Signer):
    algorithm = "ed25519"
    third_party_verifiable = True

    def __init__(self, private_bytes: Optional[bytes] = None):
        if private_bytes is not None:
            self._key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        else:
            self._key = Ed25519PrivateKey.generate()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def public_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def private_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def verifier(self) -> "Verifier":
        return Ed25519Verifier()


class Ed25519Verifier(Verifier):
    algorithm = "ed25519"

    def verify(self, message: bytes, signature: bytes, public_bytes: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, message)
            return True
        except Exception:
            return False


# ---- ML-DSA / FIPS 204 (post-quantum) ------------------------------------
class MLDSA65Signer(Signer):
    algorithm = "ml-dsa-65"
    third_party_verifiable = True

    def __init__(self, private_bytes: Optional[bytes] = None):
        # ML-DSA private material is a 32-byte seed; reconstruct via from_seed_bytes
        if private_bytes is not None:
            self._key = MLDSA65PrivateKey.from_seed_bytes(private_bytes)
        else:
            self._key = MLDSA65PrivateKey.generate()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def public_bytes(self) -> bytes:
        return self._key.public_key().public_bytes_raw()

    def private_bytes(self) -> bytes:
        return self._key.private_bytes_raw()

    def verifier(self) -> "Verifier":
        return MLDSA65Verifier()


class MLDSA65Verifier(Verifier):
    algorithm = "ml-dsa-65"

    def verify(self, message: bytes, signature: bytes, public_bytes: bytes) -> bool:
        try:
            MLDSA65PublicKey.from_public_bytes(public_bytes).verify(signature, message)
            return True
        except Exception:
            return False


# ---- HMAC fallback -------------------------------------------------------
class HmacSigner(Signer):
    algorithm = "hmac-sha256"
    third_party_verifiable = False  # needs the shared secret

    def __init__(self, secret: Optional[bytes] = None):
        self._secret = secret or secrets.token_bytes(32)

    def sign(self, message: bytes) -> bytes:
        return hmac.new(self._secret, message, hashlib.sha256).digest()

    def public_bytes(self) -> bytes:
        # not secret-revealing: a stable fingerprint of the key
        return hashlib.sha256(b"fpr:" + self._secret).digest()

    def private_bytes(self) -> bytes:
        return self._secret

    def verifier(self) -> "Verifier":
        return HmacVerifier(self._secret)


class HmacVerifier(Verifier):
    algorithm = "hmac-sha256"

    def __init__(self, secret: bytes):
        self._secret = secret

    def verify(self, message: bytes, signature: bytes, public_bytes: bytes) -> bool:
        expected = hmac.new(self._secret, message, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)


# ---- Hybrid (classical + post-quantum) -----------------------------------
class HybridSigner(Signer):
    """Signs with Ed25519 *and* ML-DSA-65; a verifier must satisfy both.

    This is the conservative migration choice: you keep a battle-tested
    classical signature while adding post-quantum protection, so a break in
    either algorithm alone doesn't forge a directive.
    """

    algorithm = "hybrid-ed25519-ml-dsa-65"
    third_party_verifiable = True

    def __init__(self, ed: Optional["Ed25519Signer"] = None,
                 pq: Optional["MLDSA65Signer"] = None):
        self.ed = ed or Ed25519Signer()
        self.pq = pq or MLDSA65Signer()

    def sign(self, message: bytes) -> bytes:
        return _lp(self.ed.sign(message)) + _lp(self.pq.sign(message))

    def public_bytes(self) -> bytes:
        return _lp(self.ed.public_bytes()) + _lp(self.pq.public_bytes())

    def private_bytes(self) -> bytes:
        return _lp(self.ed.private_bytes()) + _lp(self.pq.private_bytes())

    def verifier(self) -> "Verifier":
        return HybridVerifier()

    @classmethod
    def from_private(cls, data: bytes) -> "HybridSigner":
        ed_priv, rest = _unlp(data)
        pq_priv, _ = _unlp(rest)
        return cls(Ed25519Signer(ed_priv), MLDSA65Signer(pq_priv))


class HybridVerifier(Verifier):
    algorithm = "hybrid-ed25519-ml-dsa-65"

    def verify(self, message: bytes, signature: bytes, public_bytes: bytes) -> bool:
        try:
            ed_sig, rest = _unlp(signature)
            pq_sig, _ = _unlp(rest)
            ed_pub, rest2 = _unlp(public_bytes)
            pq_pub, _ = _unlp(rest2)
        except Exception:
            return False
        return (Ed25519Verifier().verify(message, ed_sig, ed_pub)
                and MLDSA65Verifier().verify(message, pq_sig, pq_pub))


def new_signer(prefer: str = "ed25519", **kwargs) -> Signer:
    """Construct a signer. Falls back to HMAC if the asymmetric backend is absent.

    prefer:
      "ed25519"           classical asymmetric (default)
      "ml-dsa" / "mldsa"  post-quantum (ML-DSA-65, FIPS 204)
      "hmac"              symmetric, standard-library only
    """
    if prefer == "ed25519":
        return Ed25519Signer(**kwargs) if _HAVE_ED25519 else HmacSigner(**kwargs)
    if prefer in ("ml-dsa", "mldsa", "ml-dsa-65", "mldsa65"):
        if _HAVE_MLDSA:
            return MLDSA65Signer(**kwargs)
        raise RuntimeError(
            "ml-dsa requires a 'cryptography' build with ML-DSA support (FIPS 204)")
    if prefer == "hybrid":
        if _HAVE_ED25519 and _HAVE_MLDSA:
            return HybridSigner(**kwargs)
        raise RuntimeError("hybrid requires both Ed25519 and ML-DSA support")
    if prefer in ("hmac", "hmac-sha256"):
        return HmacSigner(**kwargs)
    raise ValueError(f"unknown signer preference: {prefer}")


def verifier_for(algorithm: str, secret: Optional[bytes] = None) -> Verifier:
    """A verifier for an algorithm name (for verifying an exported bundle)."""
    if algorithm == "ed25519":
        if not _HAVE_ED25519:
            raise RuntimeError("ed25519 bundle requires the 'cryptography' package to verify")
        return Ed25519Verifier()
    if algorithm == "ml-dsa-65":
        if not _HAVE_MLDSA:
            raise RuntimeError("ml-dsa-65 bundle requires a 'cryptography' build with ML-DSA")
        return MLDSA65Verifier()
    if algorithm == "hybrid-ed25519-ml-dsa-65":
        if not (_HAVE_ED25519 and _HAVE_MLDSA):
            raise RuntimeError("hybrid bundle requires Ed25519 and ML-DSA support")
        return HybridVerifier()
    if algorithm == "hmac-sha256":
        if secret is None:
            raise RuntimeError("hmac bundle requires the signing secret to verify")
        return HmacVerifier(secret)
    raise ValueError(f"unknown algorithm: {algorithm}")


def signer_from(algorithm: str, private_bytes: bytes) -> Signer:
    """Reconstruct a signer from its algorithm name and raw private material."""
    if algorithm == "ed25519":
        return Ed25519Signer(private_bytes)
    if algorithm == "ml-dsa-65":
        return MLDSA65Signer(private_bytes)
    if algorithm == "hybrid-ed25519-ml-dsa-65":
        return HybridSigner.from_private(private_bytes)
    if algorithm == "hmac-sha256":
        return HmacSigner(private_bytes)
    raise ValueError(f"unknown algorithm: {algorithm}")


def save_key(signer: Signer, path: str) -> None:
    """Persist a signer's key to disk (JSON: algorithm + hex private material).

    The file contains private key material — store it with appropriate
    filesystem permissions / secret management.
    """
    import json
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"algorithm": signer.algorithm,
                   "private": signer.private_bytes().hex()}, fh)


def load_key(path: str) -> Signer:
    """Reconstruct a signer previously written with `save_key`."""
    import json
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return signer_from(data["algorithm"], bytes.fromhex(data["private"]))
