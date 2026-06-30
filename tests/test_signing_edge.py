"""Signing backend edge cases: round-trips, isolation, reconstruction, errors."""
import pytest

from agentledger.signing import (
    Ed25519Signer,
    HmacSigner,
    HmacVerifier,
    _HAVE_ED25519,
    _HAVE_MLDSA,
    _lp,
    _unlp,
    load_key,
    new_signer,
    save_key,
    signer_from,
    verifier_for,
)


def test_length_prefix_roundtrip():
    a, b = b"hello", b"world!!"
    blob = _lp(a) + _lp(b)
    x, rest = _unlp(blob)
    y, tail = _unlp(rest)
    assert x == a and y == b and tail == b""


def test_length_prefix_empty():
    blob = _lp(b"")
    chunk, rest = _unlp(blob)
    assert chunk == b"" and rest == b""


@pytest.mark.skipif(not _HAVE_ED25519, reason="ed25519 not available")
def test_ed25519_private_roundtrip():
    s = Ed25519Signer()
    priv = s.private_bytes()
    s2 = Ed25519Signer(priv)
    assert s.public_bytes() == s2.public_bytes()
    msg = b"m"
    assert s2.verifier().verify(msg, s2.sign(msg), s2.public_bytes())


@pytest.mark.skipif(not _HAVE_ED25519, reason="ed25519 not available")
def test_ed25519_wrong_key_does_not_verify():
    a, b = Ed25519Signer(), Ed25519Signer()
    msg = b"m"
    # b's own signature verifies under b's public key
    assert b.verifier().verify(msg, b.sign(msg), b.public_bytes())
    # but b's signature under a's public key must fail
    assert not a.verifier().verify(msg, b.sign(msg), a.public_bytes())


def test_ed25519_verifier_rejects_garbage_signature():
    s = new_signer("ed25519")
    if s.algorithm != "ed25519":
        pytest.skip("no ed25519 backend")
    assert not s.verifier().verify(b"m", b"\x00\x01\x02", s.public_bytes())


def test_hmac_isolation():
    a, b = HmacSigner(), HmacSigner()
    msg = b"m"
    assert a.verifier().verify(msg, a.sign(msg), a.public_bytes())
    assert not b.verifier().verify(msg, a.sign(msg), a.public_bytes())


def test_hmac_fingerprint_not_secret():
    s = HmacSigner(secret=b"super-secret-key-material-000000")
    assert b"super-secret" not in s.public_bytes()
    assert len(s.public_bytes()) == 32


def test_hmac_verifier_constant_time_mismatch():
    s = HmacSigner(b"k" * 32)
    v = HmacVerifier(b"k" * 32)
    assert v.verify(b"m", s.sign(b"m"), s.public_bytes())
    assert not v.verify(b"m", b"\x00" * 32, s.public_bytes())


def test_signer_from_roundtrips_every_algorithm():
    algos = [new_signer("ed25519"), new_signer("hmac")]
    if _HAVE_MLDSA:
        algos.append(new_signer("ml-dsa"))
        algos.append(new_signer("hybrid"))
    for s in algos:
        s2 = signer_from(s.algorithm, s.private_bytes())
        assert s2.public_bytes() == s.public_bytes()
        msg = b"directive"
        assert s2.verifier().verify(msg, s2.sign(msg), s2.public_bytes())


def test_signer_from_unknown_algorithm_raises():
    with pytest.raises(ValueError):
        signer_from("rsa-4096", b"x")


def test_verifier_for_unknown_algorithm_raises():
    with pytest.raises(ValueError):
        verifier_for("rsa-4096")


def test_verifier_for_hmac_requires_secret():
    with pytest.raises(RuntimeError):
        verifier_for("hmac-sha256")


def test_new_signer_unknown_preference_raises():
    with pytest.raises(ValueError):
        new_signer("rsa")


def test_save_load_key_file_roundtrip(tmp_path):
    for prefer in ("ed25519", "hmac"):
        s = new_signer(prefer)
        path = str(tmp_path / f"{prefer}.json")
        save_key(s, path)
        s2 = load_key(path)
        assert s2.public_bytes() == s.public_bytes()
        assert s2.algorithm == s.algorithm


def test_save_key_writes_private_material(tmp_path):
    import json
    s = new_signer("ed25519")
    path = str(tmp_path / "k.json")
    save_key(s, path)
    data = json.loads(open(path, encoding="utf-8").read())
    assert data["algorithm"] == s.algorithm
    assert bytes.fromhex(data["private"]) == s.private_bytes()


@pytest.mark.skipif(_HAVE_MLDSA, reason="ML-DSA IS available; can't test the raise path")
def test_mldsa_request_without_backend_raises():
    with pytest.raises(RuntimeError):
        new_signer("ml-dsa")
