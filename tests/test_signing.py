from agentledger.signing import (
    HmacSigner,
    new_signer,
    verifier_for,
)


def test_default_signer_roundtrip():
    signer = new_signer()
    msg = b"directive-hash"
    sig = signer.sign(msg)
    v = signer.verifier()
    assert v.verify(msg, sig, signer.public_bytes())


def test_signature_detects_tamper():
    signer = new_signer()
    sig = signer.sign(b"original")
    v = signer.verifier()
    assert not v.verify(b"tampered", sig, signer.public_bytes())


def test_hmac_roundtrip_and_isolation():
    a = HmacSigner()
    b = HmacSigner()
    msg = b"x"
    assert a.verifier().verify(msg, a.sign(msg), a.public_bytes())
    # a's signature must not verify under b's secret
    assert not b.verifier().verify(msg, a.sign(msg), a.public_bytes())


def test_hmac_public_bytes_not_secret():
    s = HmacSigner(secret=b"super-secret-key-material-000000")
    assert b"super-secret" not in s.public_bytes()


def test_hmac_explicit_preference():
    s = new_signer(prefer="hmac")
    assert s.algorithm == "hmac-sha256"


def test_verifier_for_hmac_requires_secret():
    import pytest
    with pytest.raises(RuntimeError):
        verifier_for("hmac-sha256")  # no secret


def test_unknown_preference():
    import pytest
    with pytest.raises(ValueError):
        new_signer(prefer="rsa")
