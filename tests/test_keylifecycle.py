from agentledger import PolicyGate, Recorder, load_key, new_signer, save_key


def test_save_load_ed25519_roundtrip(tmp_path):
    s = new_signer("ed25519")
    path = str(tmp_path / "key.json")
    save_key(s, path)
    s2 = load_key(path)
    assert s.public_bytes() == s2.public_bytes()
    msg = b"hello"
    assert s2.verifier().verify(msg, s2.sign(msg), s2.public_bytes())


def test_save_load_hmac_roundtrip(tmp_path):
    s = new_signer("hmac")
    path = str(tmp_path / "key.json")
    save_key(s, path)
    s2 = load_key(path)
    assert s.public_bytes() == s2.public_bytes()


def test_rotation_keeps_ledger_valid():
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    rec.submit("alice", "deploy", {"env": "dev"})
    rot = rec.rotate_key(new_signer("ed25519"))
    assert rot.kind == "key_rotation"
    rec.submit("alice", "deploy", {"env": "dev2"})
    ok, broken = rec.verify()
    assert ok and broken is None


def test_rotation_survives_offline_bundle():
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    _, e = rec.submit("alice", "x")
    rec.record_outcome(e.seq, "agent", "ok")
    rec.rotate_key(new_signer("ed25519"))
    rec.submit("bob", "y")
    from agentledger.evidence import verify_bundle
    ok, broken = verify_bundle(rec.export_evidence())
    assert ok and broken is None


def test_unauthorized_key_change_is_detected():
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    rec.submit("alice", "x")
    # an attacker swaps in their own key WITHOUT a rotation entry, then appends.
    # the per-entry signature is self-consistent, but continuity must reject it.
    rec.ledger.signer = new_signer("ed25519")
    forged = rec.ledger.append("directive", "mallory", "sneak", {})
    ok, broken = rec.verify()
    assert not ok
    assert broken == forged.seq
    # without the continuity check, the forged entry's own signature still "passes"
    ok2, _ = rec.verify(check_continuity=False)
    assert ok2
