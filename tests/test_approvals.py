from agentledger import PolicyGate, Recorder, new_signer


def setup():
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    _, directive = rec.submit("alice", "deploy", {"env": "prod"})
    return rec, directive


def test_threshold_met_by_distinct_approvers():
    rec, d = setup()
    alice, bob, carol = (new_signer("ed25519") for _ in range(3))
    rec.approve(d.seq, "alice", alice)
    assert rec.approval_status(d.seq, threshold=2).satisfied is False
    rec.approve(d.seq, "bob", bob)
    status = rec.approval_status(d.seq, threshold=2)
    assert status.satisfied is True
    assert len(status.approver_keys) == 2


def test_same_approver_twice_counts_once():
    rec, d = setup()
    alice = new_signer("ed25519")
    rec.approve(d.seq, "alice", alice)
    rec.approve(d.seq, "alice", alice)   # same key again
    status = rec.approval_status(d.seq, threshold=2)
    assert status.satisfied is False
    assert len(status.approver_keys) == 1


def test_allowed_keys_allowlist_enforced():
    rec, d = setup()
    insider, outsider = new_signer("ed25519"), new_signer("ed25519")
    rec.approve(d.seq, "insider", insider)
    rec.approve(d.seq, "outsider", outsider)
    allow = {insider.public_bytes().hex()}
    status = rec.approval_status(d.seq, threshold=1, allowed_keys=allow)
    assert status.satisfied is True
    assert status.approver_keys == [insider.public_bytes().hex()]
    # the outsider's approval is ignored, so a 2-of-n over the allowlist fails
    assert rec.approval_status(d.seq, threshold=2, allowed_keys=allow).satisfied is False


def test_approvals_are_in_the_signed_chain():
    rec, d = setup()
    rec.approve(d.seq, "alice", new_signer("ed25519"))
    rec.approve(d.seq, "bob", new_signer("ed25519"))
    ok, broken = rec.verify()
    assert ok and broken is None      # approval entries are part of the ledger


def test_approval_signature_bound_to_directive():
    # an approval signs the directive's hash; forging the signature fails verification
    rec, d = setup()
    alice = new_signer("ed25519")
    e = rec.approve(d.seq, "alice", alice)
    # tamper the stored approver signature
    import json
    bad = dict(e.params)
    bad["signature"] = "00" * (len(bad["signature"]) // 2)
    rec.ledger.conn.execute("UPDATE entries SET params=? WHERE seq=?",
                            (json.dumps(bad), e.seq))
    rec.ledger.conn.commit()
    status = rec.approval_status(d.seq, threshold=1)
    assert status.satisfied is False   # invalid signature isn't counted
