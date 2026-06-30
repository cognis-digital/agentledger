"""Threshold (m-of-n) approval edge cases."""
import json

from agentledger import PolicyGate, Recorder, new_signer


def setup(threshold_action="deploy"):
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    _, d = rec.submit("alice", threshold_action, {"env": "prod"})
    return rec, d


def test_zero_threshold_trivially_satisfied():
    rec, d = setup()
    assert rec.approval_status(d.seq, threshold=0).satisfied is True


def test_threshold_exactly_met():
    rec, d = setup()
    rec.approve(d.seq, "a", new_signer("ed25519"))
    rec.approve(d.seq, "b", new_signer("ed25519"))
    assert rec.approval_status(d.seq, threshold=2).satisfied is True


def test_threshold_one_short():
    rec, d = setup()
    rec.approve(d.seq, "a", new_signer("ed25519"))
    rec.approve(d.seq, "b", new_signer("ed25519"))
    assert rec.approval_status(d.seq, threshold=3).satisfied is False


def test_three_distinct_approvers():
    rec, d = setup()
    keys = [new_signer("ed25519") for _ in range(3)]
    for i, k in enumerate(keys):
        rec.approve(d.seq, f"op{i}", k)
    status = rec.approval_status(d.seq, threshold=3)
    assert status.satisfied and len(status.approver_keys) == 3


def test_same_key_many_times_counts_once():
    rec, d = setup()
    k = new_signer("ed25519")
    for _ in range(5):
        rec.approve(d.seq, "spammer", k)
    assert rec.approval_status(d.seq, threshold=2).satisfied is False
    assert len(rec.approval_status(d.seq, threshold=1).approver_keys) == 1


def test_allowlist_filters_outsiders():
    rec, d = setup()
    inside, outside = new_signer("ed25519"), new_signer("ed25519")
    rec.approve(d.seq, "inside", inside)
    rec.approve(d.seq, "outside", outside)
    allow = {inside.public_bytes().hex()}
    st = rec.approval_status(d.seq, threshold=1, allowed_keys=allow)
    assert st.satisfied and st.approver_keys == [inside.public_bytes().hex()]


def test_allowlist_empty_set_admits_nobody():
    rec, d = setup()
    rec.approve(d.seq, "a", new_signer("ed25519"))
    st = rec.approval_status(d.seq, threshold=1, allowed_keys=set())
    assert not st.satisfied and st.approver_keys == []


def test_tampered_approval_signature_not_counted():
    rec, d = setup()
    e = rec.approve(d.seq, "a", new_signer("ed25519"))
    bad = dict(e.params)
    bad["signature"] = "00" * (len(bad["signature"]) // 2)
    rec.ledger.conn.execute("UPDATE entries SET params=? WHERE seq=?",
                            (json.dumps(bad), e.seq))
    rec.ledger.conn.commit()
    assert rec.approval_status(d.seq, threshold=1).satisfied is False


def test_approval_for_wrong_directive_does_not_transfer():
    # an approval signs directive A's hash; it must not count toward directive B
    rec, dA = setup()
    _, dB = rec.submit("bob", "deploy", {"env": "prod", "svc": "other"})
    k = new_signer("ed25519")
    rec.approve(dA.seq, "a", k)
    # B has no approvals referencing it
    assert rec.approval_status(dB.seq, threshold=1).satisfied is False
    assert rec.approval_status(dA.seq, threshold=1).satisfied is True


def test_hmac_approval_skipped_no_third_party_verification():
    rec, d = setup()
    rec.approve(d.seq, "a", new_signer("hmac"))   # not third-party verifiable
    # an hmac approval can't be verified without the secret -> not counted
    assert rec.approval_status(d.seq, threshold=1).satisfied is False


def test_approvals_part_of_signed_chain():
    rec, d = setup()
    rec.approve(d.seq, "a", new_signer("ed25519"))
    rec.approve(d.seq, "b", new_signer("ed25519"))
    ok, broken = rec.verify()
    assert ok and broken is None


def test_approval_status_as_dict_shape():
    rec, d = setup()
    rec.approve(d.seq, "a", new_signer("ed25519"))
    st = rec.approval_status(d.seq, threshold=2)
    asd = st.as_dict()
    assert asd["directive_seq"] == d.seq
    assert asd["threshold"] == 2
    assert asd["approvals"] == 1
    assert asd["satisfied"] is False
    assert isinstance(asd["approver_keys"], list)
