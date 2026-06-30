"""Error paths and input validation on the recording API.

These exercise the hardening added so a bad write fails *clearly* and *before*
it can land a partial/garbage row in the signed chain.
"""
import pytest

from agentledger import PolicyGate, Recorder, new_signer
from agentledger.ledger import Ledger


def fresh_ledger():
    return Ledger(new_signer("ed25519"))


def test_append_rejects_empty_kind():
    led = fresh_ledger()
    with pytest.raises(ValueError):
        led.append("", "alice", "act", {})


def test_append_rejects_empty_actor():
    led = fresh_ledger()
    with pytest.raises(ValueError):
        led.append("directive", "", "act", {})


def test_append_rejects_empty_action():
    led = fresh_ledger()
    with pytest.raises(ValueError):
        led.append("directive", "alice", "", {})


def test_append_rejects_non_dict_params():
    led = fresh_ledger()
    with pytest.raises(TypeError):
        led.append("directive", "alice", "act", ["not", "a", "dict"])


def test_append_rejects_non_dict_decision():
    led = fresh_ledger()
    with pytest.raises(TypeError):
        led.append("directive", "alice", "act", {}, decision="nope")


def test_append_rejects_non_int_ref():
    led = fresh_ledger()
    with pytest.raises(TypeError):
        led.append("outcome", "agent", "ok", {}, ref="one")


def test_append_rejects_non_serializable_params():
    led = fresh_ledger()
    with pytest.raises(TypeError):
        led.append("directive", "alice", "act", {"obj": object()})


def test_append_failure_leaves_chain_empty():
    # a rejected append must not have written anything
    led = fresh_ledger()
    with pytest.raises(TypeError):
        led.append("directive", "alice", "act", {"bad": object()})
    assert led.all() == []
    ok, _ = led.verify()
    assert ok


def test_append_none_params_becomes_empty_dict():
    led = fresh_ledger()
    e = led.append("directive", "alice", "act", None)
    assert e.params == {}


def test_submit_with_non_serializable_params_raises_before_write():
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    with pytest.raises(TypeError):
        rec.submit("alice", "act", {"bad": object()})
    assert rec.entries() == []   # nothing recorded


def test_record_outcome_unknown_ref_raises():
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    with pytest.raises(ValueError):
        rec.record_outcome(999, "agent", "ok")
    assert rec.entries() == []   # dangling reference never written


def test_record_outcome_valid_ref_succeeds():
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    _, d = rec.submit("alice", "deploy")
    out = rec.record_outcome(d.seq, "agent", "success", {"n": 1})
    assert out.ref == d.seq and out.kind == "outcome"


def test_approve_unknown_ref_raises():
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    with pytest.raises(ValueError):
        rec.approve(404, "alice", new_signer("ed25519"))


def test_approval_status_unknown_ref_raises():
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    with pytest.raises(ValueError):
        rec.approval_status(404, threshold=1)
