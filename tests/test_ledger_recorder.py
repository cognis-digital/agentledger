from agentledger import PolicyGate, Recorder
from agentledger.ledger import Ledger
from agentledger.signing import new_signer


def test_ledger_chains_and_verifies():
    led = Ledger(new_signer())
    led.append("directive", "a", "act1", {})
    led.append("directive", "b", "act2", {"k": 1})
    ok, broken = led.verify()
    assert ok and broken is None
    entries = led.all()
    assert entries[1].prev_hash == entries[0].entry_hash


def test_ledger_detects_content_tamper():
    led = Ledger(new_signer())
    led.append("directive", "a", "act1", {})
    led.append("directive", "b", "act2", {})
    led.append("directive", "c", "act3", {})
    led.conn.execute("UPDATE entries SET action='HACKED' WHERE seq=2")
    led.conn.commit()
    ok, broken = led.verify()
    assert not ok and broken == 2


def test_ledger_detects_signature_tamper():
    led = Ledger(new_signer())
    e = led.append("directive", "a", "act1", {})
    # flip the signature but keep hash valid -> signature check must fail
    bad_sig = ("00" * (len(e.signature) // 2))
    led.conn.execute("UPDATE entries SET signature=? WHERE seq=1", (bad_sig,))
    led.conn.commit()
    ok, broken = led.verify()
    assert not ok and broken == 1


def test_recorder_submit_and_outcome():
    gate = PolicyGate(default_allow=False).allow("read.*")
    rec = Recorder(gate=gate)
    decision, entry = rec.submit("alice", "read.logs", {"lines": 100})
    assert decision.allowed
    assert entry.kind == "directive"
    out = rec.record_outcome(entry.seq, "agent:reader", "success", {"rows": 100})
    assert out.kind == "outcome" and out.ref == entry.seq
    ok, _ = rec.verify()
    assert ok


def test_recorder_records_denied_directives():
    gate = PolicyGate(default_allow=False)
    rec = Recorder(gate=gate)
    decision, entry = rec.submit("mallory", "deploy.prod")
    assert not decision.allowed
    # denial is still on the record
    assert entry.decision["allowed"] is False
    assert any(e.action == "deploy.prod" for e in rec.entries())
