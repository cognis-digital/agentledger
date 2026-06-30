"""Every way history can be altered, and proof verify() catches each one.

These reach *past* the signed append() path (the move an insider or a
compromised host makes) and assert the chain breaks at the exact seq.
"""
import json

from agentledger import PolicyGate, Recorder, new_signer
from agentledger.ledger import Ledger, GENESIS


def chain_of(n=4):
    led = Ledger(new_signer("ed25519"))
    for i in range(n):
        led.append("directive", f"actor{i}", f"act{i}", {"i": i})
    return led


def test_clean_chain_verifies():
    led = chain_of(5)
    ok, broken = led.verify()
    assert ok and broken is None


def test_edit_action_caught():
    led = chain_of(4)
    led.conn.execute("UPDATE entries SET action='HACKED' WHERE seq=2")
    led.conn.commit()
    ok, broken = led.verify()
    assert not ok and broken == 2


def test_edit_actor_caught():
    led = chain_of(4)
    led.conn.execute("UPDATE entries SET actor='mallory' WHERE seq=3")
    led.conn.commit()
    ok, broken = led.verify()
    assert not ok and broken == 3


def test_edit_params_caught():
    led = chain_of(4)
    led.conn.execute("UPDATE entries SET params=? WHERE seq=2", (json.dumps({"i": 999}),))
    led.conn.commit()
    ok, broken = led.verify()
    assert not ok and broken == 2


def test_edit_ts_caught():
    led = chain_of(4)
    led.conn.execute("UPDATE entries SET ts=0.0 WHERE seq=2")
    led.conn.commit()
    ok, broken = led.verify()
    assert not ok and broken == 2


def test_edit_decision_caught():
    led = chain_of(4)
    led.conn.execute("UPDATE entries SET decision=? WHERE seq=2",
                     (json.dumps({"allowed": True, "rule": "x", "reason": ""}),))
    led.conn.commit()
    ok, broken = led.verify()
    assert not ok and broken == 2


def test_delete_middle_entry_breaks_chain():
    led = chain_of(5)
    led.conn.execute("DELETE FROM entries WHERE seq=3")
    led.conn.commit()
    ok, broken = led.verify()
    # seq 4's prev_hash now points at a hash no longer in the chain
    assert not ok and broken == 4


def test_delete_head_entry_is_silently_truncation_only():
    # deleting the *last* entry can't be caught by the chain alone (no entry
    # references it); this documents that limitation honestly.
    led = chain_of(5)
    led.conn.execute("DELETE FROM entries WHERE seq=5")
    led.conn.commit()
    ok, broken = led.verify()
    assert ok  # the remaining 1..4 still chain cleanly


def test_swap_two_rows_breaks_chain():
    led = chain_of(4)
    # swap seq values of 2 and 3 -> prev_hash linkage no longer holds
    led.conn.execute("UPDATE entries SET seq=99 WHERE seq=2")
    led.conn.execute("UPDATE entries SET seq=2 WHERE seq=3")
    led.conn.execute("UPDATE entries SET seq=3 WHERE seq=99")
    led.conn.commit()
    ok, broken = led.verify()
    assert not ok


def test_flip_signature_caught():
    led = chain_of(3)
    e = led.get(2)
    bad = "00" * (len(e.signature) // 2)
    led.conn.execute("UPDATE entries SET signature=? WHERE seq=2", (bad,))
    led.conn.commit()
    ok, broken = led.verify()
    assert not ok and broken == 2


def test_recompute_hash_after_edit_still_caught_by_signature():
    # a smarter attacker edits the field AND recomputes entry_hash to match the
    # tampered payload -> chain link is restored, but the signature no longer
    # matches the new hash, so it's still caught.
    from agentledger.ledger import compute_hash
    led = chain_of(3)
    e = led.get(2)
    tampered_payload = dict(e.payload())
    tampered_payload["action"] = "HACKED"
    new_hash = compute_hash(e.prev_hash, tampered_payload)
    led.conn.execute("UPDATE entries SET action='HACKED', entry_hash=? WHERE seq=2",
                     (new_hash,))
    # also fix seq 3's prev_hash so the chain links again
    led.conn.execute("UPDATE entries SET prev_hash=? WHERE seq=3", (new_hash,))
    led.conn.commit()
    ok, broken = led.verify()
    # signature over the old hash no longer matches -> caught at seq 2
    assert not ok and broken == 2


def test_first_entry_prev_hash_must_be_genesis():
    led = chain_of(2)
    led.conn.execute("UPDATE entries SET prev_hash=? WHERE seq=1", ("f" * 64,))
    led.conn.commit()
    ok, broken = led.verify()
    assert not ok and broken == 1


def test_tamper_detected_in_exported_bundle_too():
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    _, d = rec.submit("alice", "wire", {"amount": 2500})
    rec.record_outcome(d.seq, "agent", "ok")
    bundle = rec.export_evidence()
    bundle["entries"][0]["params"]["amount"] = 999999
    from agentledger.evidence import verify_bundle
    ok, broken = verify_bundle(bundle)
    assert not ok and broken == bundle["entries"][0]["seq"]
