"""Ledger query / persistence behaviour: get, iteration, referencing, on-disk db."""
from agentledger import PolicyGate, Recorder, new_signer
from agentledger.ledger import GENESIS, Entry, Ledger, compute_hash


def test_get_missing_returns_none():
    led = Ledger(new_signer("ed25519"))
    assert led.get(999) is None


def test_get_returns_entry():
    led = Ledger(new_signer("ed25519"))
    e = led.append("directive", "a", "x", {"k": 1})
    got = led.get(e.seq)
    assert got is not None and got.entry_hash == e.entry_hash
    assert got.params == {"k": 1}


def test_iteration_is_seq_ordered():
    led = Ledger(new_signer("ed25519"))
    for i in range(5):
        led.append("directive", "a", f"act{i}", {})
    seqs = [e.seq for e in led]
    assert seqs == [1, 2, 3, 4, 5]


def test_all_matches_iteration():
    led = Ledger(new_signer("ed25519"))
    led.append("directive", "a", "x", {})
    led.append("directive", "b", "y", {})
    assert [e.seq for e in led.all()] == [e.seq for e in led]


def test_first_entry_prev_is_genesis():
    led = Ledger(new_signer("ed25519"))
    e = led.append("directive", "a", "x", {})
    assert e.prev_hash == GENESIS


def test_chain_links_each_to_previous():
    led = Ledger(new_signer("ed25519"))
    es = [led.append("directive", "a", f"x{i}", {}) for i in range(4)]
    for prev, cur in zip(es, es[1:]):
        assert cur.prev_hash == prev.entry_hash


def test_entries_referencing_filters_by_kind():
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"))
    _, d = rec.submit("a", "x")
    rec.record_outcome(d.seq, "agent", "ok")
    rec.approve(d.seq, "b", new_signer("ed25519"))
    outcomes = rec.ledger.entries_referencing(d.seq, kind="outcome")
    approvals = rec.ledger.entries_referencing(d.seq, kind="approval")
    everything = rec.ledger.entries_referencing(d.seq)
    assert [e.kind for e in outcomes] == ["outcome"]
    assert [e.kind for e in approvals] == ["approval"]
    assert len(everything) == 2


def test_entries_referencing_empty_when_none():
    led = Ledger(new_signer("ed25519"))
    led.append("directive", "a", "x", {})
    assert led.entries_referencing(1) == []


def test_entry_payload_and_as_dict_consistent():
    led = Ledger(new_signer("ed25519"))
    e = led.append("directive", "a", "x", {"k": 1})
    d = e.as_dict()
    # as_dict superset of payload, and recomputing the hash from payload matches
    for k, v in e.payload().items():
        assert d[k] == v
    assert compute_hash(e.prev_hash, e.payload()) == e.entry_hash


def test_explicit_ts_is_recorded():
    led = Ledger(new_signer("ed25519"))
    e = led.append("directive", "a", "x", {}, ts=1234.5)
    assert e.ts == 1234.5


def test_on_disk_db_persists_and_verifies(tmp_path):
    path = str(tmp_path / "ledger.db")
    s = new_signer("ed25519")
    led = Ledger(s, db_path=path)
    led.append("directive", "alice", "deploy", {"env": "prod"})
    led.append("directive", "bob", "scale", {"n": 3})
    # reopen the same file with the same signer
    led2 = Ledger(s, db_path=path)
    assert len(led2.all()) == 2
    ok, broken = led2.verify()
    assert ok and broken is None


def test_compute_hash_is_deterministic_and_order_independent_keys():
    p1 = {"a": 1, "b": 2}
    p2 = {"b": 2, "a": 1}   # same content, different key order
    assert compute_hash(GENESIS, p1) == compute_hash(GENESIS, p2)


def test_compute_hash_changes_with_prev():
    p = {"a": 1}
    assert compute_hash(GENESIS, p) != compute_hash("f" * 64, p)
