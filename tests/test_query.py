from agentledger import PolicyGate, Recorder
from agentledger.query import Query


def _rec():
    gate = PolicyGate(default_allow=True).deny(
        "rm-rf", reason="destructive", name="deny:rmrf")
    rec = Recorder(gate=gate)
    _, d1 = rec.submit("alice", "deploy", {"env": "prod"})
    rec.record_outcome(d1.seq, "agent:deployer", "success", {"build": 1})
    rec.submit("bob", "rm-rf", {"path": "/"})       # denied
    _, d3 = rec.submit("alice", "deploy", {"env": "dev"})
    rec.record_outcome(d3.seq, "agent:deployer", "failed", {"err": "timeout"})
    return rec


def test_kind_actor_action_filters():
    rec = _rec()
    q = Query(rec.ledger)
    assert set(q.kind("directive").seqs()) == {1, 3, 4}
    assert q.actor("bob").seqs() == [3]
    assert set(q.action("deploy").seqs()) == {1, 4}


def test_allowed_and_denied():
    q = Query(_rec().ledger)
    assert q.denied().seqs() == [3]
    assert set(q.allowed().kind("directive").seqs()) == {1, 4}
    assert q.rule("deny:rmrf").seqs() == [3]


def test_refers_to_and_param_eq():
    q = Query(_rec().ledger)
    # outcomes reference their directive seq
    assert [e.action for e in q.refers_to(1)] == ["success"]
    assert q.param_eq("env", "prod").seqs() == [1]


def test_time_windows():
    rec = Recorder(gate=PolicyGate(default_allow=True))
    a = rec.ledger.append("directive", "x", "a", {}, ts=100.0)
    b = rec.ledger.append("directive", "x", "b", {}, ts=200.0)
    c = rec.ledger.append("directive", "x", "c", {}, ts=300.0)
    q = Query(rec.ledger)
    assert q.since(200.0).seqs() == [b.seq, c.seq]
    assert q.until(200.0).seqs() == [a.seq, b.seq]
    assert q.between(150.0, 250.0).seqs() == [b.seq]
    assert q.since(200.0, inclusive=False).seqs() == [c.seq]


def test_order_limit_first_latest():
    q = Query(_rec().ledger)
    ordered_desc = q.order_by_ts(descending=True).seqs()
    assert ordered_desc[0] >= ordered_desc[-1]
    assert q.limit(2).count() == 2
    assert q.first().seq == 1
    assert q.latest().seq == 5


def test_where_escape_hatch_and_summary():
    q = Query(_rec().ledger)
    assert q.where(lambda e: e.actor == "alice").count() == 2
    s = q.summary()
    assert s["total"] == 5
    assert s["by_kind"] == {"directive": 3, "outcome": 2}
    assert s["directives_allowed"] == 2
    assert s["directives_denied"] == 1
    assert s["distinct_actors"] == 3  # alice, bob, agent:deployer


def test_query_is_reusable_and_non_destructive():
    q = Query(_rec().ledger)
    first = q.denied().seqs()
    second = q.denied().seqs()   # querying again yields the same result
    assert first == second == [3]
    # original ledger untouched
    assert len(q.all()) == 5


def test_limit_negative_rejected():
    import pytest
    with pytest.raises(ValueError):
        Query(_rec().ledger).limit(-1)
