"""Sink edge cases: fan-out, isolation, ordering, persistence."""
import json

from agentledger import (
    CallableSink,
    JSONLinesSink,
    PolicyGate,
    Recorder,
    new_signer,
)
from agentledger.sinks import Sink, SinkDispatcher


def rec_with(sinks):
    return Recorder(gate=PolicyGate(default_allow=True),
                    signer=new_signer("ed25519"), sinks=sinks)


def test_callable_sink_sees_directive_and_outcome_in_order():
    seen = []
    rec = rec_with([CallableSink(seen.append)])
    _, d = rec.submit("alice", "deploy")
    rec.record_outcome(d.seq, "agent", "ok")
    assert [s["kind"] for s in seen] == ["directive", "outcome"]


def test_streamed_entry_matches_stored_entry():
    seen = []
    rec = rec_with([CallableSink(seen.append)])
    _, e = rec.submit("alice", "deploy", {"env": "prod"})
    assert seen[0]["entry_hash"] == e.entry_hash
    assert seen[0]["signature"] == e.signature


def test_rotation_and_approval_are_streamed():
    seen = []
    rec = rec_with([CallableSink(seen.append)])
    _, d = rec.submit("a", "x")
    rec.approve(d.seq, "b", new_signer("ed25519"))
    rec.rotate_key(new_signer("ed25519"))
    kinds = [s["kind"] for s in seen]
    assert "approval" in kinds and "key_rotation" in kinds


def test_multiple_sinks_all_receive():
    a, b = [], []
    rec = rec_with([CallableSink(a.append), CallableSink(b.append)])
    rec.submit("alice", "x")
    assert len(a) == 1 and len(b) == 1
    assert a[0]["entry_hash"] == b[0]["entry_hash"]


def test_jsonlines_sink_appends_each_entry(tmp_path):
    path = str(tmp_path / "feed.jsonl")
    rec = rec_with([JSONLinesSink(path)])
    rec.submit("alice", "a")
    rec.submit("bob", "b")
    rec.submit("carol", "c")
    lines = open(path, encoding="utf-8").read().splitlines()
    assert len(lines) == 3
    assert [json.loads(x)["actor"] for x in lines] == ["alice", "bob", "carol"]


def test_failing_sink_isolated_others_still_fire():
    class Boom(Sink):
        def emit(self, entry):
            raise RuntimeError("collector down")
    good = []
    errs = []
    disp = SinkDispatcher([Boom(), CallableSink(good.append)],
                          on_error=lambda s, e: errs.append(e))
    disp.emit({"seq": 1})
    assert good == [{"seq": 1}] and len(errs) == 1


def test_recording_survives_failing_sink():
    class Boom(Sink):
        def emit(self, entry):
            raise RuntimeError("nope")
    rec = rec_with([Boom()])
    _, e = rec.submit("alice", "x")   # must not raise
    ok, _ = rec.verify()
    assert ok and e.seq == 1


def test_dispatcher_without_on_error_swallows():
    class Boom(Sink):
        def emit(self, entry):
            raise RuntimeError("x")
    disp = SinkDispatcher([Boom()])
    disp.emit({"seq": 1})   # no on_error, must not raise


def test_dispatcher_add_sink_dynamically():
    seen = []
    disp = SinkDispatcher()
    disp.add(CallableSink(seen.append))
    disp.emit({"seq": 7})
    assert seen == [{"seq": 7}]


def test_dispatcher_close_isolated():
    closed = []
    class S(Sink):
        def emit(self, entry):
            pass
        def close(self):
            closed.append(True)
    class BoomClose(Sink):
        def emit(self, entry):
            pass
        def close(self):
            raise RuntimeError("close failed")
    disp = SinkDispatcher([BoomClose(), S()])
    disp.close()   # must not raise even though one sink's close() throws
    assert closed == [True]


def test_jsonlines_sink_close_noop(tmp_path):
    s = JSONLinesSink(str(tmp_path / "f.jsonl"))
    s.close()   # base no-op; must not raise
