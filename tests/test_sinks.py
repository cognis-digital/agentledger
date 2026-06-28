import json

from agentledger import CallableSink, JSONLinesSink, PolicyGate, Recorder
from agentledger.sinks import Sink, SinkDispatcher


def test_callable_sink_receives_every_entry():
    seen = []
    rec = Recorder(gate=PolicyGate(default_allow=True),
                   sinks=[CallableSink(seen.append)])
    _, e = rec.submit("alice", "deploy", {"env": "prod"})
    rec.record_outcome(e.seq, "agent", "ok")
    assert [s["kind"] for s in seen] == ["directive", "outcome"]
    assert seen[0]["action"] == "deploy"
    # the streamed entry carries the signature/hash, same as the stored one
    assert seen[0]["entry_hash"] == e.entry_hash


def test_rotation_is_streamed_too():
    from agentledger import new_signer
    seen = []
    rec = Recorder(gate=PolicyGate(default_allow=True), signer=new_signer("ed25519"),
                   sinks=[CallableSink(seen.append)])
    rec.submit("a", "x")
    rec.rotate_key(new_signer("ed25519"))
    kinds = [s["kind"] for s in seen]
    assert "key_rotation" in kinds


def test_jsonlines_sink_writes_file(tmp_path):
    path = str(tmp_path / "feed.jsonl")
    rec = Recorder(gate=PolicyGate(default_allow=True), sinks=[JSONLinesSink(path)])
    rec.submit("alice", "a")
    rec.submit("bob", "b")
    lines = [json.loads(x) for x in open(path, encoding="utf-8").read().splitlines()]
    assert len(lines) == 2
    assert {l["actor"] for l in lines} == {"alice", "bob"}


def test_failing_sink_is_isolated():
    class Boom(Sink):
        def emit(self, entry):
            raise RuntimeError("collector down")

    errors = []
    disp = SinkDispatcher([Boom()], on_error=lambda s, e: errors.append(e))
    good = []
    disp.add(CallableSink(good.append))
    disp.emit({"seq": 1})
    # the bad sink raised but recording continued to the good sink
    assert len(errors) == 1
    assert good == [{"seq": 1}]


def test_recording_survives_sink_failure():
    class Boom(Sink):
        def emit(self, entry):
            raise RuntimeError("nope")

    rec = Recorder(gate=PolicyGate(default_allow=True), sinks=[Boom()])
    _, e = rec.submit("alice", "x")          # must not raise
    ok, _ = rec.verify()
    assert ok and e.seq == 1
