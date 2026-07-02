"""Offline tests for the HTTP-based sinks (Splunk HEC / Elastic / signed webhook).

Each sink accepts an injectable `transport` (url, body, headers) so the exact
wire output is captured and asserted without any network.
"""
import json

from agentledger import (
    ElasticSink, PolicyGate, Recorder, SignedWebhookSink, SplunkHecSink,
)


def _capture():
    calls = []

    def transport(url, body, headers):
        calls.append({"url": url, "body": body, "headers": headers})
    return calls, transport


def _entry():
    rec = Recorder(gate=PolicyGate(default_allow=True))
    _, e = rec.submit("alice", "deploy", {"env": "prod"})
    return e.as_dict()


def test_splunk_hec_envelope_and_auth():
    calls, transport = _capture()
    sink = SplunkHecSink("https://hec:8088/services/collector",
                         token="TOK", index="agents", transport=transport)
    e = _entry()
    sink.emit(e)
    assert len(calls) == 1
    assert calls[0]["headers"]["Authorization"] == "Splunk TOK"
    body = json.loads(calls[0]["body"])
    assert body["event"]["action"] == "deploy"
    assert body["index"] == "agents"
    assert body["time"] == e["ts"]


def test_elastic_bulk_ndjson_and_idempotent_id():
    calls, transport = _capture()
    sink = ElasticSink("https://es:9200", index="ledger",
                       api_key="KEY", transport=transport)
    e = _entry()
    sink.emit(e)
    assert calls[0]["url"] == "https://es:9200/_bulk"
    assert calls[0]["headers"]["Authorization"] == "ApiKey KEY"
    lines = calls[0]["body"].decode().strip().split("\n")
    assert len(lines) == 2  # action line + doc line
    action = json.loads(lines[0])
    doc = json.loads(lines[1])
    # entry_hash used as _id -> re-indexing the same entry is idempotent
    assert action["index"]["_id"] == e["entry_hash"]
    assert action["index"]["_index"] == "ledger"
    assert doc["actor"] == "alice"


def test_signed_webhook_signature_roundtrip():
    calls, transport = _capture()
    secret = b"shhh"
    sink = SignedWebhookSink("https://hook.example/agent", secret, transport=transport)
    sink.emit(_entry())
    body = calls[0]["body"]
    header = calls[0]["headers"]["X-AgentLedger-Signature"]
    assert header.startswith("sha256=")
    # a receiver with the shared secret can verify the body wasn't altered
    assert SignedWebhookSink.verify_signature(secret, body, header) is True
    assert SignedWebhookSink.verify_signature(secret, body + b"x", header) is False
    assert SignedWebhookSink.verify_signature(b"wrong", body, header) is False


def test_signed_webhook_custom_header_and_str_secret():
    calls, transport = _capture()
    sink = SignedWebhookSink("https://h", "text-secret",
                             signature_header="X-Sig", transport=transport)
    sink.emit(_entry())
    assert "X-Sig" in calls[0]["headers"]


def test_http_sinks_integrate_with_recorder():
    calls, transport = _capture()
    rec = Recorder(gate=PolicyGate(default_allow=True),
                   sinks=[SplunkHecSink("https://hec", "T", transport=transport)])
    rec.submit("a", "x")
    rec.submit("b", "y")
    assert len(calls) == 2


def test_sink_failure_never_breaks_recording():
    def boom(url, body, headers):
        raise RuntimeError("collector down")
    rec = Recorder(gate=PolicyGate(default_allow=True),
                   sinks=[ElasticSink("https://es", transport=boom)])
    _, e = rec.submit("a", "x")  # must not raise
    ok, _ = rec.verify()
    assert ok and e.seq == 1
