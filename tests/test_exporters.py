import csv
import io
import json

from agentledger import PolicyGate, Recorder, exporters


def _rec():
    gate = PolicyGate(default_allow=True).deny(
        "rm-rf", reason="destructive", name="deny:rmrf")
    rec = Recorder(gate=gate)
    _, d1 = rec.submit("alice", "deploy", {"env": "prod"})
    rec.record_outcome(d1.seq, "agent:deployer", "success", {"build": 42})
    rec.submit("bob", "rm-rf", {"path": "/"})    # denied
    return rec


def test_jsonl_one_line_per_entry(tmp_path):
    rec = _rec()
    path = str(tmp_path / "out.jsonl")
    text = exporters.to_jsonl(rec.entries(), path)
    lines = text.strip().splitlines()
    assert len(lines) == 3
    parsed = [json.loads(x) for x in lines]
    assert parsed[0]["action"] == "deploy"
    assert open(path, encoding="utf-8").read() == text


def test_csv_columns_and_rows():
    rec = _rec()
    text = exporters.to_csv(rec.entries())
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0][0:5] == ["seq", "ts", "kind", "actor", "action"]
    assert len(rows) == 4  # header + 3 entries
    # denied directive row records allowed=False
    denied = [r for r in rows[1:] if r[2] == "directive" and r[4] == "rm-rf"][0]
    assert denied[5] == "False"


def test_sarif_only_denied_directives_are_results():
    rec = _rec()
    doc = exporters.to_sarif(rec.entries())
    assert doc["version"] == "2.1.0"
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "deny:rmrf"
    assert results[0]["level"] == "error"
    # a clean ledger (no denials) yields zero results -> passing CI gate
    clean = Recorder(gate=PolicyGate(default_allow=True))
    clean.submit("a", "ok")
    assert exporters.to_sarif(clean.entries())["runs"][0]["results"] == []


def test_otel_spans_link_outcome_to_directive():
    rec = _rec()
    doc = exporters.to_otel_spans(rec.entries())
    spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert len(spans) == 3
    by_name = {s["name"]: s for s in spans}
    directive = by_name["directive:deploy"]
    outcome = by_name["outcome:success"]
    # the outcome shares the directive's trace and points at it as parent
    assert outcome["traceId"] == directive["traceId"]
    assert outcome["parentSpanId"] == directive["spanId"]
    # denied directive gets ERROR status (code 2)
    assert by_name["directive:rm-rf"]["status"]["code"] == 2


def test_html_report_is_signed_and_verifies():
    rec = _rec()
    html = exporters.to_html_report(rec.entries(), rec.signer)
    assert "Attestation" in html and "rm-rf" in html
    assert exporters.verify_html_attestation(html) is True


def test_html_attestation_detects_tamper():
    rec = _rec()
    html = exporters.to_html_report(rec.entries(), rec.signer)
    head = rec.entries()[-1].entry_hash
    # rewrite the head hash inside the SIGNED payload span -> signature breaks
    tampered = html.replace(head, "0" * 64)
    assert head not in tampered
    assert exporters.verify_html_attestation(tampered) is False


def test_html_attestation_missing_block_is_false():
    assert exporters.verify_html_attestation("<html>no attestation here</html>") is False


def test_writes_to_disk(tmp_path):
    rec = _rec()
    for fmt, fn in [("sarif", exporters.to_sarif), ("otel", exporters.to_otel_spans)]:
        p = str(tmp_path / f"o.{fmt}.json")
        fn(rec.entries(), p)
        assert json.load(open(p, encoding="utf-8"))  # valid JSON on disk
