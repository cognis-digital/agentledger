"""Scenario 8 - feeding the tools you already run.

The evidence bundle is the canonical artifact. These exporters are tool-facing
projections on top of it: SARIF for a CI security gate, OpenTelemetry spans for
your tracing backend, CSV/JSONL for triage, and a signed, self-contained HTML
attestation report a human can read and a machine can still verify. None of
them replace the bundle; each is a view.
"""
from _common import fresh_recorder, rule, step
from agentledger import PolicyGate, exporters


def main() -> None:
    rule("EXPORTERS  -  SARIF, OpenTelemetry, CSV/JSONL, signed HTML attestation")

    gate = PolicyGate(default_allow=True).deny(
        "exfiltrate-*", reason="data exfiltration", name="deny:exfil")
    rec = fresh_recorder(gate=gate)
    _, d1 = rec.submit("alice", "deploy", {"env": "prod"})
    rec.record_outcome(d1.seq, "agent:deployer", "success", {"build": 42})
    rec.submit("mallory", "exfiltrate-db", {"target": "customers"})  # denied

    step(1, "SARIF 2.1.0 - denied directives become code-scanning results.")
    sarif = exporters.to_sarif(rec.entries())
    results = sarif["runs"][0]["results"]
    print(f"   {len(results)} result(s); a clean run would be zero (passing CI gate).")
    for r in results:
        print(f"   -> [{r['level']}] {r['ruleId']}: {r['message']['text']}")

    step(2, "OpenTelemetry OTLP/JSON spans - a directive + its outcomes = a trace.")
    otel = exporters.to_otel_spans(rec.entries())
    spans = otel["resourceSpans"][0]["scopeSpans"][0]["spans"]
    print(f"   {len(spans)} spans emitted; POST to any OTLP/HTTP collector.")

    step(3, "CSV / JSONL - flat views for spreadsheets and log ingest.")
    csv_text = exporters.to_csv(rec.entries())
    jsonl_text = exporters.to_jsonl(rec.entries())
    print(f"   CSV rows   = {csv_text.count(chr(10))}")
    print(f"   JSONL lines= {jsonl_text.strip().count(chr(10)) + 1}")

    step(4, "Signed HTML attestation - human-readable AND machine-verifiable.")
    html = exporters.to_html_report(rec.entries(), rec.signer,
                                    title="Prod change attestation")
    verified = exporters.verify_html_attestation(html)
    print(f"   report length = {len(html)} bytes")
    print(f"   verify_html_attestation(report) -> {verified}")

    print("\nEach exporter is a lossy projection; the evidence bundle stays canonical.")


if __name__ == "__main__":
    main()
