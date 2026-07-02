"""Exporters: render a ledger into the formats other tools already speak.

The evidence bundle (see `evidence.py`) is the canonical, offline-verifiable
artifact. These exporters are *lossy, tool-facing views* on top of it — for
feeding a SIEM, a CI security gate, a tracing backend, or a human reading a
report. None of them replace the bundle; each one is a projection.

Everything here is standard-library only and deterministic (given the same
ledger you get byte-identical output, modulo an explicit timestamp), so outputs
are diffable and testable offline.

  * `to_jsonl`         one entry per line (ingest-friendly).
  * `to_csv`           flat table for spreadsheets / quick triage.
  * `to_sarif`         denied directives as SARIF 2.1.0 results (CI/code-scanning).
  * `to_otel_spans`    OpenTelemetry OTLP/JSON spans (directive+outcome = a trace).
  * `to_html_report`   a signed, self-contained HTML attestation report.
"""

from __future__ import annotations

import csv
import io
import json
import time
from typing import Iterable, Optional

from .ledger import Entry
from .signing import Signer


def _entries(source: Iterable[Entry]) -> list[Entry]:
    return list(source)


# ---- JSONL ----------------------------------------------------------------
def to_jsonl(source: Iterable[Entry], path: Optional[str] = None) -> str:
    """One canonical JSON object per line."""
    lines = [json.dumps(e.as_dict(), sort_keys=True, separators=(",", ":"))
             for e in _entries(source)]
    text = "\n".join(lines) + ("\n" if lines else "")
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return text


# ---- CSV ------------------------------------------------------------------
_CSV_COLUMNS = ["seq", "ts", "kind", "actor", "action", "allowed", "rule",
                "ref", "algorithm", "entry_hash", "params"]


def to_csv(source: Iterable[Entry], path: Optional[str] = None) -> str:
    """A flat CSV table; `params`/decision are JSON-encoded in their cells."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(_CSV_COLUMNS)
    for e in _entries(source):
        w.writerow([
            e.seq, e.ts, e.kind, e.actor, e.action,
            e.decision.get("allowed", ""), e.decision.get("rule", ""),
            e.ref if e.ref is not None else "", e.algorithm, e.entry_hash,
            json.dumps(e.params, sort_keys=True, separators=(",", ":")),
        ])
    text = buf.getvalue()
    if path:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
    return text


# ---- SARIF 2.1.0 ----------------------------------------------------------
def to_sarif(source: Iterable[Entry], path: Optional[str] = None,
             *, tool_version: str = "0.1.0") -> dict:
    """Denied directives become SARIF results (CI / code-scanning friendly).

    Each denied directive is one `error`-level result whose ruleId is the policy
    rule that denied it. Allowed directives and outcomes are not results — a
    clean run (no denials) yields an empty `results` array, which is exactly what
    a CI gate wants to see.
    """
    rules: dict = {}
    results: list = []
    for e in _entries(source):
        if e.kind != "directive" or e.decision.get("allowed") is not False:
            continue
        rule_id = e.decision.get("rule") or "policy.deny"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f"Directive denied by policy rule {rule_id}"},
                "defaultConfiguration": {"level": "error"},
            }
        reason = e.decision.get("reason") or "denied by policy"
        results.append({
            "ruleId": rule_id,
            "level": "error",
            "message": {"text": f"Denied directive '{e.action}' by '{e.actor}': {reason}"},
            "properties": {
                "seq": e.seq, "actor": e.actor, "action": e.action,
                "params": e.params, "entry_hash": e.entry_hash, "ts": e.ts,
            },
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "agentledger",
                "informationUri": "https://github.com/cognis-digital/agentledger",
                "version": tool_version,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
    return doc


# ---- OpenTelemetry spans (OTLP/JSON) --------------------------------------
def _hex_id(seed: str, n_bytes: int) -> str:
    import hashlib
    return hashlib.blake2b(seed.encode("utf-8"), digest_size=n_bytes).hexdigest()


def to_otel_spans(source: Iterable[Entry], path: Optional[str] = None,
                  *, service_name: str = "agentledger") -> dict:
    """Render entries as OpenTelemetry OTLP/JSON spans.

    A directive is a span; its outcomes/approvals are child spans (linked by the
    directive's seq as trace id). Times are nanoseconds since epoch, per OTLP.
    The document is a valid `ExportTraceServiceRequest` body you can POST to an
    OTLP/HTTP collector — but we produce it offline for testability.
    """
    entries = _entries(source)
    # trace id per directive; child entries reuse their referenced directive's id
    trace_of: dict = {}
    for e in entries:
        if e.kind == "directive":
            trace_of[e.seq] = _hex_id(f"trace:{e.seq}", 16)
    spans: list = []
    for e in entries:
        root_seq = e.ref if (e.ref is not None and e.ref in trace_of) else e.seq
        trace_id = trace_of.get(root_seq) or _hex_id(f"trace:{e.seq}", 16)
        span_id = _hex_id(f"span:{e.seq}", 8)
        parent = "" if e.ref is None or e.ref not in trace_of else _hex_id(f"span:{e.ref}", 8)
        start_ns = int(e.ts * 1_000_000_000)
        attrs = [
            {"key": "agentledger.seq", "value": {"intValue": e.seq}},
            {"key": "agentledger.kind", "value": {"stringValue": e.kind}},
            {"key": "agentledger.actor", "value": {"stringValue": e.actor}},
            {"key": "agentledger.entry_hash", "value": {"stringValue": e.entry_hash}},
        ]
        if e.kind == "directive":
            attrs.append({"key": "agentledger.allowed",
                          "value": {"boolValue": bool(e.decision.get("allowed"))}})
            attrs.append({"key": "agentledger.rule",
                          "value": {"stringValue": str(e.decision.get("rule", ""))}})
        # denied directive / failure outcome -> error status
        is_error = (e.kind == "directive" and e.decision.get("allowed") is False)
        span = {
            "traceId": trace_id, "spanId": span_id, "parentSpanId": parent,
            "name": f"{e.kind}:{e.action}", "kind": 1,  # SPAN_KIND_INTERNAL
            "startTimeUnixNano": str(start_ns),
            "endTimeUnixNano": str(start_ns),
            "attributes": attrs,
            "status": {"code": 2 if is_error else 1},  # ERROR / OK
        }
        spans.append(span)
    doc = {"resourceSpans": [{
        "resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": service_name}}]},
        "scopeSpans": [{
            "scope": {"name": "agentledger", "version": "0.1.0"},
            "spans": spans,
        }],
    }]}
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
    return doc


# ---- Signed HTML attestation report ---------------------------------------
def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def to_html_report(source: Iterable[Entry], signer: Signer,
                   path: Optional[str] = None, *,
                   title: str = "AgentLedger Attestation Report",
                   generated_at: Optional[float] = None) -> str:
    """A self-contained, signed HTML attestation of the ledger.

    The report embeds a summary, every entry, the ledger head hash, and an
    attestation block: the signer signs a canonical digest of (head hash +
    entry count + generated_at). A reader with the public key can confirm the
    report was produced by the ledger's key over that exact head — the HTML is
    human-readable *and* machine-checkable via `verify_html_attestation`.
    """
    entries = _entries(source)
    generated_at = time.time() if generated_at is None else generated_at
    head = entries[-1].entry_hash if entries else "0" * 64
    att_payload = json.dumps(
        {"head_hash": head, "entry_count": len(entries),
         "generated_at": generated_at, "algorithm": signer.algorithm},
        sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = signer.sign(att_payload).hex()
    public_key = signer.public_bytes().hex()

    rows = []
    for e in entries:
        decision = ""
        if e.kind == "directive":
            allowed = e.decision.get("allowed")
            decision = ("ALLOW" if allowed else "DENY") + f" ({_esc(e.decision.get('rule',''))})"
        rows.append(
            "<tr>"
            f"<td>{e.seq}</td><td>{_esc(e.kind)}</td><td>{_esc(e.actor)}</td>"
            f"<td>{_esc(e.action)}</td><td>{decision}</td>"
            f"<td>{_esc(e.ref) if e.ref is not None else ''}</td>"
            f"<td class='mono'>{_esc(e.entry_hash[:16])}…</td>"
            "</tr>")

    denied = sum(1 for e in entries
                 if e.kind == "directive" and e.decision.get("allowed") is False)
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{_esc(title)}</title>
<style>
 body{{font:14px system-ui,Segoe UI,Arial,sans-serif;margin:2rem;color:#111}}
 h1{{font-size:1.4rem}} .mono{{font-family:ui-monospace,Consolas,monospace}}
 table{{border-collapse:collapse;width:100%;margin-top:1rem}}
 th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left;font-size:13px}}
 th{{background:#f4f4f6}} .att{{background:#f8f9fb;border:1px solid #dde;
   padding:1rem;border-radius:6px;margin:1rem 0;word-break:break-all}}
 .k{{color:#556}}
</style></head><body>
<h1>{_esc(title)}</h1>
<p class="k">Generated at {_esc(generated_at)} · {len(entries)} entries · {denied} denied directive(s)</p>
<div class="att">
  <strong>Attestation</strong><br>
  <span class="k">algorithm</span> <span class="mono">{_esc(signer.algorithm)}</span><br>
  <span class="k">head_hash</span> <span class="mono">{_esc(head)}</span><br>
  <span class="k">public_key</span> <span class="mono">{_esc(public_key)}</span><br>
  <span class="k">signature</span> <span class="mono">{_esc(signature)}</span><br>
  <span class="k">payload</span> <span class="mono">{_esc(att_payload.decode())}</span>
</div>
<table><thead><tr>
<th>seq</th><th>kind</th><th>actor</th><th>action</th><th>decision</th><th>ref</th><th>entry_hash</th>
</tr></thead><tbody>
{chr(10).join(rows)}
</tbody></table>
</body></html>
"""
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
    return html


def verify_html_attestation(html: str, *, secret: Optional[bytes] = None) -> bool:
    """Verify the attestation block embedded in a report produced by `to_html_report`.

    Extracts payload/signature/public_key/algorithm from the HTML and checks the
    signature offline. For HMAC reports pass the shared `secret`. Returns False
    on any missing/malformed field rather than raising — a tampered report is
    invalid evidence, not a crash.
    """
    import re

    from .signing import verifier_for

    def grab(label: str) -> Optional[str]:
        m = re.search(
            rf'<span class="k">{label}</span> <span class="mono">(.*?)</span>', html)
        return m.group(1) if m else None

    algorithm = grab("algorithm")
    payload = grab("payload")
    signature = grab("signature")
    public_key = grab("public_key")
    if not all([algorithm, payload, signature, public_key]):
        return False
    try:
        verifier = verifier_for(algorithm, secret)
    except (RuntimeError, ValueError):
        return False
    try:
        # payload was HTML-escaped when embedded; unescape the entities we escape
        import html as _htmlmod
        raw = _htmlmod.unescape(payload).encode("utf-8")
        return verifier.verify(raw, bytes.fromhex(signature), bytes.fromhex(public_key))
    except (ValueError, TypeError):
        return False
