"""Real-time sinks: forward each ledger entry as it's recorded.

The evidence bundle is the after-the-fact artifact. Sinks are the live feed:
every directive, outcome, and key rotation is pushed to your SIEM / syslog /
append-only store the moment it lands, so detection and alerting see it in real
time and there's an independent copy outside the ledger's own database.

Sinks are best-effort: a sink that errors is isolated so it can never block or
break the recording of an entry (the signed ledger remains the source of truth).
Each sink receives the same dict as `Entry.as_dict()`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Callable, List, Optional


class Sink:
    """Receives one entry dict per recorded ledger entry."""

    def emit(self, entry: dict) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:
        pass


class JSONLinesSink(Sink):
    """Append each entry as one JSON line to a file (a simple append-only feed)."""

    def __init__(self, path: str):
        self.path = path

    def emit(self, entry: dict) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")


class CallableSink(Sink):
    """Wrap any callable (a logger, a queue put, a custom forwarder)."""

    def __init__(self, fn: Callable[[dict], None]):
        self._fn = fn

    def emit(self, entry: dict) -> None:
        self._fn(entry)


class SyslogSink(Sink):
    """Forward entries to syslog (local socket or a remote SIEM collector).

    address: a path like "/dev/log", or an (host, port) tuple for a network
    collector. Uses the standard library's SysLogHandler; no dependencies.
    """

    def __init__(self, address="/dev/log", facility: Optional[int] = None,
                 tag: str = "agentledger"):
        import logging
        import logging.handlers

        fac = facility if facility is not None else logging.handlers.SysLogHandler.LOG_AUDIT
        handler = logging.handlers.SysLogHandler(address=address, facility=fac)
        handler.setFormatter(logging.Formatter(f"{tag}: %(message)s"))
        self._logger = logging.getLogger(f"agentledger.syslog.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.addHandler(handler)
        self._logger.propagate = False
        self._handler = handler

    def emit(self, entry: dict) -> None:
        self._logger.info(json.dumps(entry, separators=(",", ":")))

    def close(self) -> None:
        self._handler.close()


class HttpSink(Sink):
    """POST each entry as JSON to an HTTP collector (Splunk HEC, a webhook, ...).

    Standard library only (urllib). Failures are swallowed by the dispatcher, so
    a flaky collector never blocks recording.
    """

    def __init__(self, url: str, headers: Optional[dict] = None, timeout: float = 5.0):
        self.url = url
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.timeout = timeout

    def emit(self, entry: dict) -> None:
        import urllib.request

        req = urllib.request.Request(
            self.url, data=json.dumps(entry).encode("utf-8"),
            headers=self.headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout):
            pass


Transport = Callable[[str, bytes, dict], None]
"""A POST transport: (url, body_bytes, headers) -> None; raise on failure.

The HTTP-based sinks below default to a urllib transport, but accept an
injectable `transport` so their exact wire output (URL, headers, body) can be
captured and asserted in tests with no network — that's how they're verified
offline.
"""


def _urllib_transport(timeout: float = 5.0) -> Transport:
    def _post(url: str, body: bytes, headers: dict) -> None:
        import urllib.request

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout):
            pass
    return _post


class SplunkHecSink(Sink):
    """Forward entries to a Splunk HTTP Event Collector (HEC) endpoint.

    Wraps each entry in the HEC envelope ({"event": ..., "time": ..., plus
    optional index/source/sourcetype}) and authenticates with the HEC token via
    the standard `Authorization: Splunk <token>` header. `transport` is
    injectable for offline testing.
    """

    def __init__(self, url: str, token: str, *, index: Optional[str] = None,
                 source: str = "agentledger", sourcetype: str = "agentledger:entry",
                 transport: Optional[Transport] = None, timeout: float = 5.0):
        self.url = url
        self.headers = {"Authorization": f"Splunk {token}",
                        "Content-Type": "application/json"}
        self.index = index
        self.source = source
        self.sourcetype = sourcetype
        self._post = transport or _urllib_transport(timeout)

    def _envelope(self, entry: dict) -> dict:
        env = {"time": entry.get("ts", time.time()), "event": entry,
               "source": self.source, "sourcetype": self.sourcetype}
        if self.index:
            env["index"] = self.index
        return env

    def emit(self, entry: dict) -> None:
        body = json.dumps(self._envelope(entry), separators=(",", ":")).encode("utf-8")
        self._post(self.url, body, dict(self.headers))


class ElasticSink(Sink):
    """Index entries into Elasticsearch via the `_bulk` API (one doc per entry).

    Sends a two-line NDJSON bulk request (action metadata + document) so it drops
    straight into the standard Elastic ingest path. Uses the entry's chained
    `entry_hash` as the document `_id`, which makes ingestion idempotent — the
    same entry can't be double-counted. `transport` is injectable for testing.
    """

    def __init__(self, url: str, index: str = "agentledger",
                 *, api_key: Optional[str] = None,
                 transport: Optional[Transport] = None, timeout: float = 5.0):
        # url is the base ES url; bulk endpoint is derived
        self.bulk_url = url.rstrip("/") + "/_bulk"
        self.index = index
        self.headers = {"Content-Type": "application/x-ndjson"}
        if api_key:
            self.headers["Authorization"] = f"ApiKey {api_key}"
        self._post = transport or _urllib_transport(timeout)

    def emit(self, entry: dict) -> None:
        doc_id = entry.get("entry_hash")
        action = {"index": {"_index": self.index, "_id": doc_id}}
        body = (json.dumps(action, separators=(",", ":")) + "\n"
                + json.dumps(entry, separators=(",", ":")) + "\n").encode("utf-8")
        self._post(self.bulk_url, body, dict(self.headers))


class SignedWebhookSink(Sink):
    """POST entries to a webhook with an HMAC signature header.

    Signs the exact request body with a shared secret (HMAC-SHA256) and sends the
    hex digest in a header (default `X-AgentLedger-Signature`, GitHub-style
    `sha256=` prefix). The receiver recomputes the HMAC over the raw body to
    confirm the payload came from you and wasn't altered in transit — the same
    pattern GitHub/Stripe webhooks use. `transport` is injectable for testing.
    """

    def __init__(self, url: str, secret: bytes,
                 *, signature_header: str = "X-AgentLedger-Signature",
                 headers: Optional[dict] = None,
                 transport: Optional[Transport] = None, timeout: float = 5.0):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        self.url = url
        self.secret = secret
        self.signature_header = signature_header
        self.base_headers = {"Content-Type": "application/json", **(headers or {})}
        self._post = transport or _urllib_transport(timeout)

    def _sign(self, body: bytes) -> str:
        return "sha256=" + hmac.new(self.secret, body, hashlib.sha256).hexdigest()

    def emit(self, entry: dict) -> None:
        body = json.dumps(entry, separators=(",", ":")).encode("utf-8")
        headers = dict(self.base_headers)
        headers[self.signature_header] = self._sign(body)
        self._post(self.url, body, headers)

    @staticmethod
    def verify_signature(secret: bytes, body: bytes, header_value: str) -> bool:
        """Receiver-side check: does `header_value` match HMAC over `body`?"""
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, header_value or "")


class SinkDispatcher:
    """Fans an entry out to many sinks, isolating each sink's failures."""

    def __init__(self, sinks: Optional[List[Sink]] = None,
                 on_error: Optional[Callable[[Sink, Exception], None]] = None):
        self.sinks: List[Sink] = list(sinks or [])
        self.on_error = on_error

    def add(self, sink: Sink) -> None:
        self.sinks.append(sink)

    def emit(self, entry: dict) -> None:
        for sink in self.sinks:
            try:
                sink.emit(entry)
            except Exception as e:  # noqa: BLE001 - never let a sink break recording
                if self.on_error:
                    self.on_error(sink, e)

    def close(self) -> None:
        for sink in self.sinks:
            try:
                sink.close()
            except Exception:  # noqa: BLE001
                pass
