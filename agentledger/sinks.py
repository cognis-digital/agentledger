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

import json
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
