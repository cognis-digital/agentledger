"""A small query/filter API over a ledger.

The ledger is append-only and hash-chained, so you never mutate it — but you do
need to *ask questions* of it: "every denied directive last hour", "everything
actor X did", "the outcomes for this directive". Doing that by hand means
re-implementing the same filters everywhere and risking an off-by-one on the
time window.

`Query` is a tiny, chainable, read-only view. It reads entries straight from the
ledger (or any iterable of `Entry`), never writes, and composes:

    from agentledger.query import Query
    denied = Query(rec.ledger).kind("directive").denied().since(t0).all()

Every filter returns a new `Query`, so the source is never consumed or mutated.
`count`, `all`, `first`, `latest`, and `summary` materialize results. Nothing
here touches signatures or the chain — use `verify()` for integrity; this is for
*reading* an already-trusted ledger.
"""

from __future__ import annotations

from typing import Callable, Iterable, Iterator, Optional

from .ledger import Entry


class Query:
    """A composable, read-only filter over ledger entries.

    Accepts a `Ledger` (anything iterable of `Entry`) or an explicit iterable of
    `Entry`. Filters are lazy where cheap and eager where a materialized list is
    clearer; either way the source ledger is never modified.
    """

    def __init__(self, source: Iterable[Entry]):
        # Materialize once so the same Query object can be iterated repeatedly
        # and so chaining doesn't exhaust a one-shot generator.
        self._entries: list[Entry] = list(source)

    # ---- construction helpers ------------------------------------------
    def _derive(self, entries: Iterable[Entry]) -> "Query":
        q = Query.__new__(Query)
        q._entries = list(entries)
        return q

    # ---- filters (each returns a new Query) ----------------------------
    def kind(self, *kinds: str) -> "Query":
        """Keep entries whose `kind` is one of the given kinds."""
        wanted = set(kinds)
        return self._derive(e for e in self._entries if e.kind in wanted)

    def actor(self, *actors: str) -> "Query":
        wanted = set(actors)
        return self._derive(e for e in self._entries if e.actor in wanted)

    def action(self, *actions: str) -> "Query":
        wanted = set(actions)
        return self._derive(e for e in self._entries if e.action in wanted)

    def refers_to(self, seq: int) -> "Query":
        """Keep entries whose `ref` points at `seq` (outcomes/approvals of it)."""
        return self._derive(e for e in self._entries if e.ref == seq)

    def since(self, ts: float, *, inclusive: bool = True) -> "Query":
        """Entries at or after `ts` (unix seconds)."""
        if inclusive:
            return self._derive(e for e in self._entries if e.ts >= ts)
        return self._derive(e for e in self._entries if e.ts > ts)

    def until(self, ts: float, *, inclusive: bool = True) -> "Query":
        """Entries at or before `ts` (unix seconds)."""
        if inclusive:
            return self._derive(e for e in self._entries if e.ts <= ts)
        return self._derive(e for e in self._entries if e.ts < ts)

    def between(self, start: float, end: float) -> "Query":
        """Entries in [start, end] (inclusive both ends)."""
        return self.since(start).until(end)

    def allowed(self) -> "Query":
        """Directives whose recorded policy decision allowed them."""
        return self._derive(
            e for e in self._entries if e.decision.get("allowed") is True)

    def denied(self) -> "Query":
        """Directives whose recorded policy decision denied them."""
        return self._derive(
            e for e in self._entries if e.decision.get("allowed") is False)

    def rule(self, *rules: str) -> "Query":
        """Directives decided by one of the named policy rules."""
        wanted = set(rules)
        return self._derive(
            e for e in self._entries if e.decision.get("rule") in wanted)

    def algorithm(self, *algorithms: str) -> "Query":
        wanted = set(algorithms)
        return self._derive(e for e in self._entries if e.algorithm in wanted)

    def where(self, predicate: Callable[[Entry], bool]) -> "Query":
        """Arbitrary predicate escape hatch for anything not covered above."""
        return self._derive(e for e in self._entries if predicate(e))

    def param_eq(self, key: str, value) -> "Query":
        """Keep entries whose `params[key]` equals `value`."""
        return self._derive(
            e for e in self._entries if e.params.get(key) == value)

    # ---- ordering / windowing ------------------------------------------
    def order_by_ts(self, *, descending: bool = False) -> "Query":
        return self._derive(
            sorted(self._entries, key=lambda e: (e.ts, e.seq), reverse=descending))

    def limit(self, n: int) -> "Query":
        if n < 0:
            raise ValueError("limit must be >= 0")
        return self._derive(self._entries[:n])

    # ---- terminals ------------------------------------------------------
    def __iter__(self) -> Iterator[Entry]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def all(self) -> list[Entry]:
        return list(self._entries)

    def seqs(self) -> list[int]:
        return [e.seq for e in self._entries]

    def count(self) -> int:
        return len(self._entries)

    def first(self) -> Optional[Entry]:
        return self._entries[0] if self._entries else None

    def latest(self) -> Optional[Entry]:
        """The highest-seq entry currently in the view (seq is monotonic)."""
        return max(self._entries, key=lambda e: e.seq) if self._entries else None

    def summary(self) -> dict:
        """A small aggregate: counts by kind, allowed/denied, distinct actors."""
        by_kind: dict = {}
        allowed = denied = 0
        actors: set = set()
        actions: set = set()
        for e in self._entries:
            by_kind[e.kind] = by_kind.get(e.kind, 0) + 1
            actors.add(e.actor)
            actions.add(e.action)
            if e.kind == "directive":
                if e.decision.get("allowed") is True:
                    allowed += 1
                elif e.decision.get("allowed") is False:
                    denied += 1
        return {
            "total": len(self._entries),
            "by_kind": dict(sorted(by_kind.items())),
            "directives_allowed": allowed,
            "directives_denied": denied,
            "distinct_actors": len(actors),
            "distinct_actions": len(actions),
        }
