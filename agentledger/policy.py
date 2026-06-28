"""A small policy gate.

Directives are evaluated before they're recorded as allowed, so "what was
permitted, and under which rule" becomes part of the evidence. This gate is
intentionally minimal — glob-matched allow/deny rules with optional predicates,
plus a hook to delegate to an external evaluator (e.g. a full `sentinel-policy`
doctrine). The richer doctrine lives there; agentledger only needs a decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Callable, List, Optional

Directive = dict
Predicate = Callable[[Directive], bool]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule: str
    reason: str = ""

    def as_dict(self) -> dict:
        return {"allowed": self.allowed, "rule": self.rule, "reason": self.reason}


@dataclass
class _Rule:
    effect: str  # allow | deny
    action_glob: str
    when: Optional[Predicate]
    reason: str
    name: str

    def matches(self, directive: Directive) -> bool:
        if not fnmatch(str(directive.get("action", "")), self.action_glob):
            return False
        if self.when is not None and not self.when(directive):
            return False
        return True


class PolicyGate:
    def __init__(self, default_allow: bool = True):
        self.default_allow = default_allow
        self._rules: List[_Rule] = []
        self._external: List[Callable[[Directive], Optional[Decision]]] = []

    def deny(self, action_glob: str = "*", when: Optional[Predicate] = None,
             reason: str = "", name: str = "") -> "PolicyGate":
        self._rules.append(_Rule("deny", action_glob, when, reason, name or f"deny:{action_glob}"))
        return self

    def allow(self, action_glob: str = "*", when: Optional[Predicate] = None,
              reason: str = "", name: str = "") -> "PolicyGate":
        self._rules.append(_Rule("allow", action_glob, when, reason, name or f"allow:{action_glob}"))
        return self

    def use(self, evaluator: Callable[[Directive], Optional[Decision]]) -> "PolicyGate":
        """Delegate to an external evaluator; the first non-None decision wins."""
        self._external.append(evaluator)
        return self

    def evaluate(self, directive: Directive) -> Decision:
        # external evaluators get first say (e.g. an org-wide doctrine)
        for ext in self._external:
            decision = ext(directive)
            if decision is not None:
                return decision
        # rules in declaration order; first match wins (explicit allow or deny)
        for rule in self._rules:
            if rule.matches(directive):
                return Decision(rule.effect == "allow", rule.name, rule.reason)
        return Decision(self.default_allow, "default",
                        "default-allow" if self.default_allow else "default-deny")
