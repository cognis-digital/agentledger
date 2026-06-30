"""Policy gate edge cases: ordering, predicates, externals, error isolation."""
from agentledger.policy import Decision, PolicyGate


def test_empty_gate_default_allow():
    assert PolicyGate(default_allow=True).evaluate({"action": "anything"}).allowed


def test_empty_gate_default_deny():
    d = PolicyGate(default_allow=False).evaluate({"action": "anything"})
    assert not d.allowed and d.rule == "default"


def test_glob_wildcard_matches_all():
    gate = PolicyGate(default_allow=True).deny("*", reason="lockdown")
    assert not gate.evaluate({"action": "anything"}).allowed


def test_glob_partial_match():
    gate = PolicyGate(default_allow=True).deny("delete.*")
    assert not gate.evaluate({"action": "delete.all"}).allowed
    assert gate.evaluate({"action": "read.all"}).allowed


def test_first_matching_rule_wins_allow_then_deny():
    gate = PolicyGate(default_allow=False).allow("safe.*").deny("safe.delete")
    assert gate.evaluate({"action": "safe.delete"}).allowed   # allow declared first


def test_first_matching_rule_wins_deny_then_allow():
    gate = PolicyGate(default_allow=True).deny("safe.delete").allow("safe.*")
    assert not gate.evaluate({"action": "safe.delete"}).allowed


def test_predicate_true_and_false_branches():
    gate = PolicyGate(default_allow=True).deny(
        "deploy", when=lambda d: d["params"].get("env") == "prod")
    assert not gate.evaluate({"action": "deploy", "params": {"env": "prod"}}).allowed
    assert gate.evaluate({"action": "deploy", "params": {"env": "dev"}}).allowed


def test_predicate_not_matched_falls_through():
    # predicate False -> rule doesn't match -> default applies
    gate = PolicyGate(default_allow=True).deny(
        "deploy", when=lambda d: d["params"].get("env") == "prod")
    d = gate.evaluate({"action": "deploy", "params": {"env": "dev"}})
    assert d.allowed and d.rule == "default"


def test_missing_action_key_treated_as_empty():
    gate = PolicyGate(default_allow=True).deny("*")
    # action defaults to "" and "*" matches it
    assert not gate.evaluate({}).allowed


def test_external_evaluator_first_non_none_wins():
    def ext(d):
        if d["action"] == "exfiltrate":
            return Decision(False, "doctrine", "blocked")
        return None
    gate = PolicyGate(default_allow=True).use(ext).allow("*")
    assert not gate.evaluate({"action": "exfiltrate"}).allowed
    assert gate.evaluate({"action": "read"}).allowed


def test_multiple_externals_order():
    calls = []
    def first(d):
        calls.append("first")
        return None
    def second(d):
        calls.append("second")
        return Decision(False, "second", "")
    gate = PolicyGate(default_allow=True).use(first).use(second)
    gate.evaluate({"action": "x"})
    assert calls == ["first", "second"]


def test_external_overrides_rules():
    def ext(d):
        return Decision(True, "ext-allow", "")
    # a deny rule exists, but the external evaluator gets first say
    gate = PolicyGate(default_allow=True).use(ext).deny("*")
    assert gate.evaluate({"action": "anything"}).allowed


def test_decision_as_dict_shape():
    d = Decision(True, "rule-x", "because")
    assert d.as_dict() == {"allowed": True, "rule": "rule-x", "reason": "because"}


def test_named_rule_propagates_to_decision():
    gate = PolicyGate(default_allow=True).deny("x", name="my-rule", reason="r")
    d = gate.evaluate({"action": "x"})
    assert d.rule == "my-rule" and d.reason == "r"


def test_chaining_returns_gate():
    gate = PolicyGate()
    assert gate.allow("a") is gate
    assert gate.deny("b") is gate
    assert gate.use(lambda d: None) is gate
