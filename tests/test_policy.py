from agentledger.policy import Decision, PolicyGate


def test_default_allow():
    assert PolicyGate(default_allow=True).evaluate({"action": "x"}).allowed


def test_default_deny():
    d = PolicyGate(default_allow=False).evaluate({"action": "x"})
    assert not d.allowed
    assert d.rule == "default"


def test_deny_rule_by_glob():
    gate = PolicyGate().deny("deploy.*", reason="prod is gated")
    assert gate.evaluate({"action": "deploy.prod"}).allowed is False
    assert gate.evaluate({"action": "read.logs"}).allowed is True


def test_predicate_condition():
    gate = PolicyGate().deny("deploy", when=lambda d: d["params"].get("env") == "prod")
    assert not gate.evaluate({"action": "deploy", "params": {"env": "prod"}}).allowed
    assert gate.evaluate({"action": "deploy", "params": {"env": "dev"}}).allowed


def test_first_match_wins():
    gate = PolicyGate(default_allow=False).allow("safe.*").deny("safe.delete")
    # allow rule declared first matches safe.delete first -> allowed
    assert gate.evaluate({"action": "safe.delete"}).allowed


def test_external_evaluator_precedence():
    def doctrine(directive):
        if directive["action"] == "exfiltrate":
            return Decision(False, "doctrine:no-exfil", "blocked by org doctrine")
        return None

    gate = PolicyGate(default_allow=True).use(doctrine)
    assert not gate.evaluate({"action": "exfiltrate"}).allowed
    assert gate.evaluate({"action": "read"}).allowed
