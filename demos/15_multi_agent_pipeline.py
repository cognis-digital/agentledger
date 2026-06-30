"""Scenario 15 - orchestrators running a multi-agent pipeline.

Real systems chain agents: a planner emits a directive, a worker acts, a
reviewer checks. agentledger records the whole pipeline as one signed chain, so
you can see exactly which agent did what, in what order, under which policy --
across agent boundaries and frameworks.

This plays a three-stage pipeline (plan -> build -> review) with outcomes at each
stage, then prints the end-to-end provenance.
"""
from _common import fresh_recorder, rule, step
from agentledger import PolicyGate


def main() -> None:
    rule("MULTI-AGENT PIPELINE  -  one signed chain across agent boundaries")

    gate = PolicyGate(default_allow=True).deny(
        "publish", when=lambda d: not d["params"].get("reviewed"),
        reason="nothing publishes without a review stage", name="require-review")
    rec = fresh_recorder(gate=gate)

    step(1, "Planner agent issues a build directive.")
    _, plan = rec.submit("agent:planner", "build", {"target": "report-Q3", "sections": 5})
    rec.record_outcome(plan.seq, "agent:planner", "planned", {"tasks": 5})

    step(2, "Worker agent executes the build and reports the outcome.")
    _, build = rec.submit("agent:worker", "build", {"target": "report-Q3"})
    rec.record_outcome(build.seq, "agent:worker", "success", {"artifacts": 3})

    step(3, "Reviewer agent approves; an unreviewed publish is BLOCKED first.")
    _, blocked = rec.submit("agent:worker", "publish", {"target": "report-Q3", "reviewed": False})
    print(f"   premature publish -> allowed={blocked.decision['allowed']} "
          f"rule={blocked.decision['rule']!r}")
    _, review = rec.submit("agent:reviewer", "review", {"target": "report-Q3"})
    rec.record_outcome(review.seq, "agent:reviewer", "approved", {"score": 0.94})

    step(4, "Now publish, marked reviewed.")
    _, pub = rec.submit("agent:publisher", "publish", {"target": "report-Q3", "reviewed": True})
    rec.record_outcome(pub.seq, "agent:publisher", "success", {"url": "s3://reports/q3"})

    step(5, "End-to-end provenance, as the signed chain recorded it:")
    for e in rec.entries():
        tag = "ALLOW" if (e.kind != "directive" or e.decision.get("allowed")) else "DENY "
        ref = f" (re #{e.ref})" if e.ref else ""
        print(f"   #{e.seq} [{tag}] {e.kind:<9} {e.actor:<17} {e.action}{ref}")

    ok, broken = rec.verify()
    print(f"\nverify() -> intact={ok}. Every agent's step is one signed, ordered fact.")


if __name__ == "__main__":
    main()
