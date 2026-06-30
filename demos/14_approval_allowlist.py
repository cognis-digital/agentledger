"""Scenario 14 - controls / separation-of-duties.

m-of-n approval is only meaningful if the approvers are the *right* people.
approval_status accepts an allowlist of authorized approver public keys, so an
outsider's signature -- even a cryptographically valid one -- doesn't count
toward the threshold.

This requires 2 approvals from a 3-person on-call rotation, shows an outsider's
valid-but-unauthorized approval being ignored, and that a duplicate from one
authorized key counts once.
"""
from _common import best_signer, rule, step
from agentledger import PolicyGate, Recorder


def main() -> None:
    rule("APPROVAL ALLOWLIST  -  valid signature is not enough; must be authorized")

    rec = Recorder(gate=PolicyGate(default_allow=True), signer=best_signer("ed25519"))

    # the authorized on-call rotation
    oncall = {name: best_signer("ed25519") for name in ("alice", "bob", "carol")}
    allow = {s.public_bytes().hex() for s in oncall.values()}
    outsider = best_signer("ed25519")  # a valid key, but NOT on the rotation

    step(1, "Submit a high-blast-radius directive (threshold = 2 authorized).")
    _, directive = rec.submit("alice", "rotate-root-credentials", {"scope": "prod"})
    print(f"   directive seq={directive.seq}; needs 2 distinct authorized approvers.")

    def status():
        return rec.approval_status(directive.seq, threshold=2, allowed_keys=allow)

    step(2, "An OUTSIDER approves with a valid signature.")
    rec.approve(directive.seq, "stranger", outsider)
    s = status()
    print(f"   approvals counted toward allowlist={len(s.approver_keys)}  "
          f"satisfied={s.satisfied}   (outsider ignored)")

    step(3, "alice (authorized) approves, then approves AGAIN.")
    rec.approve(directive.seq, "alice", oncall["alice"])
    rec.approve(directive.seq, "alice", oncall["alice"])
    s = status()
    print(f"   approvals={len(s.approver_keys)}  satisfied={s.satisfied}   "
          "(duplicate counts once; 1 of 2)")

    step(4, "bob (authorized) approves -> threshold met.")
    rec.approve(directive.seq, "bob", oncall["bob"])
    s = status()
    print(f"   approvals={len(s.approver_keys)}  satisfied={s.satisfied}")

    step(5, "Now authorized, run it and record the outcome.")
    if s.satisfied:
        out = rec.record_outcome(directive.seq, "agent:iam", "success", {"rotated": True})
        print(f"   outcome seq={out.seq} recorded.")

    ok, _ = rec.verify()
    print(f"\nverify() -> intact={ok}. Approvals, the outsider's ignored one, and the")
    print("outcome all live in the same signed chain -- separation of duties, provable.")


if __name__ == "__main__":
    main()
