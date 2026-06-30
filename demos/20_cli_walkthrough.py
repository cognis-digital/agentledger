"""Scenario 20 - operators who drive everything from the shell.

Everything the library does is available from the `agentledger` CLI. This drives
the CLI in-process (calling cli.main with argv) through a full lifecycle --
keygen, submit, outcome, rotate, verify, export, verify-bundle -- against a temp
database, exactly as you would from a shell script in CI or a runbook.

It captures and prints each command's JSON result and asserts the exit codes, so
it doubles as a living example of the command surface.
"""
import json
import os
import tempfile
from contextlib import redirect_stdout
from io import StringIO

from _common import rule, step
from agentledger.cli import main as cli_main


def run(*args):
    buf = StringIO()
    with redirect_stdout(buf):
        code = cli_main(list(args))
    out = buf.getvalue().strip()
    return code, (json.loads(out) if out else None)


def main() -> None:
    rule("CLI WALKTHROUGH  -  the whole lifecycle from the command line")

    d = tempfile.mkdtemp(prefix="agentledger_demo_")
    key = os.path.join(d, "agent.key")
    newkey = os.path.join(d, "new.key")
    ledger = os.path.join(d, "ledger.db")
    bundle = os.path.join(d, "evidence.json")

    step(1, "keygen: create an ed25519 signing key.")
    code, info = run("keygen", "--algorithm", "ed25519", "--out", key)
    print(f"   exit={code}  algorithm={info['algorithm']}  "
          f"public_key={info['public_key'][:24]}...")
    assert code == 0

    step(2, "submit: evaluate + record a directive (signed).")
    code, sub = run("submit", "--action", "deploy", "--actor", "alice",
                    "--param", "env=prod", "--ledger", ledger, "--key", key)
    print(f"   exit={code}  seq={sub['seq']}  allowed={sub['allowed']}  "
          f"hash={sub['entry_hash'][:12]}...")
    assert code == 0

    step(3, "outcome: record what happened.")
    code, out = run("outcome", "--ref", str(sub["seq"]), "--actor", "agent",
                    "--status", "success", "--param", "pods=4",
                    "--ledger", ledger, "--key", key)
    print(f"   exit={code}  seq={out['seq']}  ref={out['ref']}  status={out['status']}")
    assert code == 0

    step(4, "rotate: move to a new key, then keep recording.")
    code, rot = run("rotate", "--algorithm", "ed25519", "--out", newkey,
                    "--ledger", ledger, "--key", key)
    print(f"   exit={code}  rotation_seq={rot['rotation_seq']}")
    run("submit", "--action", "rollback", "--ledger", ledger, "--key", newkey)
    assert code == 0

    step(5, "verify: check chain + signatures + continuity (no key needed).")
    code, ver = run("verify", "--ledger", ledger)
    print(f"   exit={code}  intact={ver['intact']}  entries={ver['entries']}")
    assert code == 0 and ver["intact"]

    step(6, "export + verify-bundle: hand off an offline-verifiable file.")
    code, exp = run("export", "--ledger", ledger, "--out", bundle)
    print(f"   exit={code}  exported {exp['entries']} entries  head={exp['head_hash'][:12]}...")
    code, vb = run("verify-bundle", bundle)
    print(f"   verify-bundle exit={code}  intact={vb['intact']}")
    assert code == 0 and vb["intact"]

    print("\nThe entire lifecycle ran from the CLI; every step verified end to end.")


if __name__ == "__main__":
    main()
