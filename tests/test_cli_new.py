"""CLI tests for the new v0.2 commands: query, prove/verify-proof,
seal/verify-checkpoint, export-format, and verify --strict."""
import json

from agentledger.cli import main


def run(capsys, *args):
    code = main(list(args))
    out = capsys.readouterr().out.strip()
    return code, (json.loads(out) if out else None)


def _setup(tmp_path, capsys):
    key = str(tmp_path / "agent.key")
    ledger = str(tmp_path / "ledger.db")
    run(capsys, "keygen", "--algorithm", "ed25519", "--out", key)
    run(capsys, "submit", "--action", "deploy", "--actor", "alice",
        "--param", "env=prod", "--ledger", ledger, "--key", key)
    run(capsys, "outcome", "--ref", "1", "--actor", "agent", "--status",
        "success", "--ledger", ledger, "--key", key)
    run(capsys, "submit", "--action", "rollback", "--actor", "bob",
        "--ledger", ledger, "--key", key)
    return key, ledger


def test_query_rows_and_summary(tmp_path, capsys):
    key, ledger = _setup(tmp_path, capsys)
    code, rows = run(capsys, "query", "--ledger", ledger, "--key", key,
                     "--kind", "directive")
    assert code == 0 and len(rows) == 2
    code, summ = run(capsys, "query", "--ledger", ledger, "--key", key, "--summary")
    assert code == 0 and summ["total"] == 3
    assert summ["by_kind"]["outcome"] == 1


def test_query_actor_filter(tmp_path, capsys):
    key, ledger = _setup(tmp_path, capsys)
    code, rows = run(capsys, "query", "--ledger", ledger, "--key", key,
                     "--actor", "alice")
    assert code == 0 and [r["actor"] for r in rows] == ["alice"]


def test_prove_and_verify_proof(tmp_path, capsys):
    key, ledger = _setup(tmp_path, capsys)
    proof = str(tmp_path / "proof.json")
    code, info = run(capsys, "prove", "--ledger", ledger, "--key", key,
                     "--seq", "1", "--out", proof)
    assert code == 0 and info["seq"] == 1
    code, res = run(capsys, "verify-proof", proof, "--root", info["root"])
    assert code == 0 and res["included"] is True
    # wrong root fails with non-zero exit
    code, res = run(capsys, "verify-proof", proof, "--root", "a" * 64)
    assert code == 1 and res["included"] is False


def test_seal_and_verify_checkpoint(tmp_path, capsys):
    key, ledger = _setup(tmp_path, capsys)
    archive = str(tmp_path / "arch.json")
    cp = str(tmp_path / "cp.json")
    code, info = run(capsys, "seal", "--ledger", ledger, "--key", key,
                     "--keep-last", "1", "--archive", archive, "--checkpoint", cp)
    assert code == 0 and info["sealed"] == 2
    code, res = run(capsys, "verify-checkpoint", cp)
    assert code == 0 and res["valid"] is True


def test_export_format_all(tmp_path, capsys):
    key, ledger = _setup(tmp_path, capsys)
    for fmt, ext in [("jsonl", "jsonl"), ("csv", "csv"), ("sarif", "json"),
                     ("otel", "json"), ("html", "html")]:
        out = str(tmp_path / f"out.{ext}")
        code, info = run(capsys, "export-format", "--ledger", ledger, "--key", key,
                         "--format", fmt, "--out", out)
        assert code == 0 and info["format"] == fmt
        assert open(out, encoding="utf-8").read()  # non-empty


def test_verify_strict_passes_clean_and_fails_on_denial(tmp_path, capsys):
    key = str(tmp_path / "k.key")
    ledger = str(tmp_path / "l.db")
    run(capsys, "keygen", "--out", key)
    run(capsys, "submit", "--action", "ok", "--ledger", ledger, "--key", key)
    code, res = run(capsys, "verify", "--ledger", ledger, "--strict")
    assert code == 0 and res["passed"] is True

    # a denied directive must fail the strict gate. Build a ledger with a deny
    # rule via the Recorder directly, then point the CLI at it.
    from agentledger import PolicyGate, Recorder
    from agentledger.signing import load_key
    ledger2 = str(tmp_path / "l2.db")
    rec = Recorder(gate=PolicyGate(default_allow=True).deny("bad", name="deny:bad"),
                   signer=load_key(key), db_path=ledger2)
    rec.submit("x", "ok")
    rec.submit("x", "bad")  # denied
    code, res = run(capsys, "verify", "--ledger", ledger2, "--strict")
    assert code == 1 and res["passed"] is False
    assert res["denied_directives"] == [2]
