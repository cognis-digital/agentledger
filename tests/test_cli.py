import json

from agentledger.cli import main


def run(capsys, *args):
    code = main(list(args))
    out = capsys.readouterr().out.strip()
    return code, (json.loads(out) if out else None)


def test_full_cli_flow(tmp_path, capsys):
    key = str(tmp_path / "agent.key")
    newkey = str(tmp_path / "new.key")
    ledger = str(tmp_path / "ledger.db")
    bundle = str(tmp_path / "evidence.json")

    code, info = run(capsys, "keygen", "--algorithm", "ed25519", "--out", key)
    assert code == 0 and info["algorithm"] == "ed25519"

    code, sub = run(capsys, "submit", "--action", "deploy", "--actor", "alice",
                    "--param", "env=prod", "--ledger", ledger, "--key", key)
    assert code == 0 and sub["seq"] == 1 and sub["allowed"] is True

    code, out = run(capsys, "outcome", "--ref", "1", "--actor", "agent",
                    "--status", "success", "--ledger", ledger, "--key", key)
    assert code == 0 and out["ref"] == 1

    # rotate to a new key, then keep recording
    code, rot = run(capsys, "rotate", "--algorithm", "ed25519", "--out", newkey,
                    "--ledger", ledger, "--key", key)
    assert code == 0 and "rotation_seq" in rot
    code, _ = run(capsys, "submit", "--action", "rollback", "--ledger", ledger, "--key", newkey)
    assert code == 0

    # verify the whole ledger (across the rotation)
    code, ver = run(capsys, "verify", "--ledger", ledger)
    assert code == 0 and ver["intact"] is True

    # export and independently verify the bundle
    code, exp = run(capsys, "export", "--ledger", ledger, "--out", bundle)
    assert code == 0 and exp["entries"] >= 4
    code, vb = run(capsys, "verify-bundle", bundle)
    assert code == 0 and vb["intact"] is True


def test_verify_detects_tamper(tmp_path, capsys):
    key = str(tmp_path / "k.key")
    ledger = str(tmp_path / "l.db")
    run(capsys, "keygen", "--out", key)
    run(capsys, "submit", "--action", "a", "--ledger", ledger, "--key", key)
    run(capsys, "submit", "--action", "b", "--ledger", ledger, "--key", key)

    import sqlite3
    conn = sqlite3.connect(ledger)
    conn.execute("UPDATE entries SET action='HACKED' WHERE seq=1")
    conn.commit()
    conn.close()

    code, ver = run(capsys, "verify", "--ledger", ledger)
    assert code == 1 and ver["intact"] is False and ver["first_broken_seq"] == 1
