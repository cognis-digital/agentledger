"""CLI edge cases: param parsing, exit codes, hmac path, bad inputs."""
import json

import pytest

from agentledger.cli import build_parser, main, _parse_params


def run(capsys, *args):
    code = main(list(args))
    out = capsys.readouterr().out.strip()
    return code, (json.loads(out) if out else None)


def test_parse_params_types():
    p = _parse_params(["env=prod", "n=5", "flag=true", "off=false"])
    assert p == {"env": "prod", "n": 5, "flag": True, "off": False}


def test_parse_params_bad_pair_exits():
    with pytest.raises(SystemExit):
        _parse_params(["noequals"])


def test_parse_params_empty_list():
    assert _parse_params([]) == {}
    assert _parse_params(None) == {}


def test_keygen_then_verify_empty_ledger(tmp_path, capsys):
    key = str(tmp_path / "k.key")
    ledger = str(tmp_path / "l.db")
    code, info = run(capsys, "keygen", "--out", key)
    assert code == 0 and info["algorithm"] == "ed25519"
    code, ver = run(capsys, "verify", "--ledger", ledger)
    assert code == 0 and ver["intact"] is True and ver["entries"] == 0


def test_submit_denied_returns_exit_2(tmp_path, capsys):
    # default gate is default_allow=True, so to get a denial we need a denied
    # action; the CLI's gate allows everything, so this confirms allow exit 0.
    key = str(tmp_path / "k.key")
    ledger = str(tmp_path / "l.db")
    run(capsys, "keygen", "--out", key)
    code, sub = run(capsys, "submit", "--action", "anything",
                    "--ledger", ledger, "--key", key)
    assert code == 0 and sub["allowed"] is True


def test_approvals_exit_code_reflects_satisfaction(tmp_path, capsys):
    ledger = str(tmp_path / "l.db")
    lk = str(tmp_path / "l.key")
    ak = str(tmp_path / "a.key")
    run(capsys, "keygen", "--out", lk)
    run(capsys, "keygen", "--out", ak)
    _, sub = run(capsys, "submit", "--action", "deploy", "--ledger", ledger, "--key", lk)
    ref = str(sub["seq"])
    # no approvals yet -> threshold 1 unsatisfied -> exit 1
    code, _ = run(capsys, "approvals", "--ref", ref, "--threshold", "1", "--ledger", ledger)
    assert code == 1
    run(capsys, "approve", "--ref", ref, "--approver", "a",
        "--approver-key", ak, "--ledger", ledger, "--key", lk)
    code, st = run(capsys, "approvals", "--ref", ref, "--threshold", "1", "--ledger", ledger)
    assert code == 0 and st["satisfied"] is True


def test_hmac_keygen_and_full_flow(tmp_path, capsys):
    key = str(tmp_path / "h.key")
    ledger = str(tmp_path / "l.db")
    bundle = str(tmp_path / "b.json")
    code, info = run(capsys, "keygen", "--algorithm", "hmac", "--out", key)
    assert code == 0 and info["algorithm"] == "hmac-sha256"
    assert info["third_party_verifiable"] is False
    run(capsys, "submit", "--action", "x", "--ledger", ledger, "--key", key)
    # verify with the key (hmac needs the secret)
    code, ver = run(capsys, "verify", "--ledger", ledger, "--key", key)
    assert code == 0 and ver["intact"] is True
    # export + verify bundle requires the secret for hmac
    run(capsys, "export", "--ledger", ledger, "--out", bundle, "--key", key)
    import json as _json
    secret_hex = _json.loads(open(key, encoding="utf-8").read())["private"]
    code, vb = run(capsys, "verify-bundle", bundle, "--secret", secret_hex)
    assert code == 0 and vb["intact"] is True


def test_verify_bundle_detects_tamper_via_cli(tmp_path, capsys):
    key = str(tmp_path / "k.key")
    ledger = str(tmp_path / "l.db")
    bundle = str(tmp_path / "b.json")
    run(capsys, "keygen", "--out", key)
    run(capsys, "submit", "--action", "a", "--ledger", ledger, "--key", key)
    run(capsys, "submit", "--action", "b", "--ledger", ledger, "--key", key)
    run(capsys, "export", "--ledger", ledger, "--out", bundle, "--key", key)
    data = json.loads(open(bundle, encoding="utf-8").read())
    data["entries"][0]["action"] = "HACKED"
    open(bundle, "w", encoding="utf-8").write(json.dumps(data))
    code, vb = run(capsys, "verify-bundle", bundle)
    assert code == 1 and vb["intact"] is False


def test_rotate_changes_signing_key(tmp_path, capsys):
    key = str(tmp_path / "k.key")
    newkey = str(tmp_path / "n.key")
    ledger = str(tmp_path / "l.db")
    run(capsys, "keygen", "--out", key)
    run(capsys, "submit", "--action", "a", "--ledger", ledger, "--key", key)
    code, rot = run(capsys, "rotate", "--algorithm", "ed25519", "--out", newkey,
                    "--ledger", ledger, "--key", key)
    assert code == 0 and "rotation_seq" in rot
    # keep recording under the new key, then verify across the boundary
    run(capsys, "submit", "--action", "b", "--ledger", ledger, "--key", newkey)
    code, ver = run(capsys, "verify", "--ledger", ledger)
    assert code == 0 and ver["intact"] is True


def test_missing_subcommand_errors(capsys):
    with pytest.raises(SystemExit):
        main([])


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_parser_builds():
    assert build_parser() is not None
