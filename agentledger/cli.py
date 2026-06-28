"""agentledger command line.

    agentledger keygen --algorithm ed25519 --out agent.key
    agentledger submit  --action deploy --actor alice --param env=prod \
                        --ledger l.db --key agent.key
    agentledger outcome --ref 1 --actor agent:deployer --status success --ledger l.db --key agent.key
    agentledger rotate  --algorithm hybrid --out new.key --ledger l.db --key agent.key
    agentledger verify  --ledger l.db [--key agent.key]
    agentledger export  --ledger l.db --out bundle.json [--key agent.key]
    agentledger verify-bundle bundle.json [--secret <hex>]

Asymmetric ledgers (ed25519 / ml-dsa / hybrid) verify with no key, since each
entry carries its public key. HMAC ledgers need --key (the shared secret).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import __version__
from .evidence import verify_bundle
from .policy import PolicyGate
from .recorder import Recorder
from .signing import load_key, new_signer, save_key


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _parse_params(pairs) -> dict:
    out: dict = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise SystemExit(f"bad --param {pair!r}; expected key=value")
        k, v = pair.split("=", 1)
        if v.lower() in ("true", "false"):
            out[k] = v.lower() == "true"
        else:
            try:
                out[k] = int(v)
            except ValueError:
                out[k] = v
    return out


def _signer(args):
    return load_key(args.key) if getattr(args, "key", None) else new_signer("ed25519")


def _recorder(args) -> Recorder:
    return Recorder(gate=PolicyGate(default_allow=True), signer=_signer(args),
                    db_path=args.ledger)


def cmd_keygen(args) -> int:
    signer = new_signer(args.algorithm)
    save_key(signer, args.out)
    _print({"algorithm": signer.algorithm, "out": args.out,
            "public_key": signer.public_bytes().hex(),
            "third_party_verifiable": signer.third_party_verifiable})
    return 0


def cmd_submit(args) -> int:
    rec = _recorder(args)
    decision, entry = rec.submit(args.actor, args.action, _parse_params(args.param))
    _print({"seq": entry.seq, "allowed": decision.allowed, "rule": decision.rule,
            "algorithm": entry.algorithm, "entry_hash": entry.entry_hash})
    return 0 if decision.allowed else 2


def cmd_outcome(args) -> int:
    rec = _recorder(args)
    entry = rec.record_outcome(args.ref, args.actor, args.status, _parse_params(args.param))
    _print({"seq": entry.seq, "ref": entry.ref, "status": args.status})
    return 0


def cmd_rotate(args) -> int:
    rec = _recorder(args)
    new = new_signer(args.algorithm)
    entry = rec.rotate_key(new)
    save_key(new, args.out)
    _print({"rotated_to": new.algorithm, "out": args.out,
            "rotation_seq": entry.seq, "new_public_key": new.public_bytes().hex()})
    return 0


def cmd_verify(args) -> int:
    rec = _recorder(args)
    ok, broken = rec.verify()
    _print({"intact": ok, "first_broken_seq": broken, "entries": len(rec.entries())})
    return 0 if ok else 1


def cmd_export(args) -> int:
    rec = _recorder(args)
    bundle = rec.export_evidence(args.out)
    _print({"exported": args.out, "entries": bundle["entry_count"],
            "algorithm": bundle["algorithm"], "head_hash": bundle["head_hash"]})
    return 0


def cmd_verify_bundle(args) -> int:
    with open(args.bundle, "r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    secret = bytes.fromhex(args.secret) if args.secret else None
    ok, broken = verify_bundle(bundle, secret=secret)
    _print({"intact": ok, "first_broken_seq": broken,
            "algorithm": bundle.get("algorithm")})
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentledger", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"agentledger {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("keygen", help="generate and save a signing key")
    pk.add_argument("--algorithm", default="ed25519",
                    choices=["ed25519", "ml-dsa", "hybrid", "hmac"])
    pk.add_argument("--out", required=True)
    pk.set_defaults(func=cmd_keygen)

    ps = sub.add_parser("submit", help="evaluate + record a directive (signed)")
    ps.add_argument("--action", required=True)
    ps.add_argument("--actor", default="unknown")
    ps.add_argument("--param", action="append")
    ps.add_argument("--ledger", required=True)
    ps.add_argument("--key", required=True)
    ps.set_defaults(func=cmd_submit)

    po = sub.add_parser("outcome", help="record an outcome for a directive")
    po.add_argument("--ref", type=int, required=True)
    po.add_argument("--actor", default="agent")
    po.add_argument("--status", required=True)
    po.add_argument("--param", action="append")
    po.add_argument("--ledger", required=True)
    po.add_argument("--key", required=True)
    po.set_defaults(func=cmd_outcome)

    pr = sub.add_parser("rotate", help="rotate the signing key (with continuity proof)")
    pr.add_argument("--algorithm", default="ed25519",
                    choices=["ed25519", "ml-dsa", "hybrid", "hmac"])
    pr.add_argument("--out", required=True)
    pr.add_argument("--ledger", required=True)
    pr.add_argument("--key", required=True)
    pr.set_defaults(func=cmd_rotate)

    pv = sub.add_parser("verify", help="verify the ledger (chain + signatures + continuity)")
    pv.add_argument("--ledger", required=True)
    pv.add_argument("--key", default=None)
    pv.set_defaults(func=cmd_verify)

    pe = sub.add_parser("export", help="export an offline-verifiable evidence bundle")
    pe.add_argument("--ledger", required=True)
    pe.add_argument("--out", required=True)
    pe.add_argument("--key", default=None)
    pe.set_defaults(func=cmd_export)

    pb = sub.add_parser("verify-bundle", help="verify an exported evidence bundle")
    pb.add_argument("bundle")
    pb.add_argument("--secret", default=None, help="hex HMAC secret (HMAC bundles only)")
    pb.set_defaults(func=cmd_verify_bundle)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
