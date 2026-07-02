"""agentledger command line.

    agentledger keygen --algorithm ed25519 --out agent.key
    agentledger submit  --action deploy --actor alice --param env=prod \
                        --ledger l.db --key agent.key
    agentledger outcome --ref 1 --actor agent:deployer --status success --ledger l.db --key agent.key
    agentledger rotate  --algorithm hybrid --out new.key --ledger l.db --key agent.key
    agentledger verify  --ledger l.db [--key agent.key] [--strict]
    agentledger export  --ledger l.db --out bundle.json [--key agent.key]
    agentledger verify-bundle bundle.json [--secret <hex>]
    agentledger query   --ledger l.db [--kind directive --denied --summary ...]
    agentledger prove   --ledger l.db --seq 3 --out proof.json
    agentledger verify-proof proof.json [--root <hex>]
    agentledger seal    --ledger l.db --key agent.key --keep-last 1000 \
                        --archive archive.json --checkpoint cp.json
    agentledger verify-checkpoint cp.json [--secret <hex>]
    agentledger export-format --ledger l.db --format sarif --out out.sarif

Asymmetric ledgers (ed25519 / ml-dsa / hybrid) verify with no key, since each
entry carries its public key. HMAC ledgers need --key (the shared secret).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import __version__, exporters
from .evidence import verify_bundle
from .merkle import InclusionProof, MerkleTree, verify_proof
from .policy import PolicyGate
from .query import Query
from .recorder import Recorder
from .retention import Checkpoint, RetentionPolicy, seal_segment, verify_checkpoint
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


def cmd_approve(args) -> int:
    rec = _recorder(args)
    approver_signer = load_key(args.approver_key)
    entry = rec.approve(args.ref, args.approver, approver_signer)
    _print({"seq": entry.seq, "ref": args.ref, "approver": args.approver,
            "approver_key": approver_signer.public_bytes().hex()})
    return 0


def cmd_approvals(args) -> int:
    rec = _recorder(args)
    allowed = set(args.allowed_key) if args.allowed_key else None
    status = rec.approval_status(args.ref, args.threshold, allowed_keys=allowed)
    _print(status.as_dict())
    return 0 if status.satisfied else 1


def cmd_verify(args) -> int:
    rec = _recorder(args)
    ok, broken = rec.verify()
    entries = rec.entries()
    result = {"intact": ok, "first_broken_seq": broken, "entries": len(entries)}
    # --strict: a CI gate. The chain must be intact AND there must be no denied
    # directive on record. This turns the ledger into a fail-the-build signal:
    # any tamper OR any policy violation exits non-zero.
    if getattr(args, "strict", False):
        denied = [e.seq for e in entries
                  if e.kind == "directive" and e.decision.get("allowed") is False]
        result["strict"] = True
        result["denied_directives"] = denied
        result["passed"] = ok and not denied
        _print(result)
        return 0 if (ok and not denied) else 1
    _print(result)
    return 0 if ok else 1


def cmd_query(args) -> int:
    rec = _recorder(args)
    q = Query(rec.ledger)
    if args.kind:
        q = q.kind(*args.kind)
    if args.actor:
        q = q.actor(*args.actor)
    if args.action:
        q = q.action(*args.action)
    if args.ref is not None:
        q = q.refers_to(args.ref)
    if args.since is not None:
        q = q.since(args.since)
    if args.until is not None:
        q = q.until(args.until)
    if args.allowed:
        q = q.allowed()
    if args.denied:
        q = q.denied()
    if args.rule:
        q = q.rule(*args.rule)
    q = q.order_by_ts()
    if args.limit is not None:
        q = q.limit(args.limit)
    if args.summary:
        _print(q.summary())
    else:
        _print([{"seq": e.seq, "ts": e.ts, "kind": e.kind, "actor": e.actor,
                 "action": e.action, "allowed": e.decision.get("allowed"),
                 "rule": e.decision.get("rule"), "ref": e.ref,
                 "entry_hash": e.entry_hash} for e in q])
    return 0


def cmd_prove(args) -> int:
    rec = _recorder(args)
    tree = MerkleTree.from_ledger(rec.ledger)
    proof = tree.prove(args.seq)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(proof.as_dict(), fh, indent=2)
    _print({"seq": proof.seq, "root": proof.root, "tree_size": proof.tree_size,
            "proof_steps": len(proof.steps),
            "out": args.out if args.out else None})
    return 0


def cmd_verify_proof(args) -> int:
    with open(args.proof, "r", encoding="utf-8") as fh:
        proof = InclusionProof.from_dict(json.load(fh))
    ok = verify_proof(proof, expected_root=args.root)
    _print({"included": ok, "seq": proof.seq,
            "root": args.root or proof.root, "tree_size": proof.tree_size})
    return 0 if ok else 1


def cmd_seal(args) -> int:
    rec = _recorder(args)
    if args.keep_last is not None:
        policy = RetentionPolicy(keep_last=args.keep_last)
    elif args.max_age is not None:
        policy = RetentionPolicy(max_age_seconds=args.max_age)
    else:
        raise SystemExit("seal requires --keep-last or --max-age")
    result = seal_segment(rec.ledger, rec.signer, policy, archive_path=args.archive)
    if result is None:
        _print({"sealed": 0, "note": "nothing eligible under this policy"})
        return 0
    cp = result.checkpoint
    if args.checkpoint:
        with open(args.checkpoint, "w", encoding="utf-8") as fh:
            json.dump(cp.as_dict(), fh, indent=2)
    _print({"sealed": cp.entry_count,
            "segment": [cp.segment_start_seq, cp.segment_end_seq],
            "archived_head_hash": cp.archived_head_hash,
            "merkle_root": cp.merkle_root,
            "archive": args.archive, "checkpoint": args.checkpoint})
    return 0


def cmd_verify_checkpoint(args) -> int:
    with open(args.checkpoint, "r", encoding="utf-8") as fh:
        cp = Checkpoint.from_dict(json.load(fh))
    secret = bytes.fromhex(args.secret) if args.secret else None
    ok = verify_checkpoint(cp, secret=secret)
    _print({"valid": ok, "segment": [cp.segment_start_seq, cp.segment_end_seq],
            "entry_count": cp.entry_count, "merkle_root": cp.merkle_root})
    return 0 if ok else 1


def cmd_export_format(args) -> int:
    rec = _recorder(args)
    fmt = args.format
    if fmt == "jsonl":
        exporters.to_jsonl(rec.entries(), args.out)
    elif fmt == "csv":
        exporters.to_csv(rec.entries(), args.out)
    elif fmt == "sarif":
        exporters.to_sarif(rec.entries(), args.out, tool_version=__version__)
    elif fmt == "otel":
        exporters.to_otel_spans(rec.entries(), args.out)
    elif fmt == "html":
        exporters.to_html_report(rec.entries(), rec.signer, args.out)
    else:  # pragma: no cover - argparse choices guard this
        raise SystemExit(f"unknown format {fmt}")
    _print({"format": fmt, "out": args.out, "entries": len(rec.entries())})
    return 0


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

    pa = sub.add_parser("approve", help="record one operator's approval of a directive")
    pa.add_argument("--ref", type=int, required=True, help="directive seq to approve")
    pa.add_argument("--approver", required=True)
    pa.add_argument("--approver-key", dest="approver_key", required=True,
                    help="the approver's own key file")
    pa.add_argument("--ledger", required=True)
    pa.add_argument("--key", required=True, help="ledger signing key")
    pa.set_defaults(func=cmd_approve)

    pas = sub.add_parser("approvals", help="check m-of-n approval status of a directive")
    pas.add_argument("--ref", type=int, required=True)
    pas.add_argument("--threshold", type=int, required=True)
    pas.add_argument("--allowed-key", dest="allowed_key", action="append",
                     help="restrict to these approver public keys (hex, repeatable)")
    pas.add_argument("--ledger", required=True)
    pas.add_argument("--key", default=None)
    pas.set_defaults(func=cmd_approvals)

    pv = sub.add_parser("verify", help="verify the ledger (chain + signatures + continuity)")
    pv.add_argument("--ledger", required=True)
    pv.add_argument("--key", default=None)
    pv.add_argument("--strict", action="store_true",
                    help="CI gate: also fail if any denied directive is on record")
    pv.set_defaults(func=cmd_verify)

    pq = sub.add_parser("query", help="filter/summarize ledger entries (read-only)")
    pq.add_argument("--ledger", required=True)
    pq.add_argument("--key", default=None)
    pq.add_argument("--kind", action="append", help="directive|outcome|approval|key_rotation (repeatable)")
    pq.add_argument("--actor", action="append")
    pq.add_argument("--action", action="append")
    pq.add_argument("--ref", type=int, default=None, help="entries referencing this seq")
    pq.add_argument("--since", type=float, default=None, help="unix ts lower bound")
    pq.add_argument("--until", type=float, default=None, help="unix ts upper bound")
    pq.add_argument("--allowed", action="store_true")
    pq.add_argument("--denied", action="store_true")
    pq.add_argument("--rule", action="append", help="policy rule name (repeatable)")
    pq.add_argument("--limit", type=int, default=None)
    pq.add_argument("--summary", action="store_true", help="print an aggregate instead of rows")
    pq.set_defaults(func=cmd_query)

    pp = sub.add_parser("prove", help="build a Merkle inclusion proof for one entry")
    pp.add_argument("--ledger", required=True)
    pp.add_argument("--key", default=None)
    pp.add_argument("--seq", type=int, required=True)
    pp.add_argument("--out", default=None, help="write the proof JSON here")
    pp.set_defaults(func=cmd_prove)

    pvp = sub.add_parser("verify-proof", help="verify a Merkle inclusion proof")
    pvp.add_argument("proof", help="proof JSON file")
    pvp.add_argument("--root", default=None, help="expected root (hex); else use the proof's own")
    pvp.set_defaults(func=cmd_verify_proof)

    psl = sub.add_parser("seal", help="seal an eligible prefix into a signed archive + checkpoint")
    psl.add_argument("--ledger", required=True)
    psl.add_argument("--key", required=True)
    psl.add_argument("--keep-last", dest="keep_last", type=int, default=None,
                     help="keep the newest N live, seal the rest")
    psl.add_argument("--max-age", dest="max_age", type=float, default=None,
                     help="seal entries older than this many seconds")
    psl.add_argument("--archive", default=None, help="write the evidence bundle here")
    psl.add_argument("--checkpoint", default=None, help="write the signed checkpoint here")
    psl.set_defaults(func=cmd_seal)

    pvc = sub.add_parser("verify-checkpoint", help="verify a sealed-segment checkpoint")
    pvc.add_argument("checkpoint", help="checkpoint JSON file")
    pvc.add_argument("--secret", default=None, help="hex HMAC secret (HMAC checkpoints only)")
    pvc.set_defaults(func=cmd_verify_checkpoint)

    pef = sub.add_parser("export-format", help="export to sarif|otel|csv|jsonl|html")
    pef.add_argument("--ledger", required=True)
    pef.add_argument("--key", default=None)
    pef.add_argument("--format", required=True,
                     choices=["jsonl", "csv", "sarif", "otel", "html"])
    pef.add_argument("--out", required=True)
    pef.set_defaults(func=cmd_export_format)

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
