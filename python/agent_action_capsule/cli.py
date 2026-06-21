# SPDX-License-Identifier: BSD-3-Clause
"""Command-line front door for the Agent Action Capsule reference verifier.

Thin wrapper over the library: argument parsing -> ``verify`` / ``verify_store``
-> formatted output. It does **not** reimplement verification.

    agent-action-capsule verify <capsule.json>
        Class-1 payload verification (spec §6). Prints ok, each finding with its
        §6 check number / severity / detail, the derived modes, and the
        recomputed capsule_id. ``--json`` for the raw VerificationResult.

    agent-action-capsule verify --store <dir-or-file> [<capsule.json>]
        Store-level chain checks (supersedes / concurrent-supersedes /
        open-items) over a set of capsules.

    agent-action-capsule verify --transparent <signed-statement> --issuer-key <pem> \\
            [--log-key <pem> --leaf-entry-hex <hex>]
        Two-layer verification: the SCITT/COSE *substrate* layer (signature +
        optional receipt) via the optional ``scitt-cose`` package, then the
        *payload* layer (Class-1) on the authenticated capsule. The substrate
        layer reports ``anchored`` ONLY when a receipt actually verifies.

    agent-action-capsule anchor submit <capsule_id> [--ts-url URL] [--timeout SEC]
        Submit a capsule_id digest to a SCITT Transparency Service (digest-only
        POST; no business content crosses the wire). Returns a Transparent Statement
        with an embedded COSE Receipt. Requires the ``[anchor]`` extra.

Exit codes: 0 = ok; 1 = ran and NOT ok; 2 = could not run (bad input, missing
key, optional dependency not installed). Never a bare traceback.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

from . import verify, verify_store

EXIT_OK = 0
EXIT_NOT_OK = 1
EXIT_CANNOT_RUN = 2


# --------------------------------------------------------------------------- IO
def _load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _load_store(path: str) -> list[Any]:
    """A store is a directory of ``*.json`` capsules, a JSONL ledger, or a
    single file holding a JSON array or a ``{"ledger": [...]}`` object."""
    p = Path(path)
    if p.is_dir():
        return [_load_json(str(f)) for f in sorted(p.glob("*.json"))]
    # Try JSONL first: if the file has multiple lines that each parse as JSON
    # objects, treat it as a newline-delimited capsule ledger.
    with open(path, encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh if ln.strip()]
    if len(lines) == 0:
        return []
    if len(lines) >= 2:
        try:
            return [json.loads(ln) for ln in lines]
        except json.JSONDecodeError:
            pass  # not valid JSONL; fall through to single-doc parse
    try:
        doc = json.loads(lines[0])
    except json.JSONDecodeError:
        doc = _load_json(path)
    if isinstance(doc, dict) and "ledger" in doc:
        return list(doc["ledger"])
    if isinstance(doc, list):
        return doc
    return [doc]


# ----------------------------------------------------------------- formatting
def _result_to_dict(res) -> dict:
    return {
        "ok": res.ok,
        "derived": res.assurance,
        "capsule_id_recomputed": res.capsule_id,
        "findings": [dataclasses.asdict(f) for f in res.findings],
    }


def _print_result(res, *, label: str | None = None) -> None:
    head = f"  [{label}] " if label else "  "
    print(f"{head}ok: {res.ok}")
    if res.capsule_id:
        print(f"  capsule_id (recomputed): {res.capsule_id}")
    d = res.assurance or {}
    if d:
        print(
            f"  derived: effect_mode={d.get('effect_mode')} "
            f"attestation_mode={d.get('attestation_mode')} "
            f"ledger_mode={d.get('ledger_mode')}"
        )
    if not res.findings:
        print("  findings: none")
    else:
        print("  findings:")
        for f in res.findings:
            chk = f"check {f.check}" if f.check is not None else "check -"
            print(f"    - [{f.severity}] ({chk}) {f.code}: {f.detail}")


# ------------------------------------------------------------------- handlers
def _cmd_payload(args) -> int:
    try:
        capsule = _load_json(args.capsule)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read capsule {args.capsule!r}: {exc}", file=sys.stderr)
        return EXIT_CANNOT_RUN
    res = verify(capsule)  # never raises
    if args.as_json:
        print(json.dumps(_result_to_dict(res), indent=2, default=str))
    else:
        print(f"Agent Action Capsule — Class-1 payload verification: {args.capsule}")
        _print_result(res)
    return EXIT_OK if res.ok else EXIT_NOT_OK


def _cmd_store(args) -> int:
    try:
        store = _load_store(args.store)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read store {args.store!r}: {exc}", file=sys.stderr)
        return EXIT_CANNOT_RUN

    if args.capsule:
        # Verify one capsule in the context of the store (chain-aware, check 6).
        try:
            capsule = _load_json(args.capsule)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read capsule {args.capsule!r}: {exc}", file=sys.stderr)
            return EXIT_CANNOT_RUN
        res = verify(capsule, store=store)
        if args.as_json:
            print(json.dumps(_result_to_dict(res), indent=2, default=str))
        else:
            print(f"Class-1 verification of {args.capsule} against store {args.store}:")
            _print_result(res)
        return EXIT_OK if res.ok else EXIT_NOT_OK

    # No focus capsule: verify the whole store (supersedes / concurrent-supersedes).
    results = verify_store(store)
    if args.as_json:
        print(json.dumps([_result_to_dict(r) for r in results], indent=2, default=str))
    else:
        print(f"Store-level verification of {len(results)} capsule(s) in {args.store}:")
        for i, r in enumerate(results):
            _print_result(r, label=str(i))
    return EXIT_OK if all(r.ok for r in results) else EXIT_NOT_OK


def _cmd_transparent(args) -> int:
    # Optional extra: the SCITT/COSE substrate verifier. Never a traceback when
    # absent — a clear, actionable message instead.
    try:
        from . import transparent as _t
    except ImportError as exc:  # pragma: no cover - exercised via subprocess test
        print(
            "error: --transparent needs the optional substrate verifier.\n"
            "       install it with:  pip install 'agent-action-capsule[transparent]'\n"
            f"       (import error: {exc})",
            file=sys.stderr,
        )
        return EXIT_CANNOT_RUN

    if not args.issuer_key:
        print(
            "error: --transparent requires --issuer-key <pem> to verify the "
            "COSE_Sign1 signature and obtain the authenticated payload.",
            file=sys.stderr,
        )
        return EXIT_CANNOT_RUN

    try:
        report = _t.verify_transparent(
            statement_path=args.capsule,
            issuer_key_path=args.issuer_key,
            log_key_path=args.log_key,
            leaf_entry_hex=args.leaf_entry_hex,
        )
    except (OSError, _t.SubstrateInputError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CANNOT_RUN

    if args.as_json:
        out = dict(report.__dict__)
        if report.payload is not None:
            out["payload"] = _result_to_dict(report.payload)
        print(json.dumps(out, indent=2, default=str))
    else:
        print(f"Two-layer verification of Signed Statement: {args.capsule}")
        print("  substrate (SCITT/COSE, via scitt-cose):")
        print(f"    signature_verified : {report.signature_verified}")
        print(f"    receipt_verified   : {report.receipt_verified}")
        print(f"    attestation_tier   : {report.attestation_tier}")
        for e in report.substrate_errors:
            print(f"    [ERR] {e}")
        print("  payload (Agent Action Capsule, Class-1):")
        if report.payload is None:
            print("    skipped — substrate did not authenticate the payload")
        else:
            _print_result(report.payload)
    return EXIT_OK if report.ok else EXIT_NOT_OK


# ---------------------------------------------------------------- anchor handler
def _cmd_anchor_submit(args) -> int:
    try:
        from .anchor import AnchorError, AnchorResult, submit_anchor
    except ImportError as exc:  # pragma: no cover
        print(
            "error: anchor submit needs the optional anchor client.\n"
            "       install it with:  pip install 'agent-action-capsule[anchor]'\n"
            f"       (import error: {exc})",
            file=sys.stderr,
        )
        return EXIT_CANNOT_RUN

    capsule_id: str = args.capsule_id.strip()
    if len(capsule_id) != 64 or not all(c in "0123456789abcdef" for c in capsule_id):
        print(
            f"error: capsule_id must be a 64-character lowercase hex string, got {capsule_id!r}",
            file=sys.stderr,
        )
        return EXIT_CANNOT_RUN

    try:
        result = submit_anchor(capsule_id, ts_url=args.ts_url, timeout=args.timeout)
    except Exception as exc:
        if args.as_json:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            print(f"error: anchor submit failed: {exc}", file=sys.stderr)
        return EXIT_NOT_OK

    if isinstance(result, AnchorError):
        if args.as_json:
            print(json.dumps({"ok": False, "error": result.error, "ts_url": result.ts_url}, indent=2))
        else:
            print(f"error: anchor submit failed: {result.error}", file=sys.stderr)
        return EXIT_NOT_OK

    assert isinstance(result, AnchorResult)
    if args.as_json:
        print(
            json.dumps(
                {
                    "ok": True,
                    "capsule_id": result.capsule_id,
                    "ts_url": result.ts_url,
                    "entry_hash": result.entry_hash,
                    "receipt_size": len(result.receipt),
                    "transparent_size": len(result.transparent_statement),
                },
                indent=2,
            )
        )
    else:
        print("Agent Action Capsule — anchor submit")
        print(f"  capsule_id  : {result.capsule_id}")
        print(f"  ts_url      : {result.ts_url}")
        print(f"  entry_hash  : {result.entry_hash}")
        print(f"  receipt     : {len(result.receipt)} bytes")
        print(f"  transparent : {len(result.transparent_statement)} bytes")
    return EXIT_OK


# ---------------------------------------------------------------------- parser
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-action-capsule",
        description="Reference verifier for the Agent Action Capsule SCITT profile.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verify", help="verify a capsule, a store, or a Signed Statement")
    v.add_argument("capsule", nargs="?", help="path to a capsule JSON (or a Signed Statement with --transparent)")
    v.add_argument("--store", help="verify store-level chain checks over a dir-of-capsules or a ledger file")
    v.add_argument("--transparent", action="store_true", help="input is a SCITT Signed Statement; verify substrate + payload")
    v.add_argument("--issuer-key", dest="issuer_key", help="PEM public key of the statement issuer (required with --transparent)")
    v.add_argument("--log-key", dest="log_key", help="PEM public key of the transparency log (to verify a receipt)")
    v.add_argument("--leaf-entry-hex", dest="leaf_entry_hex", help="hex leaf entry the receipt proves inclusion of")
    v.add_argument("--json", dest="as_json", action="store_true", help="machine-readable JSON output")

    a = sub.add_parser("anchor", help="submit a capsule_id digest to a SCITT Transparency Service")
    a_sub = a.add_subparsers(dest="anchor_cmd", required=True)
    a_s = a_sub.add_parser("submit", help="post capsule_id to a TS; receive a COSE Receipt")
    a_s.add_argument("capsule_id", help="64-char lowercase-hex capsule_id to anchor")
    a_s.add_argument("--ts-url", dest="ts_url", default=None, help="TS base URL (default: AAC_ANCHOR_URL env var)")
    a_s.add_argument("--timeout", type=float, default=30.0, help="per-request HTTP timeout in seconds (default: 30)")
    a_s.add_argument("--json", dest="as_json", action="store_true", help="machine-readable JSON output")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "verify":
        if args.transparent:
            if not args.capsule:
                parser.error("verify --transparent requires a Signed Statement path")
            return _cmd_transparent(args)
        if args.store:
            return _cmd_store(args)
        if not args.capsule:
            parser.error("verify requires a capsule path (or --store, or --transparent)")
        return _cmd_payload(args)
    if args.command == "anchor":
        if args.anchor_cmd == "submit":
            return _cmd_anchor_submit(args)
    parser.error(f"unknown command {args.command!r}")
    return EXIT_CANNOT_RUN  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
