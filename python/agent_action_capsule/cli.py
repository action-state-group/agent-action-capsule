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
        open-items) over a set of capsules: a directory of ``*.json`` files, a
        ledger store directory, a JSONL ledger, or one JSON document. A
        ledger's bookkeeping lines are counted, not verified; see
        ``_load_store``.

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
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from . import verify, verify_store
from .canonical import json_digest, loads_bounded

EXIT_OK = 0
EXIT_NOT_OK = 1
EXIT_CANNOT_RUN = 2


# --------------------------------------------------------------------------- IO
def _load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return loads_bounded(fh.read())


#: The lines a capsule ledger may hold that are not Capsules: the ledger's own
#: bookkeeping, as capsule-emit writes it. Values are the names the summary
#: prints.
LEDGER_BOOKKEEPING_KINDS = {
    "checkpoint_stamp": "checkpoint stamp",
    "disclosure_record": "disclosure record",
    "checkpoint_witness_backfill": "witness backfill",
}

#: The exact members each bookkeeping kind carries: (required, optional). A
#: line is bookkeeping only when its members fit one of these, so a Capsule or
#: a padding record cannot be relabelled with ``kind`` to skip its own checks.
_BOOKKEEPING_MEMBERS = {
    "checkpoint_stamp": ({"kind", "v", "capsule_id", "checkpoint"}, {"checkpoint_cose"}),
    "checkpoint_witness_backfill": ({"kind", "v", "capsule_id", "checkpoint_entry_digest", "witness"}, set()),
    "disclosure_record": (
        {
            "kind", "v", "capsule_id", "audience", "selector", "disclosed_capsule_ids",
            "disclosed_fields", "suppressed_fields", "completeness", "timestamp",
        },
        {"signature", "key_id"},
    ),
}

_HEX64 = re.compile(r"[0-9a-f]{64}")
_PADDING_MEMBERS = {"capsule_id", "record_type", "epistemic_type", "store_nonce"}
_SEGMENT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


@dataclasses.dataclass
class _Store:
    """What ``_load_store`` read: the Capsules to verify in ledger order, the
    bookkeeping and padding lines it counted instead, notices (skipped lines),
    and problems that make the run not ok."""

    capsules: list[Any] = dataclasses.field(default_factory=list)
    bookkeeping: Counter = dataclasses.field(default_factory=Counter)
    padding: int = 0
    notices: list[str] = dataclasses.field(default_factory=list)
    problems: list[str] = dataclasses.field(default_factory=list)


class _StoreUnreadable(ValueError):
    """The store's own structure (a ledger store's manifest) is not readable."""


def _padding_problem(record: dict) -> str | None:
    """The Evidence Layer padding rules (vectors/evidence-layer/padding/README.md),
    after removing the local-only ``signature``/``key_id``; None when valid."""
    body = {k: v for k, v in record.items() if k not in ("signature", "key_id")}
    nonce = body.get("store_nonce")
    if not isinstance(nonce, str) or not _HEX64.fullmatch(nonce):
        return "store_nonce is not 64 lowercase hex"
    extra = sorted(set(body) - _PADDING_MEMBERS)
    if extra:
        return f"extra member {extra[0]!r}"
    if body.get("epistemic_type") != "producer_claim":
        return "epistemic_type is not producer_claim"
    if body.get("capsule_id") != json_digest({k: v for k, v in body.items() if k != "capsule_id"}):
        return "capsule_id does not recompute"
    return None


def _bookkeeping_problem(item: dict) -> str | None:
    """Why ``item`` (which has ``kind``) is not one of the bookkeeping lines a
    capsule ledger holds; None when it is one. Checks shape only: the
    checkpoints themselves are ``verify --bundle``'s to verify."""
    kind = item["kind"]
    if not isinstance(kind, str) or kind not in _BOOKKEEPING_MEMBERS:
        return f"kind={kind!r} is not a recognized bookkeeping line"
    required, optional = _BOOKKEEPING_MEMBERS[kind]
    members = set(item)
    if not required <= members or not members <= required | optional:
        return f"kind={kind!r} line does not have that kind's members"
    if type(item["v"]) is not int or item["v"] != 1 or not isinstance(item["capsule_id"], str) or not _HEX64.fullmatch(item["capsule_id"]):
        return f"kind={kind!r} line has a bad v or capsule_id"
    if kind == "checkpoint_witness_backfill":
        body = {"checkpoint_entry_digest": item["checkpoint_entry_digest"], "witness": item["witness"]}
        expected = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if item["capsule_id"] != expected:
            return "witness backfill capsule_id does not recompute"
    return None


def _add(store: _Store, item: Any, where: str) -> None:
    """Sort one ledger item into a Capsule, a bookkeeping line or padding."""
    if isinstance(item, dict) and "kind" in item:
        problem = _bookkeeping_problem(item)
        if problem:
            store.problems.append(f"{where}: {problem}")
        else:
            store.bookkeeping[item["kind"]] += 1
        return
    if isinstance(item, dict) and item.get("record_type") == "padding":
        problem = _padding_problem(item)
        if problem:
            store.problems.append(f"{where}: padding record: {problem}")
        else:
            store.padding += 1
        return
    store.capsules.append(item)


def _add_lines(store: _Store, data: bytes, name: str, *, segment: str | None = None, seen: dict | None = None) -> None:
    """Add a JSONL ledger's lines.

    A flat file (``segment`` None): an unparseable line is skipped with a
    notice, because a writer that crashed mid-line leaves such a fragment in
    place and it was never an entry; a parseable last line counts, newline or
    not, as capsule-emit's flat reader counts it.

    A ledger store segment (``segment`` is ``"active"`` or ``"closed"``): the
    store's index admits complete lines only, so the active segment's
    unterminated last line is skipped before parsing, and any other line that
    does not parse is a problem. ``seen`` maps each ``capsule_id`` to its first
    line's bytes: the index admits one, so a byte-identical later line is noted
    and not verified twice, and any other line under the same id is a problem
    (bytes, not parsed values, so ``true`` and ``1`` never compare equal)."""
    lines = data.split(b"\n")
    for number, raw in enumerate(lines, start=1):
        last = number == len(lines)
        if not raw.strip():
            continue
        where = f"{name} line {number}"
        if segment == "active" and last:
            store.notices.append(f"{where}: unterminated last line of the active segment, skipped")
            continue
        try:
            item = loads_bounded(raw)
        except ValueError:
            if segment is None:
                store.notices.append(f"{where}: {'unterminated last line' if last else 'not JSON'}, skipped")
            else:
                store.problems.append(f"{where}: not JSON")
            continue
        if seen is not None and isinstance(item, dict) and isinstance(item.get("capsule_id"), str):
            first = seen.get(item["capsule_id"])
            if first is not None:
                if first == raw.strip():
                    store.notices.append(f"{where}: repeats capsule_id {item['capsule_id']}, skipped")
                else:
                    store.problems.append(f"{where}: a different line under capsule_id {item['capsule_id']}")
                continue
            seen[item["capsule_id"]] = raw.strip()
        _add(store, item, where)


def _load_ledger_store(root: Path) -> _Store:
    """A ledger store directory (checkpointed-local-log's ``LedgerStore``,
    managed): ``manifest.json`` lists the segments in order, and each mounted
    segment under ``segments/`` is JSONL. Read from the segments, the store's
    source of truth; its SQLite indexes are not opened. An unmounted (archived)
    segment is a problem: the ledger cannot be checked whole without it."""
    manifest_path = root / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        segments = manifest["segments"]
        active = manifest["active_segment"]
        if not isinstance(segments, list) or not all(isinstance(e, dict) for e in segments):
            raise TypeError("segments must be a list of objects")
        names = [entry["name"] for entry in segments]
        if not all(_SEGMENT_NAME.fullmatch(n) for n in names if isinstance(n, str)) or not all(
            isinstance(n, str) for n in names
        ):
            raise TypeError("a segment name is not a plain file name")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise _StoreUnreadable(f"{manifest_path} is not a ledger store manifest: {exc}") from exc
    if not names or len(set(names)) != len(names) or active != names[-1] or not segments[-1].get("mounted", True):
        raise _StoreUnreadable(f"{manifest_path}: segments must be unique, ending with the mounted active segment")
    store = _Store()
    seen: dict = {}
    for entry in segments:
        name = entry["name"]
        if not entry.get("mounted", True):
            store.problems.append(f"segment {name} is archived (unmounted); mount it to verify the ledger")
            continue
        path = root / "segments" / name
        if not path.is_file():
            raise _StoreUnreadable(f"{path}: segment listed in the manifest is missing")
        role = "active" if name == active else "closed"
        _add_lines(store, path.read_bytes(), f"segments/{name}", segment=role, seen=seen)
    return store


def _load_store(path: str) -> _Store:
    """A store is a directory of ``*.json`` capsules, a ledger store directory
    (one holding ``manifest.json``), a single JSON document (a JSON array, a
    ``{"ledger": [...]}`` object or one capsule), or a JSONL ledger."""
    p = Path(path)
    if p.is_dir():
        if (p / "manifest.json").is_file():
            return _load_ledger_store(p)
        store = _Store()
        for f in sorted(p.glob("*.json")):
            _add(store, _load_json(str(f)), f.name)
        return store
    data = p.read_bytes()
    store = _Store()
    if not data.strip():
        return store
    try:
        doc = loads_bounded(data)
    except ValueError:
        _add_lines(store, data, p.name)
        if not (store.capsules or store.bookkeeping or store.padding or store.problems):
            raise _StoreUnreadable(f"{path}: no JSON document and no JSONL line parses") from None
        return store
    if isinstance(doc, dict) and "ledger" in doc:
        if not isinstance(doc["ledger"], list):
            raise _StoreUnreadable(f"{path}: \"ledger\" is not a list")
        items = doc["ledger"]
    elif isinstance(doc, list):
        items = doc
    else:
        items = [doc]
    for number, item in enumerate(items):
        _add(store, item, f"{p.name} item {number}")
    return store


def _store_summary(store: _Store) -> list[str]:
    lines: list[str] = []
    if store.bookkeeping:
        total = sum(store.bookkeeping.values())
        parts = ", ".join(
            f"{n} {LEDGER_BOOKKEEPING_KINDS[k]}{'s' if n != 1 else ''}" for k, n in sorted(store.bookkeeping.items())
        )
        lines.append(f"{total} bookkeeping entr{'ies' if total != 1 else 'y'} not checked ({parts}); only capsules are checked")
    if store.padding:
        lines.append(f"{store.padding} padding record{'s' if store.padding != 1 else ''} checked against the padding rules")
    lines.extend(f"notice: {n}" for n in store.notices)
    lines.extend(f"problem: {n}" for n in store.problems)
    return lines


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
    except (OSError, ValueError) as exc:
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
        loaded = _load_store(args.store)
    except (OSError, ValueError) as exc:
        print(f"error: cannot read store {args.store!r}: {exc}", file=sys.stderr)
        return EXIT_CANNOT_RUN
    store = loaded.capsules
    # The summary goes to stderr under --json, so stdout stays the result document.
    summary_out = sys.stderr if args.as_json else sys.stdout

    if args.capsule:
        # Verify one capsule in the context of the store (chain-aware, check 6).
        try:
            capsule = _load_json(args.capsule)
        except (OSError, ValueError) as exc:
            print(f"error: cannot read capsule {args.capsule!r}: {exc}", file=sys.stderr)
            return EXIT_CANNOT_RUN
        res = verify(capsule, store=store)
        if args.as_json:
            print(json.dumps(_result_to_dict(res), indent=2, default=str))
        else:
            print(f"Class-1 verification of {args.capsule} against store {args.store}:")
            _print_result(res)
        for line in _store_summary(loaded):
            print(line, file=summary_out)
        return EXIT_OK if res.ok and not loaded.problems else EXIT_NOT_OK

    # No focus capsule: verify the whole store (supersedes / concurrent-supersedes).
    results = verify_store(store)
    if args.as_json:
        print(json.dumps([_result_to_dict(r) for r in results], indent=2, default=str))
    else:
        print(f"Store-level verification of {len(results)} capsule(s) in {args.store}:")
        for i, r in enumerate(results):
            _print_result(r, label=str(i))
    for line in _store_summary(loaded):
        print(line, file=summary_out)
    return EXIT_OK if all(r.ok for r in results) and not loaded.problems else EXIT_NOT_OK


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
        if report.authenticated_capsule_id is not None:
            print(f"    capsule_id         : {report.authenticated_capsule_id}")
        for e in report.substrate_errors:
            print(f"    [ERR] {e}")
        print("  payload (Agent Action Capsule, Class-1):")
        if report.payload is None:
            if report.authenticated_capsule_id is not None:
                print("    skipped — registration authenticates Capsule ID, not Capsule JSON")
            else:
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
    v.add_argument("--store", help="verify store-level chain checks over a dir-of-capsules, a ledger store directory or a ledger file")
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
