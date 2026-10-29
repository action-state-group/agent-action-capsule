#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the Evidence Bundle ``composed/v1`` ``controller_binding`` join vectors.

The join basis is defined by ``draft-mih-zhang-agent-disclosure-bundle-02``:
"Controller Binding Records" (the binding record, its signing input and
digest, revocation statements, when a binding applies) and "Joins" (the
``controller_binding`` derivation). A derived agreement under this basis is
always redundant ("Observers and Redundancy").

Every expected result below is written by hand from the draft text. The
script builds the literal objects with the composed generator's records, keys
and block helpers, signs each binding record with both bound keys and each
revocation statement with the revoking key, and records the literal JCS
preimage of every composed digest. Nothing here imports or runs an
implementation of the join.

Each case delivers its binding records in ``controller_bindings`` and its
revocation statements in ``binding_revocations``, beside the containing
Bundle, as the draft says they are delivered.

Cases:

* ``controller-binding-linked``: one binding record over the two responders'
  keys, delivered; the join derives ``agree``, reported redundant.
* ``controller-binding-revoked-unjoined``: the same, with a revocation
  statement by one key holder dated before both root records; the producer
  declared ``unjoined`` and the verifier derives it.
* ``controller-binding-not-derivable``: no binding record delivered.
* ``controller-binding-revoked-declared-agree``: the producer declared
  ``agree`` without the revocation the verifier received: a failed check.
* ``controller-binding-one-key-signs-both``: both entries of ``sigs`` made by
  one key; the record does not apply, so the members are ``unjoined``.
* ``controller-binding-other-keys``: a binding over another pair of keys,
  addressed by its digest; ``unjoined``.
* ``controller-binding-outside-window``: ``not_after`` falls between the two
  root records' times; ``unjoined``.
* ``controller-binding-method-not-implemented``: a ``method`` this revision
  does not define; ``not_derivable``.

Output: ``vectors/bundle/composed-controller-binding/`` (or ``--out DIR``).
``README.md`` is hand-written; when present in the output directory it is
included in ``SHA256SUMS`` but never rewritten. The run is deterministic.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_bundle_composed_vectors as composed  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "bundle" / "composed-controller-binding"
DRAFT = "draft-mih-zhang-agent-disclosure-bundle-02 (Controller Binding Records; Joins)"
KEY_POINTER = "/key_id"

S_BINDING = "composed/v1: Controller Binding Records"
S_JOINS = "composed/v1: Joins"
S_OBSERVERS = "composed/v1: Observers and Redundancy"

ISSUED = "2026-10-01T00:00:00Z"
NOT_AFTER = "2027-10-01T00:00:00Z"
# Before both root records (2026-10-02T12:10:00Z and 12:11:00Z).
REVOKED = "2026-10-02T00:00:00Z"
# Between the two root records' times.
SPLIT = "2026-10-02T12:10:30Z"

A, B = composed.RESPONDER_A, composed.RESPONDER_B
OTHER = composed.RUNTIME


def binding(holders: tuple[composed.Key, composed.Key], *, not_after: str = NOT_AFTER,
            method: str = "dual_signature/0", signers: tuple[composed.Key, composed.Key] | None = None) -> dict:
    """A ``same_controller_asserted`` binding record over the two keys, each
    ``sigs`` entry made by ``signers`` (default: the key it names) over the
    record without ``sigs``."""
    keys = sorted(k.public_hex for k in holders)
    body = {"binding_version": "controller-binding/0", "claim": "same_controller_asserted", "method": method,
            "keys": keys, "issued_at": ISSUED, "not_before": ISSUED, "not_after": not_after,
            "revocation": "revocation_statement/0", "nonce": "ceremony-1"}
    by_hex = {k.public_hex: k for k in holders}
    makers = signers or tuple(by_hex[k] for k in keys)
    data = composed.jcs(body)
    return dict(body, sigs=[{"key_id": key_id, "sig": maker.private.sign(data).hex()}
                            for key_id, maker in zip(keys, makers)])


def binding_digest(record: dict) -> str:
    return composed.sha256_hex(composed.jcs({k: v for k, v in record.items() if k != "sigs"}))


def revocation(record: dict, by: composed.Key, revoked_at: str) -> dict:
    body = {"revocation_version": "controller-binding-revocation/0", "binding": binding_digest(record),
            "key_id": by.public_hex, "revoked_at": revoked_at}
    return dict(body, sig=by.private.sign(composed.jcs(body)).hex())


def cb_join(record: dict, state: str) -> dict:
    return {
        "members": ["responder-a", "responder-b"],
        "basis": "controller_binding",
        "pointer": KEY_POINTER,
        "identifier_digest": binding_digest(record),
        "compare": [composed.COMPARE_POINTER],
        "state": state,
    }


MEMBERS_EXPECT = {
    member: {"outcome": "artifact", "body": "carried", "digest": "reproduced",
             "claims": composed.MEMBER_CLAIMS_DEPTH0}
    for member in ("responder-a", "responder-b")
}
PAIR = ["responder-a", "responder-b"]
REDUNDANT = {"members": PAIR, "result": "redundant", "reason": "controller_binding",
             "report": "redundant, not corroborating"}
NOT_APPLICABLE = {"members": PAIR, "result": "not_applicable"}


def case(case_id: str, description: str, record: dict, *, declared: str, derived: str | None, status: str,
         corroboration: dict, bindings: list[dict], revocations: list[dict] | None = None) -> dict:
    members, observers = composed.two_responders()
    comp = composed.block(members, observers, [cb_join(record, declared)])
    digest, preimage = composed.composed_digest(comp)
    result = ("not_derivable" if derived is None else
              "derived_matches" if derived == declared else "join_state_mismatch")
    return {
        "id": case_id,
        "section": [S_BINDING, S_JOINS, S_OBSERVERS],
        "description": description,
        "container": composed.container(comp),
        "controller_bindings": bindings,
        "binding_revocations": revocations or [],
        "expect": {
            "composed_digest": digest,
            "canonical_preimage": preimage,
            "status": status,
            "members": copy.deepcopy(MEMBERS_EXPECT),
            "composition_closure": {"status": "pass", "missing": []},
            "joins": [{"members": PAIR, "declared": declared, "derived": derived, "result": result}],
            "corroboration": [corroboration],
        },
    }


def cases() -> list[dict]:
    record = binding((A, B))
    revoked = revocation(record, B, REVOKED)
    other = binding((A, OTHER))
    one_key = binding((A, B), signers=(A, A))
    short = binding((A, B), not_after=SPLIT)
    unknown = binding((A, B), method="x-example-method/0")
    return [
        case("controller-binding-linked",
             "The two responders' keys are bound by a same_controller_asserted record both keys signed, in effect "
             "at both root records' times and not revoked. The pointer selects each root record's key_id, the two "
             "are the record's keys, so the members are linked; the compare pointer agrees. The observers are in "
             "separate custody domains, yet the agreement is redundant: the key holders stated their keys are not "
             "independent issuers.",
             record, declared="agree", derived="agree", status="pass", corroboration=REDUNDANT, bindings=[record]),
        case("controller-binding-revoked-unjoined",
             "The linked case, with responder-b's key holder's revocation statement dated before both root "
             "records. The binding does not apply, so the members are not linked: unjoined, as declared.",
             record, declared="unjoined", derived="unjoined", status="pass", corroboration=NOT_APPLICABLE,
             bindings=[record], revocations=[revoked]),
        case("controller-binding-not-derivable",
             "The linked declaration with no binding record delivered: the verifier cannot derive the join. It "
             "reports not_derivable, never an agreement and never corroboration.",
             record, declared="agree", derived=None, status="withheld", corroboration=NOT_APPLICABLE, bindings=[]),
        case("controller-binding-revoked-declared-agree",
             "The producer declared agree; the verifier received a revocation the producer did not account for and "
             "derives unjoined. The declared state does not match the derived one: a failed check.",
             record, declared="agree", derived="unjoined", status="fail", corroboration=NOT_APPLICABLE,
             bindings=[record], revocations=[revoked]),
        case("controller-binding-one-key-signs-both",
             "Both sigs entries are made by responder-a's key, the second under responder-b's key_id. One key "
             "cannot bind another to itself: the binding does not apply and the members are unjoined.",
             one_key, declared="unjoined", derived="unjoined", status="pass", corroboration=NOT_APPLICABLE,
             bindings=[one_key]),
        case("controller-binding-other-keys",
             "A valid binding over responder-a's key and another key, addressed by its digest. The two values the "
             "pointer selects are not the record's keys: unjoined.",
             other, declared="unjoined", derived="unjoined", status="pass", corroboration=NOT_APPLICABLE,
             bindings=[other]),
        case("controller-binding-outside-window",
             "The binding's not_after falls between responder-a's root record time and responder-b's. It must be "
             "in effect at both: unjoined.",
             short, declared="unjoined", derived="unjoined", status="pass", corroboration=NOT_APPLICABLE,
             bindings=[short]),
        case("controller-binding-method-not-implemented",
             "A binding record whose method this revision does not define. A verifier that does not implement the "
             "method cannot check its signatures, so it cannot derive the join: not_derivable.",
             unknown, declared="agree", derived=None, status="withheld", corroboration=NOT_APPLICABLE,
             bindings=[unknown]),
    ]


def build() -> dict[str, bytes]:
    case_list = cases()
    files = {
        "vectors.json": composed._dump({
            "draft": DRAFT,
            "provenance": "spec-derived",
            "status": "draft -02 text; held for ratification with -02",
            "kind": composed.KIND,
            "inputs": "controller_bindings and binding_revocations are delivered beside the containing Bundle; "
                      "they are not part of it and the composed digest binds a binding only through a join's "
                      "identifier_digest.",
            "keys": {k.name: {"seed_hex": k.seed.hex(), "public_key_hex": k.public_hex} for k in (A, B, OTHER)},
            "count": len(case_list),
            "cases": case_list,
        }),
    }
    files["manifest.json"] = composed._dump({
        "draft": DRAFT,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_bundle_composed_cb_vectors.py",
        "files": [{"path": name, "sha256": composed.sha256_hex(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    lines = [f"{composed.sha256_hex(p.read_bytes())}  {p.name}"
             for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
