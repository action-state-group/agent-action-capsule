#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the Evidence Bundle ``composed/v1`` key-source vectors (#663).

``draft-mih-zhang-agent-disclosure-bundle-03`` "Joins": under
``controller_binding`` and ``same_key`` a member Bundle's key comes from its
root record's verified producer signature (``record_signature``) or, for a
root record that carries neither ``signature`` nor ``key_id``, from the key
that signed the Bundle's checkpoint, when the record's identity and its own
membership under that checkpoint hold (``log_checkpoint``), with T that
checkpoint's ``timestamp``. A present signature that fails never falls back.
Under ``controller_binding`` a ``pointer``, when present, must select the key
so determined. Every such join reports each side's key source.

Every expected join result is written by hand from the draft text. The
member Bundles' own completeness claims are those the Bundle rules give for
each edited Bundle (each stated in the case). Nothing here imports or runs an
implementation of the join.

The composition is the two responders' halves of one exchange
(``responder-a``, ``responder-b``), each its responder's whole log with a
signed checkpoint, joined by ``controller_binding`` on a binding over the two
keys, as in ``vectors/bundle/composed-controller-binding/``; responder-a's
root record is unsigned unless the case says otherwise. A join over an
unsigned root carries no ``pointer`` (an unsigned record has no ``key_id`` to
select), as -03 composers SHOULD omit it; ``key-source-pointer-selects-other-key``
shows a pointer that selects another value.

Output: ``vectors/bundle/composed-key-source/`` (or ``--out DIR``).
``README.md`` is hand-written; when present in the output directory it is
included in ``SHA256SUMS`` but never rewritten. The run is deterministic.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_bundle_composed_cb_vectors as cbv  # noqa: E402
import generate_bundle_composed_history_vectors as hv  # noqa: E402
import generate_bundle_composed_vectors as composed  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "bundle" / "composed-key-source"
DRAFT = "draft-mih-zhang-agent-disclosure-bundle-03 (Joins: key sources)"
S_JOINS = "composed/v1: Joins"
S_BINDING = "composed/v1: Controller Binding Records"
S_CLAIMS = "Completeness Claims and Log Membership"

A, B = composed.RESPONDER_A, composed.RESPONDER_B
PAIR = ["responder-a", "responder-b"]
RECORD, LOG, HISTORY, NONE = "record_signature", "log_checkpoint", "history", "none"
# Between responder-b's root record (t(11)) and the checkpoints (t(12)).
REVOKED_BETWEEN = "2026-10-02T12:11:30Z"

REDUNDANT_CB = {"result": "redundant", "reason": "controller_binding", "report": "redundant, not corroborating"}
NOT_APPLICABLE = {"result": "not_applicable"}


def unsign(record: dict) -> dict:
    """The record without its producer signature: neither ``signature`` nor
    ``key_id``. Its Capsule ID does not cover either, so it still holds."""
    return {k: v for k, v in record.items() if k not in ("signature", "key_id")}


def logged_member(member_id: str, observer: str, records: list[dict], key: composed.Key, root: dict) -> dict:
    """A member Bundle that is its responder's whole log (``records`` in log
    order), its root ``root``, with a certificate and a checkpoint signed by
    ``key`` at t(12)."""
    bundle = {"bundle_version": "2", "bundle_kind": "evidence-bundle/v2", "root": root["capsule_id"],
              "records": records,
              "completeness": {"closure_depth": 0, "records_mode": "complete", "payloads_mode": "all"}}
    bundle = composed.logged(bundle, key, f"log:composed-key-source/{member_id}", composed.t(12))
    return {"id": member_id, "observer": observer,
            "request_digest": composed.sha256_hex(composed.jcs(composed.request(member_id))),
            "outcome": "artifact", "digest": composed.bundle_digest(bundle), "bundle": bundle}


def records() -> tuple[dict, dict]:
    rec_a = composed.observation("responder-a", "responder-a.example", A, 10, transcript="shared transcript")
    rec_b = composed.observation("responder-b", "responder-b.example", B, 11, transcript="shared transcript")
    return rec_a, rec_b


def halves(*, a_record=None, a_records=None, a_logged: bool = True) -> tuple[list[dict], list[dict]]:
    """The two halves, each logged; responder-a's root record unsigned by
    default. ``a_record`` replaces it; ``a_records`` sets responder-a's whole
    log (root first)."""
    rec_a, rec_b = records()
    root = a_record if a_record is not None else unsign(rec_a)
    log_a = a_records if a_records is not None else [root]
    member_a = (logged_member("responder-a", "obs-a", log_a, A, root) if a_logged else
                {"id": "responder-a", "observer": "obs-a",
                 "request_digest": composed.sha256_hex(composed.jcs(composed.request("responder-a"))),
                 "outcome": "artifact", "digest": composed.bundle_digest(composed.member_bundle(root)),
                 "bundle": composed.member_bundle(root)})
    member_b = logged_member("responder-b", "obs-b", [rec_b], B, rec_b)
    observers = [{"id": "obs-a", "role": "responder", "custody_domain": "custody-a.example"},
                 {"id": "obs-b", "role": "responder", "custody_domain": "custody-b.example"}]
    return [member_a, member_b], observers


def cb_join(record: dict, state: str, *, pointer: str | None = cbv.KEY_POINTER, compare: bool = True) -> dict:
    out = {"members": PAIR, "basis": "controller_binding", "identifier_digest": cbv.binding_digest(record),
           "state": state}
    if pointer is not None:
        out["pointer"] = pointer
    if compare:
        out["compare"] = [composed.COMPARE_POINTER]
    return out


def member_expect(claims: dict) -> dict:
    return {"outcome": "artifact", "body": "carried", "digest": "reproduced", "claims": claims}


def make(case_id: str, description: str, members: list[dict], observers: list[dict], join: dict, *,
         derived: str | None, sources: tuple[str, str], claims_a: dict, corroboration: dict,
         bindings: list[dict], revocations: list[dict] | None = None, status: str | None = None,
         claims_b: dict | None = None, names: list[str] | None = None) -> dict:
    comp = composed.block(members, observers, [join])
    digest, preimage = composed.composed_digest(comp)
    declared = join["state"]
    result = "not_derivable" if derived is None else "derived_matches" if derived == declared else "join_state_mismatch"
    names = names or PAIR
    if status is None:
        status = "withheld" if derived is None else "pass" if derived == declared else "fail"
    expect_members = {names[0]: claims_a if "outcome" in claims_a else member_expect(claims_a),
                      names[1]: member_expect(claims_b or composed.MEMBER_CLAIMS_LOGGED)}
    return {
        "id": case_id,
        "section": [S_JOINS, S_BINDING, S_CLAIMS],
        "description": description,
        "container": composed.container(comp),
        "controller_bindings": bindings,
        "binding_revocations": revocations or [],
        "expect": {
            "composed_digest": digest,
            "canonical_preimage": preimage,
            "status": status,
            "members": expect_members,
            "composition_closure": {"status": "pass", "missing": []},
            "joins": [{"members": join["members"], "declared": declared, "derived": derived, "result": result,
                       "key_sources": [{"member": names[0], "source": sources[0]},
                                       {"member": names[1], "source": sources[1]}]}],
            "corroboration": [{"members": join["members"], **corroboration}],
        },
    }


LOGGED = composed.MEMBER_CLAIMS_LOGGED
DEPTH0 = composed.MEMBER_CLAIMS_DEPTH0


def cases() -> list[dict]:
    binding = cbv.binding((A, B))
    out = []

    members, observers = halves()
    out.append(make(
        "key-source-unsigned-logged-linked",
        "responder-a's root record carries neither signature nor key_id. Its Capsule ID recomputes from its "
        "content and its own membership proves it under responder-a's signed checkpoint, so its key is the "
        "checkpoint's signer (log_checkpoint) at the checkpoint's time. The binding applies to that key and "
        "responder-b's signed record key: agree, redundant.",
        members, observers, cb_join(binding, "agree", pointer=None), derived="agree", sources=(LOG, RECORD),
        claims_a=LOGGED, corroboration=REDUNDANT_CB, bindings=[binding]))

    members, observers = halves()
    out.append(make(
        "key-source-unsigned-with-pointer",
        "The unsigned, logged root of the linked case, with the -02 pointer /key_id. An unsigned record has "
        "no key_id, so the pointer does not select the key read from the checkpoint: not_derivable. A -03 "
        "composer omits the pointer.",
        members, observers, cb_join(binding, "agree"), derived=None, sources=(LOG, RECORD), claims_a=LOGGED,
        corroboration=NOT_APPLICABLE, bindings=[binding]))

    members, observers = halves(a_logged=False)
    out.append(make(
        "key-source-unsigned-not-logged",
        "responder-a's unsigned root record in a Bundle with no checkpoint or certificate: nothing ties it to "
        "a key, so the join is not_derivable.",
        members, observers, cb_join(binding, "agree"), derived=None, sources=(NONE, RECORD), claims_a=DEPTH0,
        corroboration=NOT_APPLICABLE, bindings=[binding]))

    rec_a, _ = records()
    other = composed.observation("responder-a/other", "responder-a.example", A, 9, transcript="other transcript")
    members, observers = halves(a_records=[other, unsign(rec_a)])
    bundle = members[0]["bundle"]
    bundle["records"] = [r for r in bundle["records"] if r["capsule_id"] != bundle["root"]]
    bundle["completeness"] = dict(bundle["completeness"], missing=[bundle["root"]])
    members[0]["digest"] = composed.bundle_digest(bundle)
    out.append(make(
        "key-source-root-missing-other-proved",
        "responder-a's Bundle proves another record of its log, and lists its root as missing, not carried. "
        "No root record is carried, so there is no record to read a key from: not_derivable.",
        members, observers, cb_join(binding, "agree"), derived=None, sources=(NONE, RECORD),
        claims_a=CLAIMS_ROOT_MISSING, corroboration=NOT_APPLICABLE, bindings=[binding]))

    members, observers = halves()
    members[0]["bundle"]["records"][0]["timestamp"] = composed.t(13)
    members[0]["digest"] = composed.bundle_digest(members[0]["bundle"])
    out.append(make(
        "key-source-edited-content-proved-id",
        "responder-a's unsigned root record, edited after it was logged: its capsule_id still has a valid "
        "inclusion proof, but no longer recomputes from its content. An inclusion proof binds only the "
        "capsule_id, so without record identity the checkpoint signer says nothing about this content: "
        "not_derivable.",
        members, observers, cb_join(binding, "agree"), derived=None, sources=(NONE, RECORD),
        claims_a=CLAIMS_EDITED, corroboration=NOT_APPLICABLE, bindings=[binding]))

    members, observers = halves()
    bundle = members[0]["bundle"]
    root_id = bundle["root"]
    bundle["completeness_certificate"]["memberships"][root_id]["log_coordinates"]["log_id"] = "log:another"
    members[0]["digest"] = composed.bundle_digest(bundle)
    out.append(make(
        "key-source-membership-other-log",
        "responder-a's root membership entry names another log than its signed checkpoint: not its own "
        "membership under that checkpoint, so no key: not_derivable.",
        members, observers, cb_join(binding, "agree"), derived=None, sources=(NONE, RECORD),
        claims_a=CLAIMS_MEMBERSHIP_BROKEN, corroboration=NOT_APPLICABLE, bindings=[binding]))

    members, observers = halves()
    bundle = members[0]["bundle"]
    bundle["completeness_certificate"]["memberships"][bundle["root"]]["inclusion_proof"]["size"] += 1
    members[0]["digest"] = composed.bundle_digest(bundle)
    out.append(make(
        "key-source-membership-size-mismatch",
        "responder-a's root inclusion proof states another MMR size than the signed checkpoint: no key: "
        "not_derivable.",
        members, observers, cb_join(binding, "agree"), derived=None, sources=(NONE, RECORD),
        claims_a=CLAIMS_MEMBERSHIP_BROKEN, corroboration=NOT_APPLICABLE, bindings=[binding]))

    members, observers = halves()
    bundle = members[0]["bundle"]
    bundle["completeness_certificate"]["memberships"][bundle["root"]]["inclusion_proof"]["leaf_index"] += 1
    members[0]["digest"] = composed.bundle_digest(bundle)
    out.append(make(
        "key-source-proof-leaf-index-mismatch",
        "responder-a's root inclusion proof states another leaf_index than its log coordinates: not a proof of "
        "this record's position, so no key: not_derivable.",
        members, observers, cb_join(binding, "agree", pointer=None), derived=None, sources=(NONE, RECORD),
        claims_a=CLAIMS_MEMBERSHIP_BROKEN, corroboration=NOT_APPLICABLE, bindings=[binding]))

    members, observers = halves()
    bundle = members[0]["bundle"]
    bundle["checkpoint"]["root"] = "0" * 64
    members[0]["digest"] = composed.bundle_digest(bundle)
    out.append(make(
        "key-source-stated-root-differs",
        "responder-a's checkpoint JSON states another root than its signed COSE form. A key is read only "
        "through a checkpoint that verifies with every stated copy matching it: not_derivable.",
        members, observers, cb_join(binding, "agree"), derived=None, sources=(NONE, RECORD),
        claims_a=CLAIMS_STATED_ROOT, corroboration=NOT_APPLICABLE, bindings=[binding]))

    rec_a, _ = records()
    members, observers = halves(a_records=[unsign(rec_a), other], a_record=unsign(rec_a))
    bundle = members[0]["bundle"]
    bundle["completeness_certificate"]["memberships"][other["capsule_id"]]["inclusion_proof"]["witness"] = \
        ["0" * 64] * len(bundle["completeness_certificate"]["memberships"][other["capsule_id"]]
                         ["inclusion_proof"]["witness"])
    members[0]["digest"] = composed.bundle_digest(bundle)
    out.append(make(
        "key-source-unrelated-membership-fails",
        "responder-a's log holds its unsigned root and another record whose inclusion proof is broken. The "
        "Bundle's per-record membership fails, and that is reported on the member, but the root's own "
        "membership holds, so its key is still the checkpoint signer: agree, redundant.",
        members, observers, cb_join(binding, "agree", pointer=None), derived="agree", sources=(LOG, RECORD),
        claims_a=CLAIMS_UNRELATED_FAIL, corroboration=REDUNDANT_CB, bindings=[binding]))

    rec_a, _ = records()
    members, observers = halves(a_record={k: v for k, v in rec_a.items() if k != "signature"})
    out.append(make(
        "key-source-key-id-without-signature",
        "responder-a's root record carries key_id but no signature: a failing producer signature, not an "
        "unsigned record. It never falls back to the checkpoint key, though its membership holds: "
        "not_derivable.",
        members, observers, cb_join(binding, "agree"), derived=None, sources=(NONE, RECORD), claims_a=LOGGED,
        corroboration=NOT_APPLICABLE, bindings=[binding]))

    rec_a, _ = records()
    members, observers = halves(a_record={k: v for k, v in rec_a.items() if k != "key_id"})
    out.append(make(
        "key-source-signature-without-key-id",
        "responder-a's root record carries a signature but no key_id: a failing producer signature. No "
        "fallback: not_derivable.",
        members, observers, cb_join(binding, "agree"), derived=None, sources=(NONE, RECORD), claims_a=LOGGED,
        corroboration=NOT_APPLICABLE, bindings=[binding]))

    rec_a, _ = records()
    tampered = dict(rec_a, signature=rec_a["signature"][:-2] + ("00" if rec_a["signature"][-2:] != "00" else "01"))
    members, observers = halves(a_record=tampered)
    out.append(make(
        "key-source-failing-signature",
        "responder-a's root record carries a producer signature that does not verify. Stripping it would "
        "not upgrade the record: no fallback to the checkpoint key: not_derivable.",
        members, observers, cb_join(binding, "agree"), derived=None, sources=(NONE, RECORD), claims_a=LOGGED,
        corroboration=NOT_APPLICABLE, bindings=[binding]))

    revoked = cbv.revocation(binding, B, REVOKED_BETWEEN)
    members, observers = halves()
    out.append(make(
        "key-source-checkpoint-time-after-revocation",
        "The binding is revoked by responder-b's key at a time after both root records but before "
        "responder-a's checkpoint. responder-a's key comes from that checkpoint, so its T is the "
        "checkpoint's time, not its record's: the revocation applies, unjoined, as declared. Read with the "
        "record's time, it would have applied.",
        members, observers, cb_join(binding, "unjoined", pointer=None), derived="unjoined", sources=(LOG, RECORD),
        claims_a=LOGGED, corroboration=NOT_APPLICABLE, bindings=[binding], revocations=[revoked]))

    rec_a, rec_b = records()
    body = {k: v for k, v in rec_a.items() if k not in ("capsule_id", "key_id", "signature")}
    body["x-counterparty-key"] = B.public_hex
    named = composed.seal(body, A)
    members, observers = halves(a_record=named)
    out.append(make(
        "key-source-pointer-selects-other-key",
        "Both root records are signed. responder-a's record also states responder-b's key in "
        "x-counterparty-key, and the join's pointer selects that member. A pointer must select the key read "
        "from the record's signature; this one does not: not_derivable.",
        members, observers, cb_join(binding, "agree", pointer="/x-counterparty-key"), derived=None,
        sources=(RECORD, RECORD), claims_a=LOGGED, corroboration=NOT_APPLICABLE, bindings=[binding]))

    rec_a, _ = records()
    members, observers = halves(a_record=rec_a)
    out.append(make(
        "key-source-signed-without-pointer",
        "Both root records are signed and the join carries no pointer: each key is read from its record's "
        "signature, so none is needed. The binding applies: agree, redundant.",
        members, observers, cb_join(binding, "agree", pointer=None), derived="agree", sources=(RECORD, RECORD),
        claims_a=LOGGED, corroboration=REDUNDANT_CB, bindings=[binding]))

    members, observers = halves()
    history = hv.history_member("history-a", "obs-history-a", A, hv.AFTER)
    members = [history, members[0]]
    observers = [hv.history_observer("history-a"), observers[0]]
    join = {"members": ["history-a", "responder-a"], "basis": "same_key", "state": "agree"}
    case = make(
        "key-source-same-key-unsigned-logged",
        "history-a (responder-a's History) joined on same_key to responder-a's unsigned, logged root record. "
        "The record's key is its checkpoint's signer, the History's responder: agree, redundant (same_key). "
        "A log_checkpoint key states that this key's log holds the record, not that it signed it.",
        members, observers, join, derived="agree", sources=(HISTORY, LOG),
        claims_a=hv.history_expect(A, hv.AFTER), claims_b=LOGGED,
        corroboration={"result": "redundant", "reason": "same_key", "report": "redundant, not corroborating"},
        bindings=[], names=["history-a", "responder-a"])
    case["expect"]["joins"][0]["history_times"] = hv.times("history-a", hv.AFTER, "responder-a", composed.t(10),
                                                           "after")
    out.append(case)
    return out


# Member claims of edited Bundles, as the Bundle rules give them.
# The root is not carried: graph closure fails, and the certificate's
# membership for it is a record the Bundle does not carry.
CLAIMS_ROOT_MISSING = {"graph_closure": "fail", "interval_coverage": "pass", "per_record_membership": "fail"}
CLAIMS_EDITED = {"graph_closure": "fail", "interval_coverage": "pass", "per_record_membership": "fail"}
CLAIMS_MEMBERSHIP_BROKEN = {"graph_closure": "pass", "interval_coverage": "pass", "per_record_membership": "fail"}
CLAIMS_STATED_ROOT = {"graph_closure": "pass", "interval_coverage": "fail", "per_record_membership": "fail"}
CLAIMS_UNRELATED_FAIL = {"graph_closure": "pass", "interval_coverage": "pass", "per_record_membership": "fail"}


def build() -> dict[str, bytes]:
    case_list = cases()
    files = {
        "vectors.json": composed._dump({
            "draft": DRAFT,
            "provenance": "spec-derived",
            "status": "draft -03 text; held for ratification with -03",
            "kind": composed.KIND,
            "inputs": "controller_bindings and binding_revocations are delivered beside the containing Bundle.",
            "keys": {k.name: {"seed_hex": k.seed.hex(), "public_key_hex": k.public_hex} for k in (A, B)},
            "count": len(case_list),
            "cases": case_list,
        }),
    }
    files["manifest.json"] = composed._dump({
        "draft": DRAFT,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_bundle_composed_key_source_vectors.py",
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
