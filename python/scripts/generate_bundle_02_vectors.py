#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the Evidence Bundle -02 certificate vectors.

Three directories, read by strict ``verify_bundle`` as
``vectors/bundle/strict/`` is:

- ``vectors/bundle/non-record-leaves/``: a range over a log whose leaves include
  padding records, carried in ``completeness_certificate.non_record_leaves``;
- ``vectors/bundle/certificate-mode/``: the producer-selected certificate in the
  shape producers already emit, and ``completeness.selection`` values that name
  a certificate mode the verifier does not implement;
- ``vectors/bundle/category-coverage/``: the ``category_coverage`` member's five
  properties and the strict verdict.

Every expected result below is written by hand, per case, from the rules in
each directory's README; nothing here runs a verifier. The literal Bundles are
built with the strict generator's records, keys and checkpoint signer, so the
output is a pure function of the two scripts. The READMEs are hand-written and
never rewritten here.

Dependencies: ``agent-action-capsule[bundle,envelope]`` and ``cryptography``.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cll.checkpoint import (
    CheckpointRecord,
    MemoryNodeStore,
    add_leaf,
    checkpoint_to_cose,
    core,
    leaf_hash,
    peaks,
    root_from_peaks,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_bundle_strict_vectors as strict  # noqa: E402

from agent_action_capsule.canonical import jcs  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "bundle"
LOG_ID = "log:bundle-02-vectors"

# The layout checked on a real padded log (pad bucket 32): 5 records, 27
# padding, 3 records, 29 padding. The checkpoint tip, seq 64, is padding.
LAYOUT = [("record", 5), ("padding", 27), ("record", 3), ("padding", 29)]

claims, claim, case, records_expect, ABSENT, UNANCHORED = (
    strict.claims, strict.claim, strict.case, strict.records_expect, strict.ABSENT, strict.UNANCHORED,
)


def digest(value: Any) -> str:
    return hashlib.sha256(jcs(value)).hexdigest()


def padding(label: str) -> dict:
    """A padding record in the four-member serialization. The nonce is a
    fixed value derived from ``label`` so the run is reproducible."""
    body = {
        "record_type": "padding",
        "epistemic_type": "producer_claim",
        "store_nonce": hashlib.sha256(f"bundle-02 padding {label}".encode()).hexdigest(),
    }
    return {"capsule_id": digest(body), **body}


def padded_log() -> list[tuple[str, dict]]:
    leaves: list[tuple[str, dict]] = []
    for kind, count in LAYOUT:
        for _ in range(count):
            seq = len(leaves) + 1
            if kind == "record":
                leaves.append((kind, strict.signed(strict.capsule(f"padded-{seq}"))))
            else:
                leaves.append((kind, padding(str(seq))))
    return leaves


def bundle_over_log(leaves: list[tuple[str, dict]], first_seq: int | None) -> dict:
    """A Bundle over the whole log ``leaves`` with a signed COSE checkpoint at
    its tip. ``first_seq`` starts a range ending at the tip, carrying every
    record of it and every padding leaf in ``non_record_leaves``; ``None``
    builds the producer-selected Bundle of every record, in the shape a
    producer already emits (``payloads_mode`` ``none``, no range)."""
    store = MemoryNodeStore()
    for _, item in leaves:
        add_leaf(store, leaf_hash(bytes.fromhex(item["capsule_id"])))
    size = store.size()
    peak_hashes = [store.node(p) for p in peaks(size)]
    root = root_from_peaks(peak_hashes).hex()
    signer = strict._StatementSigner(strict.LOG_KEY)
    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id=LOG_ID, mmr_size=size, root=root, prev_size=0, prev_root="",
        key_id=signer.key_id, timestamp=strict.TIMESTAMP, signature="",
    )
    checkpoint = {
        "log_id": LOG_ID, "mmr_size": size, "root": root, "prev_size": 0, "prev_root": "",
        "key_id": signer.key_id, "timestamp": strict.TIMESTAMP,
        "cose": strict.b64u(checkpoint_to_cose(cp, signer, peak_hashes)),
    }
    tip = len(leaves)
    start = first_seq or 1
    carried = [(seq, item) for seq, (kind, item) in enumerate(leaves, 1) if kind == "record" and seq >= start]
    certificate: dict[str, Any] = {"log_id": LOG_ID, "range_root": root}
    if first_seq is not None:
        rp = core.range_proof(store, first_seq - 1, tip - 1, size)
        certificate.update({
            "first_seq": first_seq,
            "last_seq": tip,
            "body_digests": [item["capsule_id"] for _, item in leaves[first_seq - 1:]],
            "range_proof": {
                "from_seq": first_seq, "to_seq": tip, "size": rp.size, "from_index": rp.from_index,
                "to_index": rp.to_index, "witness": list(rp.witness),
            },
        })
    certificate["memberships"] = {
        item["capsule_id"]: {
            "log_coordinates": {"log_id": LOG_ID, "seq": seq, "leaf_index": seq - 1},
            "inclusion_proof": strict.proof_dict(core.inclusion_proof(store, seq - 1, size)),
        }
        for seq, item in carried
    }
    if first_seq is not None:
        certificate["non_record_leaves"] = [
            {"seq": seq, "content": copy.deepcopy(item)}
            for seq, (kind, item) in enumerate(leaves, 1)
            if kind == "padding" and seq >= first_seq
        ]
    completeness = {
        "closure_depth": 0, "records_mode": "complete", "payloads_mode": "selected", "suppressed_fields": [],
        "missing": [],
    }
    if first_seq is None:
        completeness.update(selection="producer-selected", payloads_mode="none")
    return {
        "bundle_version": "2",
        "bundle_kind": "evidence-bundle/v2",
        "root": carried[-1][1]["capsule_id"],
        "records": [item for _, item in carried],
        "completeness": completeness,
        "completeness_certificate": certificate,
        "checkpoint": checkpoint,
    }


def expect(bundle: dict, verdict: str, **overrides: Any) -> dict:
    return {
        "verdict": verdict, "claims": claims(**overrides), "witnesses": ABSENT, "records": records_expect(bundle),
        "checkpoint_authenticated": True, "signer_matches_checkpoint": False,
    }


def leaf_cases() -> list[dict]:
    log = padded_log()
    whole = bundle_over_log(log, 1)
    suffix = bundle_over_log(log, 6)
    cases = [
        case("pos-padded-whole-log",
             "The whole 64-leaf log (5 records, 27 padding, 3 records, 29 padding): every padding leaf is carried in "
             "full and recomputes to its body digest.", whole, expect(whole, "VALID")),
        case("pos-padded-suffix",
             "The suffix [6, 64]: it starts on a padding leaf and ends on the padding tip.", suffix,
             expect(suffix, "VALID")),
    ]
    leaves = whole["completeness_certificate"]["non_record_leaves"]
    index_of = {element["seq"]: i for i, element in enumerate(leaves)}

    def edited(edit: Any) -> dict:
        bundle = copy.deepcopy(whole)
        edit(bundle["completeness_certificate"]["non_record_leaves"])
        return bundle

    def neg(case_id: str, description: str, edit: Any, *findings: str) -> None:
        bundle = edited(edit)
        cases.append(case(case_id, description, bundle,
                          expect(bundle, "INVALID", per_record_membership=claim("fail", *findings))))

    def content(seq: int) -> Any:
        return lambda leaves: leaves[index_of[seq]]["content"]

    neg("neg-padding-nonce-edited", "The padding at seq 6 has its store_nonce changed and its capsule_id left as it was.",
        lambda ls: content(6)(ls).update(store_nonce="00" * 32), "non_record_leaf_mismatch:6")

    def recomputed_other(ls: list) -> None:
        other = padding("not in this log")
        ls[index_of[7]]["content"] = other

    neg("neg-padding-other-leaf", "The padding at seq 7 is a well-formed padding record that recomputes to its own "
        "capsule_id, but not to body_digests for seq 7.", recomputed_other, "non_record_leaf_mismatch:7")

    def swapped(ls: list) -> None:
        a, b = index_of[6], index_of[7]
        ls[a]["content"], ls[b]["content"] = ls[b]["content"], ls[a]["content"]

    neg("neg-padding-swapped", "The contents of seq 6 and seq 7 are swapped.", swapped,
        "non_record_leaf_mismatch:6", "non_record_leaf_mismatch:7")

    def digest_only(ls: list) -> None:
        element = ls[index_of[8]]
        ls[index_of[8]] = {"seq": 8, "digest": element["content"]["capsule_id"]}

    neg("neg-padding-digest-only", "Seq 8 is carried as its digest, with no content.", digest_only,
        "non_record_leaf_malformed:8")
    neg("neg-padding-extra-member", "The padding at seq 9 also carries links: [].",
        lambda ls: content(9)(ls).update(links=[]), "non_record_leaf_malformed:9")

    def envelope_left(ls: list) -> None:
        c = content(10)(ls)
        c["signature"] = strict.envelope(c["capsule_id"], strict.PRODUCER)
        c["key_id"] = strict.raw_public(strict.PRODUCER).hex()

    neg("neg-padding-envelope-left", "The padding at seq 10 still carries a producer envelope (signature, key_id).",
        envelope_left, "non_record_leaf_malformed:10")
    neg("neg-padding-epistemic-type", "The padding at seq 11 has epistemic_type observed_event.",
        lambda ls: content(11)(ls).update(epistemic_type="observed_event"), "non_record_leaf_malformed:11")

    def nonce_upper(ls: list) -> None:
        c = content(12)(ls)
        c["store_nonce"] = c["store_nonce"].upper()

    neg("neg-padding-nonce-uppercase", "The padding at seq 12 has an uppercase store_nonce.", nonce_upper,
        "non_record_leaf_malformed:12")
    neg("neg-padding-content-not-object", "The content of seq 13 is a string.",
        lambda ls: ls[index_of[13]].update(content="padding"), "non_record_leaf_malformed:13")
    neg("neg-padding-seq-out-of-range", "The element for seq 14 says seq 65, past the tip.",
        lambda ls: ls[index_of[14]].update(seq=65),
        f"non_record_leaf_seq_invalid:{index_of[14]}", "membership_record_missing:14")
    # Elements are read in order: the first to claim seq 16 holds it (and does
    # not recompute to it), the next one is the repeat.
    neg("neg-padding-seq-repeated", "The element for seq 15 says seq 16, which the next element also claims.",
        lambda ls: ls[index_of[15]].update(seq=16),
        "non_record_leaf_mismatch:16", f"non_record_leaf_seq_invalid:{index_of[16]}", "membership_record_missing:15")
    neg("neg-padding-seq-on-record", "The element for seq 17 says seq 3, a record's seq.",
        lambda ls: ls[index_of[17]].update(seq=3),
        f"non_record_leaf_seq_invalid:{index_of[17]}", "membership_record_missing:17")
    neg("neg-padding-seq-not-integer", "The element for seq 18 says seq \"18\".",
        lambda ls: ls[index_of[18]].update(seq="18"),
        f"non_record_leaf_seq_invalid:{index_of[18]}", "membership_record_missing:18")
    neg("neg-padding-omitted", "The element for the tip, seq 64, is left out.",
        lambda ls: ls.pop(index_of[64]), "membership_record_missing:64")

    bundle = copy.deepcopy(whole)
    bundle["completeness_certificate"]["non_record_leaves"] = {}
    padding_seqs = [e["seq"] for e in leaves]
    cases.append(case(
        "neg-non-record-leaves-not-array", "non_record_leaves is an object, not an array: no padding seq is accounted for.",
        bundle, expect(bundle, "INVALID", per_record_membership=claim(
            "fail", "non_record_leaves_malformed", *[f"membership_record_missing:{s}" for s in padding_seqs]))))
    neg("neg-non-record-leaf-element-not-object", "The element for seq 19 is the number 19.",
        lambda ls: ls.__setitem__(index_of[19], 19),
        f"non_record_leaf_element_invalid:{index_of[19]}", "membership_record_missing:19")

    stamp = {"record_type": "checkpoint_stamp", "epistemic_type": "producer_claim", "note": "an unknown type"}
    unknown = edited(lambda ls: ls[index_of[20]].update(content=stamp))
    cases.append(case(
        "incomplete-unknown-leaf-type", "Seq 20 is carried as a leaf of a record_type this document does not define: "
        "everything else passes, the claim is withheld.", unknown,
        expect(unknown, "INCOMPLETE", per_record_membership=claim("withheld", "non_record_leaf_type_unsupported:20"))))

    def unknown_and(edit: Any) -> Any:
        def both(ls: list) -> None:
            ls[index_of[20]]["content"] = copy.deepcopy(stamp)
            edit(ls)
        return both

    neg("neg-unknown-type-and-mismatch", "Seq 20 is of an unknown type and seq 21's nonce is edited: the mismatch fails.",
        unknown_and(lambda ls: content(21)(ls).update(store_nonce="11" * 32)),
        "non_record_leaf_type_unsupported:20", "non_record_leaf_mismatch:21")
    neg("neg-unknown-type-and-missing", "Seq 20 is of an unknown type and the element for seq 22 is left out.",
        unknown_and(lambda ls: ls.pop(index_of[22])),
        "non_record_leaf_type_unsupported:20", "membership_record_missing:22")

    no_cose = copy.deepcopy(unknown)
    del no_cose["checkpoint"]["cose"]
    cases.append(case(
        "incomplete-unknown-leaf-type-unsigned-checkpoint", "The unknown-type Bundle without checkpoint.cose: "
        "withheld, with checkpoint_unverified added.", no_cose,
        {**expect(no_cose, "INCOMPLETE",
                  checkpoint=claim("withheld", "checkpoint_signature_absent"),
                  interval_coverage=UNANCHORED,
                  per_record_membership=claim("withheld", "non_record_leaf_type_unsupported:20", "checkpoint_unverified")),
         "checkpoint_authenticated": False, "signer_matches_checkpoint": None}))

    selected = bundle_over_log(log, None)
    selected["completeness_certificate"]["non_record_leaves"] = []
    cases.append(case(
        "neg-non-record-leaves-on-producer-selected", "A producer-selected Bundle (no range) carrying an empty "
        "non_record_leaves member.", selected,
        expect(selected, "INVALID", interval_coverage=claim("withheld", "selection_not_checkable"),
               per_record_membership=claim("fail", "completeness_certificate_invalid"))))
    return cases


def mode_cases() -> list[dict]:
    log = padded_log()
    selected = bundle_over_log(log, None)
    cases = [case(
        "incomplete-producer-selected-padded-log", "The eight records of the padded log, producer-selected, in the "
        "shape producers emit (payloads_mode none, no range): each record's proof checks, the interval is not shown.",
        selected, expect(selected, "INCOMPLETE", interval_coverage=claim("withheld", "selection_not_checkable")))]
    tampered = copy.deepcopy(selected)
    tampered["completeness_certificate"]["memberships"][tampered["root"]]["inclusion_proof"]["witness"][0] = "00" * 32
    cases.append(case(
        "neg-producer-selected-padded-log-tampered", "The same with the root record's inclusion proof edited.", tampered,
        expect(tampered, "INVALID", interval_coverage=claim("withheld", "selection_not_checkable"),
               per_record_membership=claim("fail", f"membership_proof_invalid:{tampered['root']}"))))
    unsupported = claim("withheld", "certificate_mode_unsupported")
    for case_id, value, what in (
        ("incomplete-certificate-mode-unknown", "x-sampled", "a selection value this document does not define"),
        ("incomplete-certificate-mode-not-a-string", 7, "a selection value that is not a string"),
    ):
        bundle = copy.deepcopy(selected)
        bundle["completeness"]["selection"] = value
        cases.append(case(case_id, f"The producer-selected Bundle with {what}: interval coverage and per-record "
                          "membership are withheld, never failed.", bundle,
                          expect(bundle, "INCOMPLETE", interval_coverage=unsupported, per_record_membership=unsupported)))
    ranged = bundle_over_log(log, 33)
    ranged["completeness"]["selection"] = "x-sampled"
    cases.append(case(
        "incomplete-certificate-mode-unknown-on-range", "A valid range certificate [33, 64] under an unknown selection "
        "value: the verifier does not read the certificate under a mode it does not implement.", ranged,
        expect(ranged, "INCOMPLETE", interval_coverage=unsupported, per_record_membership=unsupported)))
    return cases


# -- category_coverage ----------------------------------------------------------

SET_ID = "example-set"
SET_NAMES = ["messages", "tool_calls", "payments", "approvals", "model_inputs", "memory", "telemetry"]
POLICY_URI = "https://policy.example/retention/v1"


def sign_coverage(member: dict, root: str, key: Any = None) -> dict:
    """``member`` with ``signer`` and ``signature`` by ``key`` (the producer
    key by default) over JCS({"category_coverage": member without signature,
    "root": root})."""
    key = key or strict.PRODUCER
    out = {**{k: v for k, v in member.items() if k not in ("signer", "signature")},
           "signer": {"key_id": strict.raw_public(key).hex()}}
    out["signature"] = key.sign(jcs({"category_coverage": out, "root": root})).hex()
    return out


def coverage_case(case_id: str, description: str, bundle: dict, verdict: str, properties: dict | None,
                  **options: Any) -> dict:
    return {"id": case_id, "description": description, "options": {
        "category_sets": options.get("category_sets"),
        "category_request": options.get("category_request"),
        "record_categories": options.get("record_categories"),
    }, "bundle": bundle, "expect": {"verdict": verdict, "category_coverage": properties}}


def props(form="PASS", signature="PASS", set_registered="PASS", request="PASS", consistency="PASS") -> dict:
    return {
        "category_coverage_form": form,
        "category_coverage_signature": signature,
        "category_coverage_set_registered": set_registered,
        "category_coverage_request": request,
        "category_coverage_consistency": consistency,
    }


MALFORMED = props("FAIL", "NOT_CHECKED", "NOT_CHECKED", "NOT_CHECKED", "NOT_CHECKED")


def coverage_cases() -> list[dict]:
    records = [strict.signed(strict.capsule(f"coverage-{i}")) for i in range(1, 4)]
    base = strict.bundle_over(records)
    root = base["root"]
    ids = [r["capsule_id"] for r in records]
    request = json.dumps({"subject": {"kind": "record", "id": root},
                          "categories": {"set": SET_ID, "names": ["messages", "payments"]}},
                         separators=(",", ":"), sort_keys=True)
    request_digest = hashlib.sha256(request.encode()).hexdigest()
    six = {
        "messages": {"status": "AVAILABLE"},
        "tool_calls": {"status": "PARTIAL"},
        "payments": {"status": "WITHHELD"},
        "approvals": {"status": "DELETED"},
        "model_inputs": {"status": "ABSENT"},
        "memory": {"status": "UNDISCLOSED", "policy_uri": POLICY_URI},
    }
    declaration = {"set": SET_ID, "categories": six, "request_digest": request_digest}
    sets = {SET_ID: SET_NAMES}
    # Every carried record is a message; nothing is in a WITHHELD or ABSENT category.
    assigned = {cid: "messages" for cid in ids}
    full = {"category_sets": sets, "category_request": request, "record_categories": assigned}

    def with_member(member: Any) -> dict:
        bundle = copy.deepcopy(base)
        bundle["category_coverage"] = member
        return bundle

    signed_six = sign_coverage(declaration, root)
    cases = [
        coverage_case("pos-all-six-statuses", "One category in each of the six statuses, signed by the producer key, "
                      "with every input supplied: all five properties pass.", with_member(signed_six), "VALID",
                      props(), **full),
        coverage_case("pos-no-inputs", "The same with no inputs: the set is unknown to the verifier (INCONCLUSIVE), "
                      "request and consistency are NOT_CHECKED.", with_member(signed_six), "VALID",
                      props(set_registered="INCONCLUSIVE", request="NOT_CHECKED", consistency="NOT_CHECKED")),
        coverage_case("no-member", "A Bundle with no category_coverage member.", copy.deepcopy(base), "VALID", None, **full),
    ]
    private = sign_coverage({**declaration, "set": "x-local-categories"}, root)
    cases.append(coverage_case(
        "private-set", "A private x- set: never looked up, reported NOT_PRESENT; the request names another set.",
        with_member(private), "VALID", props(set_registered="NOT_PRESENT", request="FAIL"), **full))
    unsigned = {k: v for k, v in signed_six.items() if k not in ("signer", "signature")}
    cases.append(coverage_case("unsigned-member", "No signer and no signature: the declaration is attributed to no "
                               "one (NOT_PRESENT), which does not fail the Bundle.", with_member(unsigned), "VALID",
                               props(signature="NOT_PRESENT"), **full))
    wrong_key = dict(sign_coverage(declaration, root, strict.OTHER))
    wrong_key["signer"] = {"key_id": strict.raw_public(strict.PRODUCER).hex()}
    cases.append(coverage_case("neg-signature-wrong-key", "Signed by another key than signer.key_id.",
                               with_member(wrong_key), "INVALID", props(signature="FAIL"), **full))
    moved = sign_coverage(declaration, "00" * 32)
    cases.append(coverage_case("neg-signature-other-root", "Signed over another Bundle's root: a declaration "
                               "moved from another Bundle.", with_member(moved), "INVALID", props(signature="FAIL"),
                               **full))
    edited = copy.deepcopy(signed_six)
    edited["categories"]["payments"]["status"] = "AVAILABLE"
    cases.append(coverage_case("neg-signature-edited", "WITHHELD changed to AVAILABLE after signing.",
                               with_member(edited), "INVALID", props(signature="FAIL"), **full))

    def malformed(case_id: str, description: str, edit: Any) -> None:
        member = copy.deepcopy(declaration)
        edit(member)
        cases.append(coverage_case(case_id, description, with_member(sign_coverage(member, root)), "INVALID",
                                   MALFORMED, **full))

    malformed("neg-undisclosed-without-policy-uri", "UNDISCLOSED with no policy_uri.",
              lambda m: m["categories"]["memory"].pop("policy_uri"))
    malformed("neg-policy-uri-relative", "UNDISCLOSED with a relative policy_uri.",
              lambda m: m["categories"]["memory"].update(policy_uri="/retention/v1"))
    malformed("neg-status-lowercase", "A status in lowercase (available).",
              lambda m: m["categories"]["messages"].update(status="available"))
    malformed("neg-status-unknown", "A status that is not one of the six (LEGAL_HOLD).",
              lambda m: m["categories"]["messages"].update(status="LEGAL_HOLD"))
    malformed("neg-categories-empty", "categories is an empty object.", lambda m: m.update(categories={}))
    malformed("neg-set-missing", "No set.", lambda m: m.pop("set"))
    malformed("neg-request-digest-uppercase", "request_digest in uppercase hex.",
              lambda m: m.update(request_digest=m["request_digest"].upper()))
    half = dict(signed_six)
    del half["signature"]
    cases.append(coverage_case("neg-signer-without-signature", "signer with no signature.", with_member(half),
                               "INVALID", MALFORMED, **full))
    cases.append(coverage_case("neg-member-not-object", "category_coverage is an array.", with_member([signed_six]),
                               "INVALID", MALFORMED, **full))

    unknown_name = sign_coverage({**declaration, "categories": {**six, "receipts": {"status": "AVAILABLE"}}}, root)
    cases.append(coverage_case("unknown-category", "A name the registered set does not have: set_registered fails, "
                               "which is reported and does not fail the Bundle.", with_member(unknown_name), "VALID",
                               props(set_registered="FAIL"), **full))
    cases.append(coverage_case("unknown-set", "A set the verifier does not know: INCONCLUSIVE.",
                               with_member(signed_six), "VALID", props(set_registered="INCONCLUSIVE"),
                               **{**full, "category_sets": {"another-set": SET_NAMES}}))
    narrow = copy.deepcopy(declaration)
    del narrow["categories"]["payments"]
    cases.append(coverage_case("request-not-covered", "The request asks for payments; the declaration has no entry "
                               "for it.", with_member(sign_coverage(narrow, root)), "VALID", props(request="FAIL"),
                               **full))
    other_request = request.replace('"messages"', '"telemetry"')
    cases.append(coverage_case("request-digest-mismatch", "request_digest names another request than the one "
                               "supplied.", with_member(signed_six), "VALID", props(request="FAIL"),
                               **{**full, "category_request": other_request}))
    no_digest = sign_coverage({k: v for k, v in declaration.items() if k != "request_digest"}, root)
    bare = json.dumps({"subject": {"kind": "record", "id": root}}, separators=(",", ":"), sort_keys=True)
    cases.append(coverage_case("request-without-categories", "The request asked for no categories: NOT_PRESENT.",
                               with_member(no_digest), "VALID", props(request="NOT_PRESENT"),
                               **{**full, "category_request": bare}))
    for case_id, category, status in (
        ("neg-consistency-absent-with-record", "model_inputs", "ABSENT"),
        ("neg-consistency-withheld-with-record", "payments", "WITHHELD"),
    ):
        cases.append(coverage_case(case_id, f"A carried record is in a category declared {status}.",
                                   with_member(signed_six), "INVALID", props(consistency="FAIL"),
                                   **{**full, "record_categories": {**assigned, ids[0]: category}}))
    for case_id, category, status in (
        ("consistency-deleted-with-record", "approvals", "DELETED"),
        ("consistency-undisclosed-with-record", "memory", "UNDISCLOSED"),
    ):
        cases.append(coverage_case(case_id, f"A carried record is in a category declared {status}: not a "
                                   "contradiction.", with_member(signed_six), "VALID", props(),
                                   **{**full, "record_categories": {**assigned, ids[0]: category}}))
    return cases


def write(out: Path, description: str, cases: list[dict]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    vectors = {
        "format_version": "1",
        "description": description,
        "keys": {
            "producer_public_key": strict.raw_public(strict.PRODUCER).hex(),
            "log_public_key": strict.raw_public(strict.LOG_KEY).hex(),
        },
        "cases": cases,
    }
    files = {"vectors.json": strict.dump(vectors)}
    files["manifest.json"] = strict.dump({
        "format_version": "1",
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest()} for name, data in files.items()},
        "case_count": len(cases),
    })
    for name, data in files.items():
        (out / name).write_bytes(data)
    names = sorted(p.name for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (out / "SHA256SUMS").write_text("".join(f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n" for n in names))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="the parent of the two vector directories")
    out = parser.parse_args().out
    write(out / "non-record-leaves", "Strict verify_bundle over ranges that carry padding leaves in "
          "completeness_certificate.non_record_leaves (Evidence Bundle -02). See README.md.", leaf_cases())
    write(out / "certificate-mode", "Strict verify_bundle on the producer-selected certificate and on certificate "
          "modes a verifier does not implement (Evidence Bundle -02). See README.md.", mode_cases())
    write(out / "category-coverage", "verify_bundle on the category_coverage member: its five properties and "
          "the strict verdict (Evidence Bundle -02). See README.md.", coverage_cases())


if __name__ == "__main__":
    main()
