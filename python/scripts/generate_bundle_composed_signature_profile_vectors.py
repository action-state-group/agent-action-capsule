#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the ``composed/v1`` carried signature profile vectors (#676).

``draft-mih-zhang-agent-disclosure-bundle-03``, "Carried Signature Profiles":
``three-member-refusal/v1``, ``whole-refusal/v1`` and
``digest-bound-artifact-response/v1``. Each object case is a carried refusal
or response with the profile it is read in and its signature state; each
composed case is a ``composed/v1`` container verified with both profile
verifiers set, with the member's signature state and the block's status.

Every expected value is written by hand from the draft text. The generator
only builds objects and signs them with ``cryptography``; it imports no
implementation of the profiles. The forgery cases (a small-order key, an
identity R) also record that a lenient Ed25519 verifier, ``cryptography``'s,
accepts them, so they test strictness and nothing else.

Output: ``vectors/bundle/composed-signature-profiles/`` (or ``--out DIR``).
``README.md`` is hand-written; when present in the output directory it is
included in ``SHA256SUMS`` but never rewritten. The run is deterministic.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ed25519_forgeries as forgeries  # noqa: E402
import generate_bundle_composed_vectors as composed  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "bundle" / "composed-signature-profiles"
DRAFT = "draft-mih-zhang-agent-disclosure-bundle-03 (composed/v1: Carried Signature Profiles)"
SECTION = "composed/v1: Carried Signature Profiles"
S_MEMBERS = "composed/v1: Members and Outcomes"

TM, WR, DB = "three-member-refusal/v1", "whole-refusal/v1", "digest-bound-artifact-response/v1"
VERIFIED, INVALID, UNVERIFIED = "verified", "invalid", "signature_unverified"
ARTIFACT_RESPONSE_TYPE = "evidence-artifact-response/v1"

RESPONDER = composed.RESPONDER_A
OTHER = composed.RESPONDER_B
#: The identity point as a key, with R = [r]B and S = r: [S]B = R + [k]A holds
#: for any message, since [k]A is the identity. R and S are canonical and R is
#: not of small order, so only the small-order key condition refuses it.
SMALL_ORDER_KEY, SMALL_ORDER_SIG = (x.hex() for x in forgeries.small_order_key(
    b"composed/v1 carried signature profile vectors: r"))

REQUEST_DIGEST = composed.sha256_hex(b"composed/v1 carried signature profile vectors: request")
ANCHOR = composed.sha256_hex(b"composed/v1 carried signature profile vectors: anchor")
ARTIFACT_DIGEST = composed.sha256_hex(b"composed/v1 carried signature profile vectors: artifact")
ISSUED_AT = "2026-11-22T12:00:00Z"


def sign(key: composed.Key, message: bytes) -> str:
    return key.private.sign(message).hex()


def lenient_verifies(key_hex: str, sig_hex: str, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(bytes.fromhex(sig_hex), message)
    except (InvalidSignature, ValueError):
        return False
    return True


def three_member_input(refusal: dict) -> bytes:
    return composed.jcs({k: refusal[k] for k in ("issued_at", "reason", "request_digest")})


def whole_input(refusal: dict) -> bytes:
    return composed.jcs({k: v for k, v in refusal.items() if k != "signature"})


def response_input(response: dict) -> bytes:
    signed = {k: response[k] for k in ("request_digest", "anchor", "artifact_kind", "artifact_digest", "issued_at")}
    return composed.jcs({"type": ARTIFACT_RESPONSE_TYPE, **signed})


def base_refusal() -> dict:
    return {"request_digest": REQUEST_DIGEST, "reason": "policy_declined", "issued_at": ISSUED_AT}


def three_member(key: composed.Key = RESPONDER, **extra: Any) -> dict:
    refusal = base_refusal()
    refusal["key_id"] = key.public_hex
    refusal["sig"] = sign(key, three_member_input(refusal))
    refusal.update(extra)
    return refusal


def whole(key: composed.Key = RESPONDER, **extra: Any) -> dict:
    refusal = base_refusal()
    refusal.update(extra)
    refusal["key_id"] = key.public_hex
    refusal["signature"] = sign(key, whole_input(refusal))
    return refusal


def base_response() -> dict:
    return {"request_digest": REQUEST_DIGEST, "anchor": ANCHOR, "artifact_kind": "evidence-bundle/v2",
            "artifact_digest": ARTIFACT_DIGEST, "issued_at": ISSUED_AT}


def response(key: composed.Key = RESPONDER) -> dict:
    out = base_response()
    out["key_id"] = key.public_hex
    out["sig"] = sign(key, response_input(out))
    return out


def case(case_id: str, kind: str, obj: dict, profile: str | None, state: str, description: str,
         *, signing_input: bytes | None = None, lenient: bool | None = None) -> dict:
    out: dict[str, Any] = {"id": case_id, "section": [SECTION], "description": description, "kind": kind,
                           "object": obj, "expect": {"profile": profile, "state": state}}
    if signing_input is not None:
        out["signing_input_hex"] = signing_input.hex()
    if lenient is not None:
        out["lenient_ed25519_verifies"] = lenient
    return out


def forgery_cases() -> list[dict]:
    """A small-order key and an identity R in each profile: strict Ed25519
    refuses both, and a lenient verifier accepts both."""
    out = []
    # three-member-refusal/v1
    tm_small = dict(base_refusal(), key_id=SMALL_ORDER_KEY, sig=SMALL_ORDER_SIG)
    tm_r = dict(base_refusal(), key_id=RESPONDER.public_hex)
    tm_r["sig"] = forgeries.identity_r(RESPONDER.private, three_member_input(tm_r)).hex()
    # whole-refusal/v1
    wr_small = dict(base_refusal(), key_id=SMALL_ORDER_KEY, signature=SMALL_ORDER_SIG)
    wr_r = dict(base_refusal(), key_id=RESPONDER.public_hex)
    wr_r["signature"] = forgeries.identity_r(RESPONDER.private, whole_input(wr_r)).hex()
    # digest-bound-artifact-response/v1
    db_small = dict(base_response(), key_id=SMALL_ORDER_KEY, sig=SMALL_ORDER_SIG)
    db_r = dict(base_response(), key_id=RESPONDER.public_hex)
    db_r["sig"] = forgeries.identity_r(RESPONDER.private, response_input(db_r)).hex()
    for case_id, kind, obj, profile, sig_name, message in (
        ("three-member-small-order-key", "refusal", tm_small, TM, "sig", three_member_input(tm_small)),
        ("three-member-identity-r", "refusal", tm_r, TM, "sig", three_member_input(tm_r)),
        ("whole-refusal-small-order-key", "refusal", wr_small, WR, "signature", whole_input(wr_small)),
        ("whole-refusal-identity-r", "refusal", wr_r, WR, "signature", whole_input(wr_r)),
        ("response-small-order-key", "response", db_small, DB, "sig", response_input(db_small)),
        ("response-identity-r", "response", db_r, DB, "sig", response_input(db_r)),
    ):
        lenient = lenient_verifies(obj["key_id"], obj[sig_name], message)
        assert lenient, case_id
        what = ("a key of small order (the identity point) with R = [r]B and S = r, which verifies any message "
                "and fails only the small-order key condition" if "small-order" in case_id else
                "the responder's own key with R the identity point, a signature only that key holder can make")
        out.append(case(case_id, kind, obj, profile, INVALID,
                        f"Signed in {profile} by {what}. A lenient Ed25519 verifier accepts it; strict Ed25519 "
                        "refuses it, so the signature is invalid (named after the forged-refusal cases of "
                        "vectors/interop-profile-v1/).", lenient=True))
    return out


def refusal_cases() -> list[dict]:
    tm = three_member()
    tampered = dict(tm, reason="not_authorized")
    other_key = dict(tm, key_id=OTHER.public_hex)
    extra = three_member(detail="declined by policy", note="unsigned")
    v2 = dict(base_refusal(), policy_digest=composed.sha256_hex(b"policy"), key_id=RESPONDER.public_hex)
    v2["sig"] = sign(RESPONDER, composed.jcs({k: v2[k] for k in ("issued_at", "reason", "request_digest",
                                                                  "policy_digest")}))
    wr_policy = whole(policy_digest=composed.sha256_hex(b"policy"))
    empty = dict(base_refusal(), reason="", key_id=RESPONDER.public_hex)
    empty["sig"] = sign(RESPONDER, three_member_input(empty))
    nonstring = dict(base_refusal(), reason=["policy_declined"], key_id=RESPONDER.public_hex)
    nonstring["sig"] = sign(RESPONDER, composed.jcs({k: nonstring[k] for k in ("issued_at", "reason",
                                                                                   "request_digest")}))
    missing = {k: v for k, v in tm.items() if k != "issued_at"}
    missing["sig"] = sign(RESPONDER, composed.jcs({k: missing[k] for k in ("reason", "request_digest")}))
    sig_only = {k: v for k, v in tm.items() if k != "key_id"}
    upper = dict(tm, sig=tm["sig"].upper())
    short_key = dict(tm, key_id=tm["key_id"][:62])
    sig_null = dict(base_refusal(), key_id=RESPONDER.public_hex, sig=None)
    unregistered = dict(base_refusal(), reason="not-a-registered-reason", key_id=RESPONDER.public_hex)
    unregistered["sig"] = sign(RESPONDER, three_member_input(unregistered))

    wr = whole(detail="declined by policy")
    wr_unsigned = base_refusal()
    wr_key_only = dict(base_refusal(), key_id=RESPONDER.public_hex)
    wr_sig_only = {k: v for k, v in wr.items() if k != "key_id"}
    wr_added = dict(wr, detail="changed after signing")
    wr_key_swapped = dict(wr, key_id=OTHER.public_hex)
    both = dict(base_refusal(), key_id=RESPONDER.public_hex, sig="ab" * 64)
    both["signature"] = sign(RESPONDER, whole_input(both))
    wr_array = whole(reason=["policy_declined"])
    wr_minimal = {"key_id": RESPONDER.public_hex}
    wr_minimal["signature"] = sign(RESPONDER, whole_input(wr_minimal))
    wr_values = whole(attempt=2, detail={"lang": "en", "text": "declined"})
    wr_float = dict(base_refusal(), key_id=RESPONDER.public_hex, attempt=1.5)
    wr_float["signature"] = sign(RESPONDER, json.dumps({k: v for k, v in wr_float.items()}, sort_keys=True,
                                                       separators=(",", ":")).encode())
    wr_proto = whole(__proto__="signed member")
    wr_proto_changed = dict(wr_proto, __proto__="changed after signing")
    three_member_sig_as_whole = dict(base_refusal(), key_id=RESPONDER.public_hex,
                                     signature=sign(RESPONDER, three_member_input(base_refusal())))

    return [
        case("three-member-verified", "refusal", tm, TM, VERIFIED,
             "A refusal carrying sig and no signature: three-member-refusal/v1. sig is the responder's Ed25519 "
             "signature over the JCS of {issued_at, reason, request_digest}, the signing input of an "
             "evidence-interop/0 or /1 signed refusal.", signing_input=three_member_input(tm)),
        case("three-member-extra-members", "refusal", extra, TM, VERIFIED,
             "As three-member-verified, also carrying detail and another member. Neither is signed in this "
             "profile, so the signature still verifies.", signing_input=three_member_input(extra)),
        case("refusal-with-policy-digest", "refusal", v2, None, UNVERIFIED,
             "An evidence-interop/2 refusal: sig, no signature, and policy_digest, signed over the four members "
             "policy_digest included. A refusal carrying sig, no signature and policy_digest is in none of these "
             "profiles, so it is signature-unverified, never read as a three-member refusal and reported "
             "invalid."),
        case("whole-refusal-with-policy-digest", "refusal", wr_policy, WR, VERIFIED,
             "A refusal carrying signature and policy_digest is in whole-refusal/v1, which signs policy_digest "
             "like every other member.", signing_input=whole_input(wr_policy)),
        case("three-member-empty-reason", "refusal", empty, TM, VERIFIED,
             "reason is the empty string, signed. An empty string is a string, and the signature state covers "
             "the signature alone, not whether reason is a registered token.",
             signing_input=three_member_input(empty)),
        case("three-member-unregistered-reason", "refusal", unregistered, TM, VERIFIED,
             "reason is not a registered token. The signature verifies; verified does not make the refusal "
             "conforming to Evidence Request.", signing_input=three_member_input(unregistered)),
        case("three-member-tampered", "refusal", tampered, TM, INVALID,
             "As three-member-verified, with reason changed after signing."),
        case("three-member-other-key", "refusal", other_key, TM, INVALID,
             "As three-member-verified, with key_id replaced by another key: the signature does not verify "
             "under the key the refusal carries."),
        case("three-member-reason-not-string", "refusal", nonstring, TM, INVALID,
             "reason is an array, signed as such. A signed member that is not a string is invalid, even though "
             "the signature verifies over the JCS of the members as carried."),
        case("three-member-missing-issued-at", "refusal", missing, TM, INVALID,
             "issued_at is absent; sig is over the JCS of the two members present. A signed member that is "
             "absent is invalid."),
        case("three-member-sig-without-key", "refusal", sig_only, TM, INVALID,
             "sig without key_id: a signature without a key is invalid. The refusal carries sig, so it is in "
             "three-member-refusal/v1 and never signature-unverified."),
        case("three-member-uppercase-sig", "refusal", upper, TM, INVALID,
             "As three-member-verified, with sig in uppercase hexadecimal: not of the stated form."),
        case("three-member-short-key", "refusal", short_key, TM, INVALID,
             "key_id is 62 hexadecimal characters: not of the stated form."),
        case("three-member-sig-null", "refusal", sig_null, TM, INVALID,
             "sig is JSON null. Presence decides the profile, so the refusal is in three-member-refusal/v1; "
             "null is not a string of the stated form, so it is invalid."),
        case("whole-refusal-verified", "refusal", wr, WR, VERIFIED,
             "A refusal carrying signature: whole-refusal/v1. signature is over the JCS of the refusal without "
             "signature, so key_id and detail are signed.", signing_input=whole_input(wr)),
        case("whole-refusal-unsigned", "refusal", wr_unsigned, WR, UNVERIFIED,
             "A refusal carrying none of sig, key_id and signature: whole-refusal/v1, with no signature to check."),
        case("whole-refusal-key-without-signature", "refusal", wr_key_only, WR, INVALID,
             "key_id without signature or sig: a key carried without a signature is invalid."),
        case("whole-refusal-signature-without-key", "refusal", wr_sig_only, WR, INVALID,
             "As whole-refusal-verified, without key_id."),
        case("whole-refusal-member-changed", "refusal", wr_added, WR, INVALID,
             "As whole-refusal-verified, with detail changed after signing: every member is signed."),
        case("whole-refusal-key-swapped", "refusal", wr_key_swapped, WR, INVALID,
             "As whole-refusal-verified, with key_id replaced by another key."),
        case("whole-refusal-carries-sig-and-signature", "refusal", both, WR, VERIFIED,
             "A refusal carrying both sig and signature is in whole-refusal/v1. sig is then an ordinary member, "
             "covered by signature.", signing_input=whole_input(both)),
        case("whole-refusal-non-string-member", "refusal", wr_array, WR, VERIFIED,
             "reason is an array, signed. whole-refusal/v1 signs the object as carried, whatever its members' "
             "values, so it verifies; the string rule belongs to the three-member and digest-bound profiles.",
             signing_input=whole_input(wr_array)),
        case("whole-refusal-integer-and-object-members", "refusal", wr_values, WR, VERIFIED,
             "Carries an integer member and an object member, both signed: any JSON value JCS can serialize "
             "is signed as carried.", signing_input=whole_input(wr_values)),
        case("whole-refusal-float-member", "refusal", wr_float, WR, INVALID,
             "Carries the number 1.5, which JCS cannot represent in this document's integer-only profile, so "
             "the signing input has no JCS serialization and the signature is invalid (as for "
             "category_coverage_signature). sig is over a sorted compact serialization that writes 1.5."),
        case("whole-refusal-only-key-and-signature", "refusal", wr_minimal, WR, VERIFIED,
             "A refusal carrying only key_id and signature, signed over {key_id}. whole-refusal/v1 names no "
             "required member, so it verifies; whether the refusal conforms to Evidence Request is a separate "
             "check.", signing_input=whole_input(wr_minimal)),
        case("whole-refusal-proto-member", "refusal", wr_proto, WR, VERIFIED,
             "As whole-refusal-verified, also carrying a member named __proto__, which is signed like any other "
             "(an implementation that copies members by plain assignment in JavaScript would drop it).",
             signing_input=whole_input(wr_proto)),
        case("whole-refusal-proto-member-changed", "refusal", wr_proto_changed, WR, INVALID,
             "As whole-refusal-proto-member, with __proto__ changed after signing."),
        case("whole-refusal-three-member-signature", "refusal", three_member_sig_as_whole, WR, INVALID,
             "signature is a valid three-member signature (over issued_at, reason and request_digest), carried "
             "as signature: the refusal is in whole-refusal/v1, whose signing input also covers key_id, so it "
             "does not verify."),
    ]


def response_cases() -> list[dict]:
    db = response()
    with_extras = dict(db, type="something-else", artifact="ignored", note="unsigned")
    unsigned = base_response()
    responder = dict(db, responder=RESPONDER.public_hex)
    responder_null = dict(db, responder=None)
    key_only = dict(base_response(), key_id=RESPONDER.public_hex)
    sig_only = {k: v for k, v in db.items() if k != "key_id"}
    tampered = dict(db, anchor=composed.sha256_hex(b"another anchor"))
    missing = {k: v for k, v in db.items() if k != "artifact_kind"}
    nonstring = dict(base_response(), issued_at=1795411300, key_id=RESPONDER.public_hex)
    nonstring["sig"] = sign(RESPONDER, composed.jcs({"type": ARTIFACT_RESPONSE_TYPE, **{
        k: nonstring[k] for k in ("request_digest", "anchor", "artifact_kind", "artifact_digest", "issued_at")}}))
    no_type = dict(base_response(), key_id=RESPONDER.public_hex)
    no_type["sig"] = sign(RESPONDER, composed.jcs(base_response()))
    return [
        case("response-verified", "response", db, DB, VERIFIED,
             "A response carrying no responder: digest-bound-artifact-response/v1. sig is over the JCS of the "
             "five members plus type evidence-artifact-response/v1, which the verifier supplies.",
             signing_input=response_input(db)),
        case("response-carried-type-artifact-and-extra", "response", with_extras, DB, VERIFIED,
             "As response-verified, also carrying type with another value, artifact and an extra member. type is "
             "never read from the object, and neither is any other unsigned member.",
             signing_input=response_input(with_extras)),
        case("response-unsigned", "response", unsigned, DB, UNVERIFIED,
             "A response carrying neither key_id nor sig: no signature to check."),
        case("response-carries-responder", "response", responder, None, UNVERIFIED,
             "As response-verified, also carrying responder: in none of these profiles (for example an "
             "interop envelope), so signature-unverified, whatever else it carries."),
        case("response-responder-null", "response", responder_null, None, UNVERIFIED,
             "As response-carries-responder, with responder JSON null: presence decides."),
        case("response-key-without-sig", "response", key_only, DB, INVALID,
             "key_id without sig: invalid."),
        case("response-sig-without-key", "response", sig_only, DB, INVALID,
             "As response-verified, without key_id: invalid."),
        case("response-tampered", "response", tampered, DB, INVALID,
             "As response-verified, with anchor changed after signing."),
        case("response-missing-artifact-kind", "response", missing, DB, INVALID,
             "As response-verified, without artifact_kind: a signed member that is absent is invalid."),
        case("response-issued-at-not-string", "response", nonstring, DB, INVALID,
             "issued_at is a number, signed as such: a signed member that is not a string is invalid."),
        case("response-signed-without-type", "response", no_type, DB, INVALID,
             "sig is over the JCS of the five members without type: the signing input always includes type, "
             "so it does not verify."),
    ]


# --- composed cases ------------------------------------------------------------------------------


def refusal_member(member_id: str, observer: str, refusal: dict) -> dict:
    return {"id": member_id, "observer": observer, "request_digest": refusal["request_digest"],
            "outcome": "refusal", "digest": composed.sha256_hex(composed.jcs(refusal)), "refusal": refusal}


def refused_composition(refusal_of: Any) -> dict:
    members, observers = composed.two_responders()
    request_digest = members[1]["request_digest"]
    members[1] = refusal_member("responder-b", "obs-b", refusal_of(request_digest))
    return composed.container(composed.block(members, observers,
                                             [composed.join("responder-a", "responder-b", "one_sided")]))


def responded_composition(tamper: bool) -> dict:
    members, observers = composed.two_responders()
    a = members[0]
    signed = {"request_digest": a["request_digest"], "anchor": ANCHOR, "artifact_kind": "evidence-bundle/v2",
              "artifact_digest": a["digest"], "issued_at": ISSUED_AT, "key_id": RESPONDER.public_hex}
    signed["sig"] = sign(RESPONDER, response_input(signed))
    if tamper:
        signed["issued_at"] = "2026-11-22T12:00:01Z"
    a["response"] = signed
    return composed.container(composed.block(members, observers,
                                             [composed.join("responder-a", "responder-b", "agree")]))


def composed_cases() -> list[dict]:
    def signed_refusal(digest: str) -> dict:
        refusal = {"request_digest": digest, "reason": "policy_declined", "issued_at": ISSUED_AT,
                   "key_id": OTHER.public_hex}
        refusal["sig"] = sign(OTHER, three_member_input(refusal))
        return refusal

    def tampered_refusal(digest: str) -> dict:
        return dict(signed_refusal(digest), reason="not_authorized")

    def unsigned_refusal(digest: str) -> dict:
        return {"request_digest": digest, "reason": "policy_declined", "issued_at": ISSUED_AT}

    def member(signature_kind: str, state: str) -> dict:
        return {"responder-b" if signature_kind == "refusal_signature" else "responder-a": {signature_kind: state}}

    return [
        {"id": "composed-refusal-verified", "section": [SECTION, S_MEMBERS],
         "description": "responder-a granted a Bundle; responder-b refused with a three-member-refusal/v1 "
                        "refusal whose signature verifies. Verified with both profile verifiers set: the refusal "
                        "signature is verified, nothing is withheld, and a refusal is not a failed claim.",
         "container": refused_composition(signed_refusal),
         "expect": {"status": "pass", "findings": [], "members": member("refusal_signature", VERIFIED)}},
        {"id": "composed-refusal-invalid", "section": [SECTION, S_MEMBERS],
         "description": "As composed-refusal-verified, with the refusal's reason changed after signing (the "
                        "member digest recomputed over the refusal as carried): the refusal signature is invalid, "
                        "so the block fails.",
         "container": refused_composition(tampered_refusal),
         "expect": {"status": "fail", "findings": ["refusal_signature_invalid:responder-b"],
                    "members": member("refusal_signature", INVALID)}},
        {"id": "composed-refusal-unsigned", "section": [SECTION, S_MEMBERS],
         "description": "As composed-refusal-verified, with a refusal that carries no key and no signature "
                        "(whole-refusal/v1, nothing to check): signature-unverified, so the block is withheld.",
         "container": refused_composition(unsigned_refusal),
         "expect": {"status": "withheld", "findings": ["refusal_signature_unverified:responder-b"],
                    "members": member("refusal_signature", UNVERIFIED)}},
        {"id": "composed-response-verified", "section": [SECTION, S_MEMBERS],
         "description": "The agree composition, with responder-a carrying a digest-bound-artifact-response/v1 "
                        "response bound to its request and its Bundle, signed by responder-a's key: verified, and "
                        "the block passes.",
         "container": responded_composition(False),
         "expect": {"status": "pass", "findings": [], "members": member("response_signature", VERIFIED)}},
        {"id": "composed-response-invalid", "section": [SECTION, S_MEMBERS],
         "description": "As composed-response-verified, with issued_at changed after signing: the response "
                        "signature is invalid, so the block fails.",
         "container": responded_composition(True),
         "expect": {"status": "fail", "findings": ["response_signature_invalid:responder-a"],
                    "members": member("response_signature", INVALID)}},
    ]


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    objects = refusal_cases() + response_cases() + forgery_cases()
    blocks = composed_cases()
    files = {
        "vectors.json": _dump({
            "draft": DRAFT,
            "provenance": "spec-derived",
            "profiles": [TM, WR, DB],
            "states": [VERIFIED, INVALID, UNVERIFIED],
            "keys": {k.name: {"seed_hex": k.seed.hex(), "public_key_hex": k.public_hex} for k in (RESPONDER, OTHER)},
            "count": len(objects) + len(blocks),
            "cases": objects,
            "composed_cases": blocks,
        }),
    }
    files["manifest.json"] = _dump({
        "draft": DRAFT,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_bundle_composed_signature_profile_vectors.py",
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
