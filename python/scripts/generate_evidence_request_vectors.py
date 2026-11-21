#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the draft-mih-agent-evidence-request conformance vectors.

Every expected result below is written by hand from the text of
``spec/draft-mih-agent-evidence-request-00.md``, or of the later revision a
corpus names in its ``draft`` member, and cites the section it comes
from. Nothing here imports or runs an implementation of the interaction: the
script only encodes the literal inputs (JSON per RFC 8785, CBOR per RFC 8949
section 4.2.1), hashes them, and signs the refusal cases with a fixed Ed25519
key. Where -00 leaves a choice open, the case carries an ``ambiguity`` note and
the README lists it for -01.

Output: ``vectors/evidence-request/`` (or ``--out DIR``). The run is a pure
function of this file: no clock, no randomness. ``README.md`` and ``DIFFS.md``
are hand-written; when present in the output directory they are included in
``SHA256SUMS`` but never rewritten.

Dependencies: the standard library and ``cryptography`` (Ed25519 only).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "evidence-request"
DRAFT = "draft-mih-agent-evidence-request-00"
# Corpora written from text that first appears in -01 name that revision. The
# -00 corpora keep DRAFT, which also seeds the refusal keys.
DRAFT_01 = "draft-mih-agent-evidence-request-01"
DRAFT_02 = "draft-mih-agent-evidence-request-02"

# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------


def _check_json_value(value: Any) -> None:
    if isinstance(value, float):
        raise TypeError("the vectors use no floating-point numbers")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise TypeError("map keys in these vectors are ASCII text")
            _check_json_value(item)
    elif isinstance(value, list):
        for item in value:
            _check_json_value(item)


def jcs(value: Any) -> str:
    """RFC 8785 for the value space these vectors use (no floats, ASCII keys).

    With ASCII keys, UTF-16 code-unit order equals code-point order, so
    ``sort_keys`` is the RFC 8785 member order; the separators and string
    escaping of ``json.dumps(ensure_ascii=False)`` match RFC 8785 for these
    values.
    """
    _check_json_value(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24]) + n.to_bytes(1, "big")
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def cbor(value: Any, *, sort_keys: bool = True) -> bytes:
    """CBOR, RFC 8949 section 4.2.1 core deterministic encoding.

    Preferred (shortest) argument encoding, definite lengths only, and map
    keys sorted by the bytewise lexicographic order of their deterministic
    encodings. ``sort_keys=False`` keeps insertion order and exists only to
    build the deliberately non-deterministic digest case.
    """
    if value is None:
        return b"\xf6"
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if isinstance(value, int):
        return _cbor_head(0, value) if value >= 0 else _cbor_head(1, -1 - value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, list):
        return _cbor_head(4, len(value)) + b"".join(cbor(v, sort_keys=sort_keys) for v in value)
    if isinstance(value, dict):
        pairs = [(cbor(k, sort_keys=sort_keys), cbor(v, sort_keys=sort_keys)) for k, v in value.items()]
        if sort_keys:
            pairs.sort(key=lambda kv: kv[0])
        return _cbor_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    raise TypeError(f"no CBOR encoding for {type(value).__name__} in these vectors")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def label_digest(label: str) -> str:
    """A fixed, reproducible 32-byte digest used as an example value."""
    return sha256_hex(f"{DRAFT} example: {label}".encode())


# ---------------------------------------------------------------------------
# Keys and the refusal signature profile
# ---------------------------------------------------------------------------

PRIMARY_SEED = hashlib.sha256(f"{DRAFT} conformance vectors: primary responder key".encode()).digest()
OTHER_SEED = hashlib.sha256(f"{DRAFT} conformance vectors: other key".encode()).digest()


def _key(seed: bytes) -> tuple[Ed25519PrivateKey, str]:
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return private, public


PRIMARY, PRIMARY_PUB = _key(PRIMARY_SEED)
OTHER, OTHER_PUB = _key(OTHER_SEED)

REASONS = [
    "not_authorized",
    "no_such_subject",
    "coverage_unsatisfiable",
    "derivation_unsupported",
    "policy_declined",
    "deadline_unmet",
    "request_malformed",
    "retention_expired",
]
SUBJECT_FORMS = ["full_history", "checkpoints", "record", "range", "correlation", "exchange"]
ISSUED_AT = "2026-09-28T00:00:00Z"

SIGNATURE_PROFILE = {
    "note": (
        "-00 section 4.2 item 4 leaves the signature format to the deployment. These vectors use "
        "one profile, the one the existing cross-implementation refusal vector already uses: "
        "Ed25519 (RFC 8032) over the RFC 8785 serialization of the JSON object with exactly the "
        "members issued_at, reason and request_digest; key_id is the raw 32-byte public key and "
        "sig the 64-byte signature, both lowercase hex."
    ),
    "algorithm": "Ed25519",
    "signed_members": ["issued_at", "reason", "request_digest"],
    "signing_body": "RFC 8785 (JCS) of the signed members",
    "key_id": "raw Ed25519 public key, lowercase hex",
    "sig": "Ed25519 signature, lowercase hex",
}


def sign_body(body: dict, private: Ed25519PrivateKey = PRIMARY) -> str:
    return private.sign(jcs(body).encode("utf-8")).hex()


def refusal(request_digest: Any, reason: Any, issued_at: Any = ISSUED_AT, detail: str | None = None) -> dict:
    """A refusal object signed with the primary key over the three members.
    ``detail`` is carried outside the signed members."""
    body = {"issued_at": issued_at, "reason": reason, "request_digest": request_digest}
    out = {**body, "key_id": PRIMARY_PUB, "sig": sign_body(body)}
    if detail:
        out["detail"] = detail
    return out


# The refusal vector that three implementations already verify (Python signed it;
# Rust and Go verify it). Reproduced byte for byte; see refusal.json case
# pos-imported-interop-vector.
IMPORTED_REFUSAL_BYTES = (
    b"{\n"
    b' "issued_at": "2026-09-26T12:00:00Z",\n'
    b' "key_id": "1a965c7d75b9a6b82aea451a40c7de9b770933afb1297d7803b83254b208a863",\n'
    b' "reason": "no_such_subject",\n'
    b' "request_digest": "abababababababababababababababababababababababababababababababab",\n'
    b' "sig": "02d05ae646f078851b834cb27c20aa869bfe78bfe13450fc81b766054f588e3cd3c2a1bd47c4b4234b1c3ecd9a53821e27160228a2842d8330bed7258a898500"\n'
    b"}\n"
)
IMPORTED_REFUSAL_SHA256 = "885d7981f8fd8a22bffd61c5bd10444515e12ea009fa9d70170bb467c7e5a66e"

# ---------------------------------------------------------------------------
# Example values (all fixed)
# ---------------------------------------------------------------------------

R1 = label_digest("record 1")
R2 = label_digest("record 2")
R3 = label_digest("record 3")
R_UNKNOWN = label_digest("record never written")
HALF = label_digest("requester's own exchange half")
HALF_UNKNOWN = label_digest("an exchange half nobody cites")
HALF_OTHER = label_digest("another exchange's half")
ANCHOR_40 = label_digest("checkpoint at size 40")
ANCHOR_42 = label_digest("checkpoint at size 42")
ANCHOR_UNKNOWN = label_digest("a checkpoint this responder never issued")
DERIVATION_DEF = label_digest("definition of a count over a declared field set")
CORRELATION = "c-7d1e9a40"

AMBIGUITY = {
    "A1": "§3.1 Subject: -00 gives six forms and their content but no wire shape. Vectors use a map "
    "with exactly one member, named by the form token, whose value is the content: null for "
    "full_history and checkpoints, a digest for record and exchange, [a, b] (two unsigned integers) "
    "for range, a text string for correlation.",
    "A2": "§3.1, §3.2, §4.2: -00 names digests but not the hash algorithm or representation. Vectors "
    "use SHA-256 as 64 lowercase hex characters, as text in both the JSON and CBOR bindings.",
    "A3": "§3.2 Coverage: min_freshness is 'size or time' with no shape. Vectors read the value "
    "itself: an unsigned integer is a log size, a text string is an RFC 3339 UTC time. Any other "
    "type is not a conforming value.",
    "A4": "§3 / §3.2: coverage_unsatisfiable is assigned for 'both, or neither'. Vectors read an "
    "absent coverage field as 'neither' (coverage_unsatisfiable), and a coverage value that is not "
    "a map, or a member whose value does not conform, as request_malformed.",
    "A5": "§3.4-§3.6: deadline, nonce and route have no stated type. Vectors use text strings "
    "(deadline as an RFC 3339 UTC time).",
    "A6": "§3.1 range: -00 does not say whether a > b is malformed. Vectors treat it as a value "
    "that does not conform (request_malformed).",
    "A7": "§4.2 / §10: -00 names the refusal's contents but no member names or signature format. "
    "Vectors use request_digest, reason, issued_at, key_id and sig with the signature profile in "
    "refusal.json. In the CBOR binding the same map is the frame; the signature is still over the "
    "RFC 8785 body.",
    "A8": "§4.3 / §10: the stream binding says absence is 'the stream closed or timed out without a "
    "response frame'; §4.3 says only the close of the waiting window resolves a request. Vectors "
    "follow §4.3: a transport failure inside the window leaves the request pending.",
    "A9": "§9: -00 lists retention_expired only as the correct refusal after until. Inside until, "
    "vectors apply the literal 'any other refusal reason' rule: it is a breach.",
    "A10": "§9: after until, -00 names only retention_expired as correct. Vectors class the four "
    "request/capability reasons, policy_declined and deadline_unmet as no breach, and "
    "no_such_subject as the wrong token (the lapsed promise must not read as never held, §4.2 "
    "item 2).",
    "A11": "§9: 'a digest or a position under a checkpoint'. Vectors read full_history, checkpoints "
    "and correlation subjects in a commitment as malformed.",
    "A12": "§4.1: the artifact envelope has no member names. Invariance cases compare artifact bytes "
    "only; the observation members are local to these vectors.",
    "A13": "§4.2 item 2 / §4.5: -00 does not say what a correctly signed object with an "
    "unregistered reason is. Vectors: not a conforming refusal, and still never recorded as "
    "absence.",
    "A14": "§3.3: a registered derivation token and the digest of a definition share one field. "
    "Vectors tell them apart by form: a token has a '/N' suffix, a digest is 64 lowercase hex.",
}

# A4 amendment (spec ruling 2026-10-06). Kept out of AMBIGUITY["A4"] so the
# cases shipped in 0.6.0 keep their bytes; the README carries the amended A4.
A4_PRECEDENCE = (
    "A4 (amended 2026-10-06): -00 does not state which refusal wins when coverage carries both "
    "members and a value does not conform. A responder first checks that each member present in "
    "coverage has a conforming value; a non-conforming value is refused request_malformed, whether "
    "or not the other member is present. Only then is coverage carrying both members, or neither, "
    "refused coverage_unsatisfiable."
)

# ---------------------------------------------------------------------------
# request.json: the request map
# ---------------------------------------------------------------------------

PIN_42 = {"expected_pin": ANCHOR_42}


def _req(subject: Any, coverage: Any = None, **extra: Any) -> dict:
    out: dict[str, Any] = {"subject": subject}
    if coverage is not None:
        out["coverage"] = coverage
    out.update(extra)
    return out


WELL_FORMED = {"well_formed": True}


def MALFORMED(reason: str) -> dict:  # noqa: N802 - reads as a constant at call sites
    return {"well_formed": False, "reason": reason}


def request_case(
    case_id: str,
    section: list[str],
    description: str,
    value: Any = None,
    expect: dict | None = None,
    *,
    json_text: str | None = None,
    cbor_hex: str | None = None,
    ambiguity: str | None = None,
    json_only: bool = False,
) -> dict:
    case: dict[str, Any] = {"id": case_id, "section": section, "description": description}
    if json_text is None and value is not None:
        json_text = jcs(value)
    if json_text is not None:
        case["request_json"] = json_text
        case["request_json_digest"] = sha256_hex(json_text.encode("utf-8"))
    if cbor_hex is None and value is not None and not json_only:
        cbor_hex = cbor(value).hex()
    if cbor_hex is not None:
        case["request_cbor_hex"] = cbor_hex
        case["request_cbor_digest"] = sha256_hex(bytes.fromhex(cbor_hex))
    case["expect"] = expect
    if ambiguity:
        case["ambiguity"] = ambiguity
    return case


S_REQ = "§3 The Request"
S_SUBJ = "§3.1 Subject"
S_COV = "§3.2 Coverage"
S_DER = "§3.3 Derivation"
S_DEADLINE = "§3.4 Deadline"
S_NONCE = "§3.5 Nonce"
S_ROUTE = "§3.6 Route"
S_RECREQ = "§3.8 Recording the Request"
S_CAT = "§3.9 Categories"
S_OUT = "§4 Interaction Outcomes"
S_ART = "§4.1 The Artifact Response"
S_REF = "§4.2 The Signed Refusal"
S_PEND = "§4.3 Pending"
S_ABS = "§4.4 Recorded Absence"
S_DISC = "§4.5 The Three-State Discipline"
S_INV = "§5 Caller Invariance"
S_HC = "§8.1 The History Card"
S_RET = "§9 Retention Commitments"
S_BIND = "§10 Transport Bindings"
S_CARRY = "§10.1 Carriage Rules"
S_A2A = "§10.2 A2A Binding"
S_MCP = "§10.3 MCP Binding"
S_PRIV = "§12 Privacy Considerations"
S_IANA = "§13 IANA Considerations"


def request_cases() -> list[dict]:
    c = request_case
    a1 = AMBIGUITY["A1"]
    cases = [
        c("pos-subject-full_history", [S_REQ, S_SUBJ, S_COV],
          "full_history subject under an expected_pin.",
          _req({"full_history": None}, PIN_42, nonce="n-0001"), WELL_FORMED, ambiguity=a1),
        c("pos-subject-checkpoints", [S_REQ, S_SUBJ, S_COV],
          "checkpoints subject under an expected_pin.",
          _req({"checkpoints": None}, PIN_42, nonce="n-0002"), WELL_FORMED, ambiguity=a1),
        c("pos-subject-record", [S_REQ, S_SUBJ, S_COV],
          "record subject named by digest, under an expected_pin.",
          _req({"record": R1}, PIN_42, nonce="n-0003"), WELL_FORMED, ambiguity=a1),
        c("pos-subject-range", [S_REQ, S_SUBJ, S_COV],
          "range subject, positions 0 through 2 inclusive, under a size min_freshness.",
          _req({"range": [0, 2]}, {"min_freshness": 42}, nonce="n-0004"), WELL_FORMED,
          ambiguity=a1 + " " + AMBIGUITY["A3"]),
        c("pos-subject-correlation", [S_REQ, S_SUBJ, S_COV],
          "correlation subject under a time min_freshness.",
          _req({"correlation": CORRELATION}, {"min_freshness": "2026-09-27T00:00:00Z"}, nonce="n-0005"),
          WELL_FORMED, ambiguity=a1 + " " + AMBIGUITY["A3"]),
        c("pos-subject-exchange", [S_REQ, S_SUBJ, S_COV, "§6 The Symmetric Ask"],
          "exchange subject naming the requester's own half, pinned on that same half "
          "(§3.2: a requester's own exchange half is a valid pin for an exchange subject).",
          _req({"exchange": HALF}, {"expected_pin": HALF}, nonce="n-0006"), WELL_FORMED, ambiguity=a1),
        c("pos-nonce-absent", [S_REQ, S_NONCE],
          "nonce is RECOMMENDED, not REQUIRED: subject and coverage alone are well formed.",
          _req({"record": R1}, PIN_42), WELL_FORMED),
        c("pos-all-optional-fields", [S_REQ, S_DER, S_DEADLINE, S_NONCE, S_ROUTE],
          "Every defined field present.",
          _req({"checkpoints": None}, PIN_42, derivation="history_card/1",
               deadline="2026-09-28T00:05:00Z", nonce="n-0007", route="https://responder.example/evidence"),
          WELL_FORMED, ambiguity=AMBIGUITY["A5"]),
        c("pos-unknown-field-ignored", [S_REQ],
          "A responder MUST ignore request fields it does not understand.",
          _req({"record": R1}, PIN_42, nonce="n-0008", page={"size": 10}), WELL_FORMED),
        c("pos-derivation-history-card", [S_DER, S_HC, S_IANA],
          "The registered derivation token history_card/1.",
          _req({"full_history": None}, PIN_42, derivation="history_card/1", nonce="n-0009"), WELL_FORMED),
        c("pos-derivation-by-digest", [S_DER],
          "A derivation named by the digest of its definition.",
          _req({"record": R1}, PIN_42, derivation=DERIVATION_DEF, nonce="n-0010"), WELL_FORMED,
          ambiguity=AMBIGUITY["A14"]),
        # --- request_malformed ------------------------------------------------
        c("neg-not-a-map", [S_REQ],
          "A request that is not a map (an array) is refused request_malformed.",
          [{"record": R1}, PIN_42], MALFORMED("request_malformed")),
        c("neg-not-well-formed", [S_REQ],
          "Bytes that are not well-formed JSON / CBOR are refused request_malformed.",
          None, MALFORMED("request_malformed"), json_text='{"subject":', cbor_hex="a2"),
        c("neg-subject-missing", [S_REQ],
          "Missing the REQUIRED subject field.",
          {"coverage": PIN_42, "nonce": "n-0011"}, MALFORMED("request_malformed")),
        c("neg-subject-unknown-form", [S_REQ, S_SUBJ],
          "A subject form outside the six (chain_segment) does not conform.",
          _req({"chain_segment": [0, 2]}, PIN_42, nonce="n-0012"), MALFORMED("request_malformed"),
          ambiguity=a1),
        c("neg-subject-two-forms", [S_REQ, S_SUBJ],
          "A subject naming two forms at once does not conform.",
          _req({"record": R1, "correlation": CORRELATION}, PIN_42, nonce="n-0013"),
          MALFORMED("request_malformed"), ambiguity=a1),
        c("neg-subject-kind-member", [S_REQ, S_SUBJ],
          "A subject shaped {kind, <id>} carries no form token as a member, so it does not conform "
          "under the A1 reading.",
          _req({"kind": "record", "capsule_id": R1}, PIN_42, nonce="n-0014"),
          MALFORMED("request_malformed"), ambiguity=a1),
        c("neg-subject-none-form-with-content", [S_REQ, S_SUBJ],
          "full_history carries no content; a value other than null does not conform.",
          _req({"full_history": "everything"}, PIN_42, nonce="n-0015"), MALFORMED("request_malformed"),
          ambiguity=a1),
        c("neg-record-digest-malformed", [S_REQ, S_SUBJ],
          "A record digest that is not 64 lowercase hex characters does not conform.",
          _req({"record": "zz" + R1[2:]}, PIN_42, nonce="n-0016"), MALFORMED("request_malformed"),
          ambiguity=AMBIGUITY["A2"]),
        c("neg-record-digest-prefix", [S_REQ, S_SUBJ],
          "A 16-character prefix of a held record's digest is not a digest: never resolved by "
          "prefix (§3.1: no fuzzy or best-effort matching).",
          _req({"record": R1[:16]}, PIN_42, nonce="n-0017"), MALFORMED("request_malformed"),
          ambiguity=AMBIGUITY["A2"]),
        c("neg-range-reversed", [S_REQ, S_SUBJ],
          "range with a > b.",
          _req({"range": [5, 2]}, PIN_42, nonce="n-0018"), MALFORMED("request_malformed"),
          ambiguity=AMBIGUITY["A6"]),
        c("neg-range-not-a-pair", [S_REQ, S_SUBJ],
          "range content that is not a pair of positions.",
          _req({"range": "0..2"}, PIN_42, nonce="n-0019"), MALFORMED("request_malformed"), ambiguity=a1),
        c("neg-derivation-not-text", [S_REQ, S_DER],
          "derivation that is neither a registered token nor a digest.",
          _req({"record": R1}, PIN_42, derivation=7, nonce="n-0020"), MALFORMED("request_malformed"),
          ambiguity=AMBIGUITY["A14"]),
        c("neg-expected-pin-malformed-digest", [S_REQ, S_COV],
          "expected_pin whose value is not a digest.",
          _req({"record": R1}, {"expected_pin": ANCHOR_42[:40]}, nonce="n-0021"),
          MALFORMED("request_malformed"), ambiguity=AMBIGUITY["A4"]),
        c("neg-expected-pin-map", [S_REQ, S_COV],
          "expected_pin given as a map {root, mmr_size}; -00 defines it as a digest.",
          _req({"record": R1}, {"expected_pin": {"root": ANCHOR_42, "mmr_size": 42}}, nonce="n-0022"),
          MALFORMED("request_malformed"), ambiguity=AMBIGUITY["A4"]),
        c("neg-min-freshness-max-age", [S_REQ, S_COV],
          "min_freshness given as {max_age_seconds}; -00 defines it as a size or a time.",
          _req({"record": R1}, {"min_freshness": {"max_age_seconds": 60}}, nonce="n-0023"),
          MALFORMED("request_malformed"), ambiguity=AMBIGUITY["A3"] + " " + AMBIGUITY["A4"]),
        c("neg-coverage-not-a-map", [S_REQ, S_COV],
          "coverage whose value is not a map.",
          _req({"record": R1}, ANCHOR_42, nonce="n-0024"), MALFORMED("request_malformed"),
          ambiguity=AMBIGUITY["A4"]),
        # --- coverage_unsatisfiable: the more specific reason wins -----------
        c("neg-coverage-both", [S_REQ, S_COV],
          "coverage carrying both members MUST be refused coverage_unsatisfiable, not "
          "request_malformed.",
          _req({"record": R1}, {"expected_pin": ANCHOR_42, "min_freshness": 42}, nonce="n-0025"),
          MALFORMED("coverage_unsatisfiable")),
        c("neg-coverage-neither", [S_REQ, S_COV],
          "coverage carrying neither member MUST be refused coverage_unsatisfiable.",
          _req({"record": R1}, {}, nonce="n-0026"), MALFORMED("coverage_unsatisfiable")),
        c("neg-coverage-missing", [S_REQ, S_COV],
          "No coverage field: the REQUIRED field is missing and the request carries neither member.",
          {"subject": {"record": R1}, "nonce": "n-0027"}, MALFORMED("coverage_unsatisfiable"),
          ambiguity=AMBIGUITY["A4"]),
        # --- both members, one or both malformed: request_malformed wins -----
        # (A4 as amended 2026-10-06; AMBIGUITY["A4"] itself is left as shipped
        # in 0.6.0 so the existing cases keep their bytes.)
        c("neg-coverage-both-pin-malformed", [S_REQ, S_COV],
          "coverage carrying both members where expected_pin is not a digest: the "
          "non-conforming value is refused request_malformed before the member count is checked.",
          _req({"record": R1}, {"expected_pin": "not-a-digest", "min_freshness": 42}, nonce="n-0028"),
          MALFORMED("request_malformed"), ambiguity=A4_PRECEDENCE),
        c("neg-coverage-both-freshness-malformed", [S_REQ, S_COV],
          "coverage carrying both members where min_freshness is {max_age_seconds}: the "
          "non-conforming value is refused request_malformed before the member count is checked.",
          _req({"record": R1}, {"expected_pin": ANCHOR_42, "min_freshness": {"max_age_seconds": 60}},
               nonce="n-0029"),
          MALFORMED("request_malformed"), ambiguity=AMBIGUITY["A3"] + " " + A4_PRECEDENCE),
        c("neg-coverage-both-both-malformed", [S_REQ, S_COV],
          "coverage carrying both members, neither of which conforms: refused request_malformed.",
          _req({"record": R1}, {"expected_pin": "not-a-digest", "min_freshness": -1}, nonce="n-0030"),
          MALFORMED("request_malformed"), ambiguity=AMBIGUITY["A3"] + " " + A4_PRECEDENCE),
    ]
    return cases


# ---------------------------------------------------------------------------
# resolution.json: exact-match resolution and the most specific reason
# ---------------------------------------------------------------------------

RESPONDER = {
    "evidence_stream": "stream-a",
    "log_size": 42,
    "positional_ordering": True,
    "issues_new_commitments": False,
    "anchors": [
        {"digest": ANCHOR_40, "size": 40, "issued_at": "2026-09-26T00:00:00Z"},
        {"digest": ANCHOR_42, "size": 42, "issued_at": "2026-09-27T12:00:00Z"},
    ],
    "records": [R1, R2, R3],
    "correlations": {CORRELATION: [R1, R2]},
    "exchange_citations": {HALF: [R3]},
    "supported_derivations": {"history_card/1": ["full_history", "checkpoints"]},
    "uniform_policy_declined": False,
}


def resolution_cases() -> list[dict]:
    def c(case_id: str, section: list[str], description: str, value: dict, expect: dict,
          *, overrides: dict | None = None, ambiguity: str | None = None) -> dict:
        case = request_case(case_id, section, description, value, expect, ambiguity=ambiguity)
        if overrides:
            case["responder_overrides"] = overrides
        return case

    art = {"answer": "artifact"}

    def ref(reason: str) -> dict:
        return {"answer": "refusal", "reason": reason}

    return [
        c("res-record-exact", [S_SUBJ], "record digest held exactly: served.",
          _req({"record": R1}, PIN_42, nonce="n-0101"), art),
        c("res-record-not-held", [S_SUBJ, S_REF], "well-formed record digest not held.",
          _req({"record": R_UNKNOWN}, PIN_42, nonce="n-0102"), ref("no_such_subject")),
        c("res-record-prefix", [S_SUBJ], "prefix of a held record's digest: never matched.",
          _req({"record": R1[:8]}, PIN_42, nonce="n-0103"), ref("request_malformed"),
          ambiguity=AMBIGUITY["A2"]),
        c("res-correlation-exact", [S_SUBJ], "correlation identifier held exactly: served.",
          _req({"correlation": CORRELATION}, PIN_42, nonce="n-0104"), art),
        c("res-correlation-prefix", [S_SUBJ],
          "prefix of a held correlation identifier: no fuzzy matching.",
          _req({"correlation": CORRELATION[:6]}, PIN_42, nonce="n-0105"), ref("no_such_subject")),
        c("res-correlation-case-folded", [S_SUBJ],
          "a case-folded variant of a held correlation identifier: no best-effort matching.",
          _req({"correlation": CORRELATION.upper()}, PIN_42, nonce="n-0106"), ref("no_such_subject")),
        c("res-exchange-cited", [S_SUBJ, "§6 The Symmetric Ask"],
          "an exchange half the responder's records cite: served.",
          _req({"exchange": HALF}, {"expected_pin": HALF}, nonce="n-0107"), art),
        c("res-exchange-not-cited", [S_SUBJ, "§6 The Symmetric Ask"],
          "an exchange half no record cites.",
          _req({"exchange": HALF_UNKNOWN}, {"expected_pin": HALF_UNKNOWN}, nonce="n-0108"),
          ref("no_such_subject")),
        c("res-range-positional", [S_SUBJ], "range under a mechanism with positions: served.",
          _req({"range": [0, 2]}, PIN_42, nonce="n-0109"), art),
        c("res-range-no-positional-ordering", [S_SUBJ],
          "range under a mechanism that defines no positional ordering.",
          _req({"range": [0, 2]}, PIN_42, nonce="n-0110"), ref("coverage_unsatisfiable"),
          overrides={"positional_ordering": False}),
        c("res-pin-unknown-anchor", [S_COV], "pinned anchor the responder cannot satisfy.",
          _req({"record": R1}, {"expected_pin": ANCHOR_UNKNOWN}, nonce="n-0111"),
          ref("coverage_unsatisfiable")),
        c("res-min-freshness-size-met", [S_COV], "size floor met by the size-42 anchor.",
          _req({"record": R1}, {"min_freshness": 42}, nonce="n-0112"), art, ambiguity=AMBIGUITY["A3"]),
        c("res-min-freshness-size-unmet", [S_COV, S_PRIV],
          "size floor above every anchor: MUST refuse rather than serve under weaker coverage.",
          _req({"record": R1}, {"min_freshness": 43}, nonce="n-0113"), ref("coverage_unsatisfiable"),
          ambiguity=AMBIGUITY["A3"]),
        c("res-min-freshness-time-met", [S_COV], "time floor met by the anchor issued 2026-09-27T12:00:00Z.",
          _req({"record": R1}, {"min_freshness": "2026-09-27T00:00:00Z"}, nonce="n-0114"), art,
          ambiguity=AMBIGUITY["A3"]),
        c("res-min-freshness-time-unmet", [S_COV],
          "time floor later than every anchor, and the responder issues no new commitment.",
          _req({"record": R1}, {"min_freshness": "2026-09-28T00:00:00Z"}, nonce="n-0115"),
          ref("coverage_unsatisfiable"), ambiguity=AMBIGUITY["A3"]),
        c("res-derivation-unsupported", [S_DER],
          "a derivation token the responder does not support at all.",
          _req({"full_history": None}, PIN_42, derivation="record_count/1", nonce="n-0116"),
          ref("derivation_unsupported")),
        c("res-derivation-not-for-subject", [S_DER],
          "a supported derivation, but not for this subject.",
          _req({"record": R1}, PIN_42, derivation="history_card/1", nonce="n-0117"),
          ref("no_such_subject")),
        c("res-derivation-history-card", [S_DER, S_HC], "history_card/1 over checkpoints: served.",
          _req({"checkpoints": None}, PIN_42, derivation="history_card/1", nonce="n-0118"), art),
        c("res-uniform-policy-declined", [S_REF, S_PRIV],
          "a responder whose policy answers policy_declined uniformly may do so in place of "
          "no_such_subject.",
          _req({"record": R_UNKNOWN}, PIN_42, nonce="n-0119"), ref("policy_declined"),
          overrides={"uniform_policy_declined": True}),
    ]


# ---------------------------------------------------------------------------
# carries.json: which record members carry a correlation id or cite a half
# ---------------------------------------------------------------------------

S_CARRIES = "§3.1.1 What a Record Carries"


def _layer_record(**header: Any) -> dict:
    """An Evidence Layer record header: seq, record_id, record_type, epistemic_type and links, plus ``header``."""
    return {"seq": 7, "record_id": R1, "record_type": "observation",
            "epistemic_type": "observed_event", "links": [], **header}


def _capsule_reference(citation_purpose: str, digest: str = HALF) -> dict:
    """A Capsule's ``references`` member holding one entry (by default, the half's digest)."""
    return {"references": [{"type": "agent-action-capsule", "digest_alg": "SHA-256",
                            "digest": digest, "citation_purpose": citation_purpose}]}


def carries_cases() -> list[dict]:
    def c(case_id: str, description: str, record_format: str, record: dict, subject: dict,
          expect: dict) -> dict:
        return {"id": case_id, "section": [S_CARRIES], "description": description,
                "record_format": record_format, "record": record, "subject": subject,
                "expect": expect}

    return [
        c("carries-correlation-subject-ref",
          "the identifier is the whole value of the header's subject_ref: the record carries it.",
          "evidence-layer", _layer_record(subject_ref=CORRELATION),
          {"correlation": CORRELATION}, {"carries": True}),
        c("carries-correlation-undesignated-member",
          "the identifier is the whole value of principal_ref, which the format defines as a party "
          "reference and not a correlation field, while subject_ref holds another identifier: the "
          "record does not carry it.",
          "evidence-layer", _layer_record(subject_ref="c-0b44f2e1", principal_ref=CORRELATION),
          {"correlation": CORRELATION}, {"carries": False}),
        c("cites-exchange-counterparty-half",
          "a references entry with citation_purpose counterparty_half whose digest is the half's: "
          "the record cites the half.",
          "capsule", _capsule_reference("counterparty_half"),
          {"exchange": HALF}, {"cites": True}),
        c("cites-exchange-responds-to",
          "a references entry whose digest is the half's, with citation_purpose responds_to: the "
          "record does not cite the half.",
          "capsule", _capsule_reference("responds_to"),
          {"exchange": HALF}, {"cites": False}),
        c("cites-exchange-counterparty-half-other-digest",
          "a references entry with citation_purpose counterparty_half whose digest is another "
          "half's: the record does not cite this half.",
          "capsule", _capsule_reference("counterparty_half", HALF_OTHER),
          {"exchange": HALF}, {"cites": False}),
    ]


# ---------------------------------------------------------------------------
# digest.json: the request digest is over the bytes as received
# ---------------------------------------------------------------------------


def digest_cases() -> list[dict]:
    logical = _req({"record": R1}, PIN_42, nonce="n-0201")
    canonical = jcs(logical)
    pretty = json.dumps({"nonce": "n-0201", "coverage": PIN_42, "subject": {"record": R1}}, indent=2)
    cbor_det = cbor(logical)
    # Same logical map, keys in insertion order (nonce, coverage, subject): not deterministic.
    cbor_unsorted = cbor({"nonce": "n-0201", "coverage": PIN_42, "subject": {"record": R1}}, sort_keys=False)
    assert cbor_unsorted != cbor_det
    other_nonce = jcs(_req({"record": R1}, PIN_42, nonce="n-0202"))

    def enc(case_id: str, description: str, encoding: str, raw: bytes, *, deterministic: bool,
            section: list[str]) -> dict:
        field = "request_json" if encoding == "json" else "request_cbor_hex"
        text = raw.decode("utf-8") if encoding == "json" else raw.hex()
        return {
            "id": case_id,
            "section": section,
            "description": description,
            "encoding": encoding,
            field: text,
            "deterministic_encoding": deterministic,
            "expect": {"request_digest": sha256_hex(raw)},
            "ambiguity": AMBIGUITY["A2"],
        }

    cases = [
        enc("digest-json-jcs", "RFC 8785 bytes: the recorded bytes and the transmitted bytes are the same.",
            "json", canonical.encode(), deterministic=True, section=[S_REF, S_RECREQ]),
        enc("digest-json-as-received", "The same logical request received pretty-printed with another "
            "member order. The digest is over these bytes, never over a re-canonicalized form.",
            "json", pretty.encode(), deterministic=False, section=[S_REF]),
        enc("digest-cbor-deterministic", "RFC 8949 §4.2.1 frame of the same logical request.",
            "cbor", cbor_det, deterministic=True, section=[S_REF, S_RECREQ, S_BIND]),
        enc("digest-cbor-as-received", "The same logical map as CBOR with unsorted keys: a different "
            "byte string, so a different digest. The digest is over the bytes received.",
            "cbor", cbor_unsorted, deterministic=False, section=[S_REF, S_BIND]),
        enc("digest-nonce-distinguishes", "digest-json-jcs with only the nonce changed: a distinct "
            "request instance with a distinct digest.",
            "json", other_nonce.encode(), deterministic=True, section=[S_NONCE, S_REF]),
    ]
    # Refusal binding to the received bytes.
    cases.append({
        "id": "neg-refusal-digest-recanonicalized",
        "section": [S_REF],
        "description": "A refusal of the pretty-printed request (digest-json-as-received) that carries the "
        "digest of the re-canonicalized form does not identify the request as received.",
        "request_json": pretty,
        "refusal_request_digest": sha256_hex(canonical.encode()),
        "expect": {"identifies_request": False},
        "ambiguity": AMBIGUITY["A2"],
    })
    cases.append({
        "id": "pos-refusal-digest-as-received",
        "section": [S_REF],
        "description": "The same refusal carrying the digest of the bytes as received identifies the request.",
        "request_json": pretty,
        "refusal_request_digest": sha256_hex(pretty.encode()),
        "expect": {"identifies_request": True},
        "ambiguity": AMBIGUITY["A2"],
    })
    return cases


# ---------------------------------------------------------------------------
# refusal.json: the signed refusal
# ---------------------------------------------------------------------------


def refusal_cases(requests: list[dict]) -> list[dict]:
    by_id = {c["id"]: c for c in requests}
    target = by_id["pos-subject-record"]
    digest = target["request_json_digest"]
    cases: list[dict] = []

    def c(case_id: str, section: list[str], description: str, obj: dict, expect: dict,
          *, ambiguity: str | None = AMBIGUITY["A7"], **extra: Any) -> dict:
        case: dict[str, Any] = {"id": case_id, "section": section, "description": description, "refusal": obj}
        case.update(extra)
        case["expect"] = expect
        if ambiguity:
            case["ambiguity"] = ambiguity
        return case

    valid = {"signature": "valid", "reason_registered": True, "conformant": True}
    for reason in REASONS:
        obj = refusal(digest, reason)
        cases.append(c(f"pos-reason-{reason}", [S_REF, S_IANA],
                       f"A signed refusal of request pos-subject-record (JSON binding) with reason {reason}.",
                       obj, valid, request_case="pos-subject-record",
                       signing_body=jcs({k: obj[k] for k in ("issued_at", "reason", "request_digest")})))
    cases.append({
        "id": "pos-imported-interop-vector",
        "section": [S_REF, S_IANA],
        "description": "The refusal vector three implementations already verify, reproduced byte for byte in "
        "refusal-imported.json. It carries every item §4.2 requires and a registered reason.",
        "file": "refusal-imported.json",
        "file_sha256": IMPORTED_REFUSAL_SHA256,
        "expect": valid,
        "ambiguity": AMBIGUITY["A7"],
    })
    good = refusal(digest, "policy_declined")
    frame = cbor(good)
    cases.append(c("pos-cbor-frame", [S_REF, S_BIND],
                   "The policy_declined refusal as a deterministic CBOR response frame. The signature is "
                   "unchanged: it covers the RFC 8785 body, not the frame.",
                   good, valid, refusal_cbor_hex=frame.hex(), refusal_cbor_digest=sha256_hex(frame)))
    with_detail = refusal(digest, "request_malformed", detail="profiles supported: evidence-interop/0")
    detail_frame = cbor(with_detail)
    cases.append(c("pos-detail-outside-signature", [S_REF, S_BIND],
                   "A request_malformed refusal with an optional detail (profile P-6), in both bindings. detail "
                   "is outside the signed members: the signature is the one a refusal without detail carries, "
                   "and the signing body is unchanged.",
                   with_detail, valid, refusal_cbor_hex=detail_frame.hex(),
                   refusal_cbor_digest=sha256_hex(detail_frame),
                   signing_body=jcs({k: with_detail[k] for k in ("issued_at", "reason", "request_digest")})))
    bad_sig = {"signature": "invalid", "conformant": False}
    cases.append(c("neg-tamper-reason", [S_REF], "reason changed after signing.",
                   {**good, "reason": "not_authorized"}, {**bad_sig, "reason_registered": True}))
    cases.append(c("neg-tamper-issued_at", [S_REF], "issued_at changed after signing (it MUST be covered).",
                   {**good, "issued_at": "2026-09-28T00:00:01Z"}, {**bad_sig, "reason_registered": True}))
    cases.append(c("neg-tamper-request_digest", [S_REF], "request_digest changed after signing.",
                   {**good, "request_digest": R_UNKNOWN}, {**bad_sig, "reason_registered": True}))
    cases.append(c("neg-tamper-key_id", [S_REF, "§11 Security Considerations"],
                   "key_id replaced with another key: a response signed by the wrong key is not a response "
                   "from the responder.",
                   {**good, "key_id": OTHER_PUB}, {**bad_sig, "reason_registered": True}))
    cases.append(c("neg-unsigned", [S_REF], "sig empty: a refusal exists only if the responder signed one.",
                   {**good, "sig": ""}, {**bad_sig, "reason_registered": True}))
    unreg = {"signature": "valid", "reason_registered": False, "conformant": False}
    cases.append(c("neg-unregistered-reason-no_such_record", [S_REF, S_IANA],
                   "Correctly signed, but no_such_record is not in the registry (the -00 token is "
                   "no_such_subject).", refusal(digest, "no_such_record"), unreg,
                   ambiguity=AMBIGUITY["A13"]))
    cases.append(c("neg-reason-recorded_absence", [S_REF, S_DISC, S_IANA],
                   "Correctly signed with reason recorded_absence: absence is not a reason token, and a "
                   "signed answer is never an absence.", refusal(digest, "recorded_absence"), unreg,
                   ambiguity=AMBIGUITY["A13"]))
    cases.append(c("neg-reason-wrong-case", [S_REF, S_IANA],
                   "NO_SUCH_SUBJECT: tokens are lowercase and matched exactly.",
                   refusal(digest, "NO_SUCH_SUBJECT"), unreg, ambiguity=AMBIGUITY["A13"]))
    cases.append(c("neg-two-reasons", [S_REF],
                   "Two tokens where exactly one is required.",
                   refusal(digest, ["no_such_subject", "policy_declined"]), unreg, ambiguity=AMBIGUITY["A13"]))
    body = {"reason": "policy_declined", "request_digest": digest}
    cases.append(c("neg-missing-issued_at", [S_REF],
                   "No issued_at (it MUST be present), signed over the remaining members.",
                   {**body, "key_id": PRIMARY_PUB, "sig": sign_body(body)},
                   {"signature": "valid", "reason_registered": True, "conformant": False}))
    cases.append(c("neg-malformed-request_digest", [S_REF],
                   "request_digest that is not a SHA-256 digest (8 hex characters), correctly signed.",
                   refusal(digest[:8], "no_such_subject"),
                   {"signature": "valid", "reason_registered": True, "conformant": False},
                   ambiguity=AMBIGUITY["A2"] + " " + AMBIGUITY["A7"]))
    return cases


# ---------------------------------------------------------------------------
# outcomes.json: three outcomes, pending, and the three-state discipline
# ---------------------------------------------------------------------------


def outcome_cases() -> list[dict]:
    def c(case_id: str, section: list[str], description: str, facts: dict, state: str,
          must_not: list[str], *, ambiguity: str | None = None) -> dict:
        case: dict[str, Any] = {
            "id": case_id, "section": section, "description": description, "facts": facts,
            "expect": {"state": state, "must_not_record_as": must_not},
        }
        if ambiguity:
            case["ambiguity"] = ambiguity
        return case

    return [
        c("out-artifact-verified", [S_OUT, S_ART, "§4.6 Mapping to a Requirement-Satisfaction Status"],
          "An artifact response that verifies against the anchor.",
          {"received": "artifact", "artifact_verification": "verified", "window": "open"},
          "artifact_verified", ["refusal", "recorded_absence", "pending"]),
        c("out-artifact-verification-failed", [S_ART, S_DISC],
          "An artifact that fails verification: a response received and failed. Not a grant, not an "
          "absence, not a fourth outcome.",
          {"received": "artifact", "artifact_verification": "failed", "window": "open"},
          "artifact_verification_failed", ["artifact_verified", "recorded_absence", "refusal"]),
        c("out-refusal-signed", [S_REF, S_DISC], "A valid signed refusal.",
          {"received": "refusal", "refusal_signature": "valid", "refusal_reason": "policy_declined",
           "window": "open"},
          "refusal", ["recorded_absence", "pending", "artifact_verified"]),
        c("neg-refusal-as-absence", [S_DISC],
          "A valid signed no_such_subject refusal is a refusal. Discarding it and recording an absence "
          "misstates the exchange.",
          {"received": "refusal", "refusal_signature": "valid", "refusal_reason": "no_such_subject",
           "window": "closed"},
          "refusal", ["recorded_absence"]),
        c("out-refusal-over-http", [S_BIND, S_DISC],
          "HTTP binding: a refusal is a successful transport exchange carrying a refusal answer.",
          {"received": "refusal", "refusal_signature": "valid", "refusal_reason": "not_authorized",
           "transport": "http", "window": "open"},
          "refusal", ["recorded_absence"]),
        c("out-pending", [S_PEND, S_DISC], "Nothing received and the window still open.",
          {"received": "nothing", "window": "open"}, "pending", ["recorded_absence", "refusal"]),
        c("out-absence", [S_ABS, S_DISC], "Nothing received and the window closed.",
          {"received": "nothing", "window": "closed"}, "recorded_absence", ["refusal", "pending"]),
        c("neg-timeout-as-refusal", [S_DISC],
          "No party may manufacture a refusal from a timeout.",
          {"received": "nothing", "window": "closed", "deadline_passed": True},
          "recorded_absence", ["refusal"]),
        c("neg-transport-error-as-refusal", [S_BIND, S_DISC],
          "A transport-level error is never a refusal.",
          {"received": "transport_error", "window": "closed"}, "recorded_absence", ["refusal"]),
        c("out-transport-error-inside-window", [S_PEND, S_BIND],
          "A transport failure while the window is open leaves the request pending.",
          {"received": "transport_error", "window": "open"}, "pending", ["recorded_absence", "refusal"],
          ambiguity=AMBIGUITY["A8"]),
        c("neg-subprotocol-not-offered", [S_BIND],
          "A peer that does not offer evidence-request/1 has not refused; it has not answered.",
          {"received": "subprotocol_not_offered", "window": "closed"},
          "recorded_absence", ["refusal"]),
        c("neg-commitment-makes-refusal", [S_ABS, S_DISC, S_RET],
          "An absence inside an outstanding retention commitment is attributable to the responder but "
          "is still an absence, never a refusal.",
          {"received": "nothing", "window": "closed", "retention_commitment": "in_force"},
          "recorded_absence", ["refusal"]),
        c("neg-unregistered-reason-as-absence", [S_REF, S_DISC],
          "A correctly signed object with an unregistered reason is not a conforming refusal, and "
          "is still the responder's signed answer: never an absence.",
          {"received": "refusal", "refusal_signature": "valid", "refusal_reason": "no_such_record",
           "window": "closed"},
          "refusal_nonconformant", ["recorded_absence", "refusal"], ambiguity=AMBIGUITY["A13"]),
    ]


# ---------------------------------------------------------------------------
# invariance.json: byte-identical artifacts for the same subject and coverage
# ---------------------------------------------------------------------------


def invariance_cases() -> list[dict]:
    content = {"anchor": ANCHOR_42, "evidence_stream": "stream-a", "records": [R1]}
    artifact = jcs(content).encode()
    reordered = json.dumps({"records": [R1], "evidence_stream": "stream-a", "anchor": ANCHOR_42},
                           separators=(",", ":")).encode()
    assert reordered != artifact
    other_artifact = jcs({"anchor": ANCHOR_42, "evidence_stream": "stream-a", "records": [R1, R2]}).encode()
    at_40 = jcs({"anchor": ANCHOR_40, "evidence_stream": "stream-a", "records": [R1]}).encode()
    proof_a = jcs({"consistency": [ANCHOR_40, ANCHOR_42]}).encode()
    proof_b = jcs({"consistency": [ANCHOR_42]}).encode()

    def obs(requester: str, transport: str, request: dict, anchor: str, art: bytes,
            verification: bytes = proof_b) -> dict:
        return {
            "requester": requester,
            "transport": transport,
            "request": request,
            "resolved_anchor": anchor,
            "artifact_hex": art.hex(),
            "artifact_digest": sha256_hex(art),
            "verification_material_hex": verification.hex(),
        }

    subj = {"record": R1}

    def c(case_id: str, description: str, observations: list[dict], verdict: str,
          section: list[str] | None = None) -> dict:
        return {
            "id": case_id,
            "section": section or [S_INV],
            "description": description,
            "observations": observations,
            "expect": {"invariance": verdict},
            "ambiguity": AMBIGUITY["A12"],
        }

    return [
        c("inv-same-pin-byte-identical",
          "Two requesters, two transports, different nonce and route, same subject and pin: the same bytes.",
          [obs("requester-a", "stream", _req(subj, PIN_42, nonce="n-0301"), ANCHOR_42, artifact),
           obs("requester-b", "http", _req(subj, PIN_42, nonce="n-0302", route="https://responder.example/e"),
               ANCHOR_42, artifact)],
          "holds", [S_INV, S_NONCE, S_ROUTE]),
        c("inv-verification-material-may-differ",
          "Identical artifacts with different verification material: invariance binds the artifact only.",
          [obs("requester-a", "stream", _req(subj, PIN_42, nonce="n-0303"), ANCHOR_42, artifact, proof_a),
           obs("requester-b", "stream", _req(subj, PIN_42, nonce="n-0304"), ANCHOR_42, artifact, proof_b)],
          "holds"),
        c("inv-min-freshness-same-selected-anchor",
          "Two min_freshness requests the responder resolved to the same anchor: the same bytes.",
          [obs("requester-a", "stream", _req(subj, {"min_freshness": 40}, nonce="n-0305"), ANCHOR_42, artifact),
           obs("requester-b", "http", _req(subj, {"min_freshness": 41}, nonce="n-0306"), ANCHOR_42, artifact)],
          "holds"),
        c("inv-different-anchor-not-comparable",
          "Different resolved anchors: different bytes are expected, and no invariance claim applies.",
          [obs("requester-a", "stream", _req(subj, {"min_freshness": 40}, nonce="n-0307"), ANCHOR_40, at_40),
           obs("requester-b", "stream", _req(subj, {"min_freshness": 42}, nonce="n-0308"), ANCHOR_42, artifact)],
          "not_comparable"),
        c("neg-inv-divergent-artifacts",
          "Same subject and pin, different artifact bytes for different requesters: a violation.",
          [obs("requester-a", "stream", _req(subj, PIN_42, nonce="n-0309"), ANCHOR_42, artifact),
           obs("requester-b", "stream", _req(subj, PIN_42, nonce="n-0310"), ANCHOR_42, other_artifact)],
          "violated"),
        c("neg-inv-nondeterministic-serialization",
          "Same content with a different member order: the bytes differ, so invariance is violated even "
          "with honest intent (the serialization MUST be deterministic).",
          [obs("requester-a", "stream", _req(subj, PIN_42, nonce="n-0311"), ANCHOR_42, artifact),
           obs("requester-b", "stream", _req(subj, PIN_42, nonce="n-0312"), ANCHOR_42, reordered)],
          "violated"),
    ]


# ---------------------------------------------------------------------------
# categories.json: the OPTIONAL categories request field (-01)
# ---------------------------------------------------------------------------

# An x- set: well-formedness does not depend on a set being registered, and
# no category-set registry exists yet (§3.9 leaves it to a companion document).
CAT_SET = "x-example-set"
CATS = {"set": CAT_SET, "names": ["alpha", "beta"]}
CATEGORIES_NOTES = {
    "B1": "§3.9: the request cases apply to a responder that implements categories. A responder that "
    "does not implement it ignores the field, malformed or not, and answers as if it were absent.",
    "B2": "§3.9 leaves open whether the order of names carries meaning. No case compares two requests "
    "whose names differ only in order.",
    "B3": "§3.9 does not say whether a member other than set and names is malformed. No case has one.",
}


def categories_cases() -> list[dict]:
    def c(case_id: str, description: str, categories: Any, expect: dict,
          section: list[str] | None = None) -> dict:
        case = request_case(case_id, section or [S_CAT], description,
                            _req({"record": R1}, PIN_42, categories=categories), expect)
        case["kind"] = "request"
        return case

    content = {"anchor": ANCHOR_42, "category_declaration": {"set": CAT_SET, "alpha": "available",
                                                              "beta": "withheld"}, "records": [R1]}
    declared = jcs(content).encode()
    declared_alpha = jcs({"anchor": ANCHOR_42, "category_declaration": {"set": CAT_SET, "alpha": "available"},
                          "records": [R1]}).encode()

    def obs(requester: str, request: dict, art: bytes) -> dict:
        return {"requester": requester, "request": request, "resolved_anchor": ANCHOR_42,
                "artifact_hex": art.hex(), "artifact_digest": sha256_hex(art)}

    def inv(case_id: str, description: str, observations: list[dict], verdict: str) -> dict:
        return {"id": case_id, "kind": "invariance", "section": [S_INV, S_CAT],
                "description": description, "observations": observations,
                "expect": {"invariance": verdict}}

    subj = {"record": R1}
    return [
        c("cat-two-names", "A set identifier and two distinct names: well formed.", CATS, WELL_FORMED),
        c("cat-one-name", "One name is enough: names is non-empty.", {"set": CAT_SET, "names": ["alpha"]},
          WELL_FORMED),
        c("cat-names-any-order", "Names in descending order: well formed. §3.9 leaves open whether the order "
          "carries meaning, and does not make it a well-formedness rule.",
          {"set": CAT_SET, "names": ["beta", "alpha"]}, WELL_FORMED),
        c("neg-cat-not-a-map", "categories is a text string, not a map.", "alpha",
          MALFORMED("request_malformed")),
        c("neg-cat-missing-set", "categories lacks set.", {"names": ["alpha"]},
          MALFORMED("request_malformed")),
        c("neg-cat-missing-names", "categories lacks names.", {"set": CAT_SET},
          MALFORMED("request_malformed")),
        c("neg-cat-names-empty", "names is an empty array.", {"set": CAT_SET, "names": []},
          MALFORMED("request_malformed")),
        c("neg-cat-names-duplicate", "names repeats a name.", {"set": CAT_SET, "names": ["alpha", "alpha"]},
          MALFORMED("request_malformed")),
        c("neg-cat-names-not-array", "names is a text string, not an array.", {"set": CAT_SET, "names": "alpha"},
          MALFORMED("request_malformed")),
        c("neg-cat-set-not-text", "set is an integer, not a text string.", {"set": 7, "names": ["alpha"]},
          MALFORMED("request_malformed")),
        c("neg-cat-name-not-text", "A name is an integer, not a text string.", {"set": CAT_SET, "names": [1]},
          MALFORMED("request_malformed")),
        inv("cat-inv-same-categories",
            "Same subject, pin and categories from two requesters: the same bytes, declaration included.",
            [obs("requester-a", _req(subj, PIN_42, nonce="n-0901", categories=CATS), declared),
             obs("requester-b", _req(subj, PIN_42, nonce="n-0902", categories=CATS), declared)],
            "holds"),
        inv("cat-inv-different-categories-not-comparable",
            "Same subject and pin, different categories: categories is an input of the artifact when "
            "honored (§5), so different bytes are expected and no invariance claim applies.",
            [obs("requester-a", _req(subj, PIN_42, nonce="n-0903", categories=CATS), declared),
             obs("requester-b", _req(subj, PIN_42, nonce="n-0904",
                                     categories={"set": CAT_SET, "names": ["alpha"]}), declared_alpha)],
            "not_comparable"),
        inv("neg-cat-inv-same-categories-divergent",
            "Same subject, pin and categories, different declarations for different requesters: a violation.",
            [obs("requester-a", _req(subj, PIN_42, nonce="n-0905", categories=CATS), declared),
             obs("requester-b", _req(subj, PIN_42, nonce="n-0906", categories=CATS), declared_alpha)],
            "violated"),
    ]


# ---------------------------------------------------------------------------
# carriage.json: A2A and MCP carriage and the envelope's request digest (-01)
# ---------------------------------------------------------------------------


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _carriage_request() -> tuple[dict, bytes]:
    """A request whose CBOR needs padding and holds '+' or '/' in base64, so the
    A2A text and the MCP text differ and a decoder for the wrong one fails."""
    for i in range(1, 64):
        value = _req({"record": R1}, PIN_42, nonce="n-carriage-" + "~" * i)
        raw = cbor(value)
        text = _b64(raw)
        if len(raw) % 3 and ("+" in text or "/" in text):
            return value, raw
    raise SystemExit("no carriage request found")


def carriage_cases() -> list[dict]:
    value, raw = _carriage_request()
    digest = sha256_hex(raw)
    other_raw = cbor(_req({"record": R1}, PIN_42, nonce="n-carriage-other"))
    a2a_text, mcp_text = _b64(raw), _b64url(raw)
    assert a2a_text != mcp_text and a2a_text.endswith("=")

    def dig(case_id: str, section: list[str], description: str, carriage: str, text: str,
            digest_over: str, candidate: str, matches: bool) -> dict:
        return {"id": case_id, "kind": "digest", "section": section, "description": description,
                "carriage": carriage, "carried_text": text, "digest_over": digest_over,
                "candidate_digest": candidate, "expect": {"is_request_digest": matches}}

    def bind(case_id: str, description: str, envelope_digest: str, answers: bool) -> dict:
        return {"id": case_id, "kind": "binding", "section": [S_ART], "description": description,
                "retained_request_hex": raw.hex(), "envelope_request_digest": envelope_digest,
                "expect": {"answers": answers}}

    def media(case_id: str, media_type: str, ok: bool, description: str) -> dict:
        return {"id": case_id, "kind": "media_type", "section": [S_CARRY], "description": description,
                "media_type": media_type, "expect": {"accepted": ok}}

    def raw_part(media_type: str = "application/cbor") -> dict:
        return {"kind": "raw", "media_type": media_type}

    def a2a(task_state: str, parts: list[dict] | None) -> dict:
        return {"carriage": "a2a", "request_media_type": "application/cbor", "task_state": task_state,
                "reply_artifact": None if parts is None else {"parts": parts}}

    def mcp(is_error: bool, structured: dict | None) -> dict:
        return {"carriage": "mcp", "request_media_type": "application/cbor", "is_error": is_error,
                "structured_content": structured}

    def cls(case_id: str, section: list[str], description: str, received: dict, state: str) -> dict:
        expect: dict[str, Any] = {"classified_as": state}
        if state != "reply":
            expect["must_not_classify_as"] = ["refusal"]
        return {"id": case_id, "kind": "classify", "section": section, "description": description,
                "received": received, "expect": expect}

    return [
        dig("carry-a2a-raw-part", [S_CARRY, S_A2A],
            "A2A JSON writes the raw part as base64 with padding. The digest is over the decoded octets.",
            "a2a", a2a_text, "decoded", digest, True),
        dig("carry-mcp-request-argument", [S_CARRY, S_MCP],
            "MCP writes the request argument as base64url without padding. The digest is over the decoded "
            "octets, and equals the A2A one.", "mcp", mcp_text, "decoded", digest, True),
        dig("neg-carry-digest-over-text", [S_CARRY],
            "A digest over the base64 text instead of the decoded octets is not the request digest.",
            "a2a", a2a_text, "text", sha256_hex(a2a_text.encode("ascii")), False),
        dig("neg-carry-digest-over-reencoding", [S_CARRY],
            "A digest over a JSON re-encoding of the decoded request is not the request digest.",
            "mcp", mcp_text, "reencoded_json", sha256_hex(jcs(value).encode("utf-8")), False),
        bind("bind-envelope-answers-own-request",
             "The envelope's request digest is the digest of the requester's retained bytes: it answers.",
             digest, True),
        bind("neg-bind-envelope-other-request",
             "The envelope's request digest is that of another request (a different nonce): it does not "
             "answer this one, however well it verifies otherwise.", sha256_hex(other_raw), False),
        media("media-cbor", "application/cbor", True, "Deterministic CBOR."),
        media("media-json", "application/json", True, "JCS."),
        media("neg-media-parameter", "application/cbor; charset=binary", False,
              "Compared as an exact string with no parameters."),
        media("neg-media-case", "Application/CBOR", False, "Compared as an exact string."),
        cls("classify-a2a-completed-with-reply", [S_A2A],
            "A completed task with one reply Artifact carrying one raw part of the request's media type.",
            a2a("TASK_STATE_COMPLETED", [raw_part()]), "reply"),
        cls("neg-classify-a2a-reply-two-parts", [S_A2A],
            "A reply Artifact with two parts is not of the reply's form: not a reply.",
            a2a("TASK_STATE_COMPLETED", [raw_part(), raw_part()]), "no_reply"),
        cls("neg-classify-a2a-reply-other-media-type", [S_A2A, S_CARRY],
            "A reply Artifact whose raw part has a media type other than the request's: not a reply.",
            a2a("TASK_STATE_COMPLETED", [raw_part("application/json")]), "no_reply"),
        cls("neg-classify-a2a-reply-text-part", [S_A2A],
            "A reply Artifact whose one part is text, not raw: not a reply.",
            a2a("TASK_STATE_COMPLETED", [{"kind": "text", "media_type": "text/plain"}]), "no_reply"),
        cls("neg-classify-a2a-rejected-no-reply", [S_A2A, S_CARRY],
            "A rejected task with no reply Artifact is the responder sending no reply, never a refusal. "
            "The request stays pending until the window closes, then is a recorded absence.",
            a2a("TASK_STATE_REJECTED", None), "no_reply"),
        cls("classify-a2a-working-no-reply", [S_A2A, S_PEND],
            "A working task with no reply Artifact yet: pending.",
            a2a("TASK_STATE_WORKING", None), "pending"),
        cls("classify-a2a-unspecified-no-reply", [S_A2A, S_PEND],
            "A task in an unspecified state with no reply Artifact: pending.",
            a2a("TASK_STATE_UNSPECIFIED", None), "pending"),
        cls("classify-mcp-error-flag-with-reply", [S_MCP, S_CARRY],
            "The error flag is set but structuredContent carries a reply with the request's media type: "
            "it is the reply.", mcp(True, {"reply": "AA", "media_type": "application/cbor"}), "reply"),
        cls("neg-classify-mcp-reply-other-media-type", [S_MCP],
            "structuredContent carries a reply labeled with a media type other than the request's: not a "
            "reply.", mcp(False, {"reply": "AA", "media_type": "application/json"}), "no_reply"),
        cls("neg-classify-mcp-reply-not-base64url", [S_MCP],
            "structuredContent.reply is padded base64, not base64url without padding: not a reply.",
            mcp(False, {"reply": "AA==", "media_type": "application/cbor"}), "no_reply"),
        cls("neg-classify-mcp-error-text-no-reply", [S_MCP, S_CARRY],
            "The error flag is set, no structuredContent, text saying the caller is not authorized: "
            "not a reply, and never a refusal. The request stays pending until the window closes.",
            mcp(True, None), "no_reply"),
    ]


# ---------------------------------------------------------------------------
# retention.json
# ---------------------------------------------------------------------------

CAPABILITY_REASONS = {"not_authorized", "coverage_unsatisfiable", "request_malformed", "derivation_unsupported"}
BREACH_REASONS = {"no_such_subject", "policy_declined", "deadline_unmet"}


def retention_cases() -> list[dict]:
    cases: list[dict] = []
    for reason in REASONS:
        if reason in CAPABILITY_REASONS:
            inside, amb_in = "no_breach", None
        elif reason in BREACH_REASONS:
            inside, amb_in = "breach", None
        else:  # retention_expired
            inside, amb_in = "breach", AMBIGUITY["A9"]
        case = {"id": f"ret-inside-{reason}", "section": [S_RET],
                "description": f"A refusal with reason {reason} inside until.",
                "facts": {"commitment": "in_force", "refusal_reason": reason},
                "expect": {"classification": inside}}
        if amb_in:
            case["ambiguity"] = amb_in
        cases.append(case)
    for reason in REASONS:
        if reason == "retention_expired":
            after, amb_after = "correct", None
        elif reason == "no_such_subject":
            after, amb_after = "wrong_token", AMBIGUITY["A10"]
        else:
            after, amb_after = "no_breach", AMBIGUITY["A10"]
        case = {"id": f"ret-after-{reason}", "section": [S_RET, S_REF],
                "description": f"A refusal with reason {reason} after until.",
                "facts": {"commitment": "lapsed", "refusal_reason": reason},
                "expect": {"classification": after}}
        if amb_after:
            case["ambiguity"] = amb_after
        cases.append(case)
    cases.append({"id": "ret-absence-inside", "section": [S_RET, S_ABS],
                  "description": "An absence inside until is recorded citing the commitment and is "
                  "chargeable to the responder that signed it.",
                  "facts": {"commitment": "in_force", "received": "nothing", "window": "closed"},
                  "expect": {"classification": "attributable_absence", "state": "recorded_absence"}})
    cases.append({"id": "ret-absence-without-commitment", "section": [S_ABS],
                  "description": "An absence with no commitment is evidence of nothing but the attempt.",
                  "facts": {"commitment": "none", "received": "nothing", "window": "closed"},
                  "expect": {"classification": "attempt_only", "state": "recorded_absence"}})
    for form, value, ok in (
        ("record", R1, True),
        ("exchange", HALF, True),
        ("range", [0, 2], True),
        ("correlation", CORRELATION, False),
        ("full_history", None, False),
        ("checkpoints", None, False),
    ):
        commitment = {"evidence_stream": "stream-a", "subject": {form: value}, "until": "2027-09-28T00:00:00Z"}
        case = {"id": f"ret-commitment-subject-{form}", "section": [S_RET, S_SUBJ],
                "description": f"A retention commitment naming a {form} subject.",
                "commitment": commitment,
                "expect": {"well_formed": ok}}
        if not ok or form == "range":
            case["ambiguity"] = AMBIGUITY["A11"] + " " + AMBIGUITY["A1"]
        else:
            case["ambiguity"] = AMBIGUITY["A1"]
        cases.append(case)
    cases.append({"id": "ret-commitment-missing-until", "section": [S_RET],
                  "description": "A commitment without until (item 2 is not optional).",
                  "commitment": {"evidence_stream": "stream-a", "subject": {"record": R1}},
                  "expect": {"well_formed": False}, "ambiguity": AMBIGUITY["A1"]})
    return cases


# ---------------------------------------------------------------------------
# unavailable-window.json: unavailable-window statements and how a reader
# shows an absence they cover (-02)
# ---------------------------------------------------------------------------

S_UW = "§4.7 Unavailable-Window Statements"
S_MAP = "§4.6 Mapping to a Requirement-Satisfaction Status"
UW_CLASSES = ["flood", "maintenance", "outage", "other_declared"]
UW_SHOWN = "no answer; holder states unavailability"
UW_SIGNED_MEMBERS = ("end", "reason_class", "start")
UW_SIGNATURE_PROFILE = {
    "note": (
        "-02 section 4.7 item 3 leaves the signature format to the deployment. These vectors use the "
        "refusal.json profile: Ed25519 over the RFC 8785 serialization of the JSON object with "
        "exactly the members of the statement present among end, reason_class and start, signed "
        "with the primary key of refusal.json."
    ),
    "algorithm": "Ed25519",
    "signed_members": list(UW_SIGNED_MEMBERS),
    "signing_body": "RFC 8785 (JCS) of the signed members",
    "key_id": "raw Ed25519 public key, lowercase hex",
    "sig": "Ed25519 signature, lowercase hex",
}
UW_NOTES = (
    "Times are RFC 3339 UTC strings and compare chronologically. A statement's receipts are those "
    "on checkpoints covering it that attest a time; accepted is true when the receipt comes from a "
    "transparency service the reader accepts as independent of the responder. Only accepted "
    "receipts register a statement and give its registration time. An absence's waiting window runs from sent_at, when the requester sent the request, to closed_at, both included. "
    "A statement case expects whether a reader recognizes it (well formed, signed by the key named, "
    "registered) and its registration time. A display case expects which statements cover the "
    "absence, how the reader shows it, and per covering statement the reason class and whether it "
    "is labelled stated afterwards."
)


def uw_statement(start: Any, end: Any, reason_class: Any = "flood", *,
                 private: Ed25519PrivateKey = PRIMARY, public: str = PRIMARY_PUB,
                 tamper: bool = False, **extra: Any) -> dict:
    body = {k: v for k, v in (("start", start), ("end", end), ("reason_class", reason_class))
            if v is not None}
    sig = sign_body(body, private)
    if tamper:
        sig = ("0" if sig[0] != "0" else "1") + sig[1:]
    return {**body, **extra, "key_id": public, "sig": sig}


def unavailable_window_cases() -> list[dict]:
    cases: list[dict] = []

    def receipts_of(times: list) -> list[dict]:
        return [t if isinstance(t, dict) else {"time": t, "accepted": True} for t in times]

    def stmt_case(case_id: str, description: str, statement: dict, receipts: list,
                  recognized: bool, *, registration_time: str | None = None,
                  why: str | None = None, shown_reason: str | None = None) -> None:
        expect: dict[str, Any] = {"recognized": recognized}
        if recognized:
            expect["registration_time"] = registration_time
            expect["shown_reason"] = shown_reason or statement["reason_class"]
        else:
            expect["why"] = why
        cases.append({"id": case_id, "kind": "statement", "section": [S_UW], "description": description,
                      "responder_key": PRIMARY_PUB, "statement": statement,
                      "receipts": receipts_of(receipts), "expect": expect})

    for cls in UW_CLASSES:
        stmt_case(f"uw-class-{cls}", f"A registered statement with reason_class {cls}.",
                  uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z", cls),
                  ["2026-10-29T10:06:00Z"], True, registration_time="2026-10-29T10:06:00Z")
    stmt_case("uw-neg-class-unlisted", "A reason_class outside the closed list: malformed.",
              uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z", "ddos"),
              ["2026-10-29T10:06:00Z"], False, why="malformed")
    stmt_case("uw-neg-class-free-text", "A reason_class that is free text: malformed.",
              uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z", "flooded by a botnet"),
              ["2026-10-29T10:06:00Z"], False, why="malformed")
    stmt_case("uw-neg-class-wrong-case", "A reason_class differing from a listed token only in case: "
              "malformed (exact token comparison).",
              uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z", "Flood"),
              ["2026-10-29T10:06:00Z"], False, why="malformed")
    stmt_case("uw-neg-class-missing", "A statement with no reason_class: malformed.",
              uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z", None),
              ["2026-10-29T10:06:00Z"], False, why="malformed")
    stmt_case("uw-extra-member-not-the-reason", "An extra prose member beside a listed class: the "
              "statement is recognized, and the reader shows only the class as the reason.",
              uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z", "flood",
                           detail="a botnet hit us"),
              ["2026-10-29T10:06:00Z"], True, registration_time="2026-10-29T10:06:00Z",
              shown_reason="flood")
    stmt_case("uw-neg-start-missing", "A statement with no start: malformed.",
              uw_statement(None, "2026-10-29T10:40:00Z"), ["2026-10-29T10:06:00Z"], False, why="malformed")
    stmt_case("uw-neg-end-missing", "A statement with no end is malformed, not open-ended.",
              uw_statement("2026-10-29T10:00:00Z", None), ["2026-10-29T10:06:00Z"], False, why="malformed")
    stmt_case("uw-neg-time-unparseable", "An end that is not a time in the deployment's representation: "
              "malformed.",
              uw_statement("2026-10-29T10:00:00Z", "later today"), ["2026-10-29T10:06:00Z"], False,
              why="malformed")
    stmt_case("uw-neg-end-before-start", "end earlier than start: malformed.",
              uw_statement("2026-10-29T10:40:00Z", "2026-10-29T10:00:00Z"),
              ["2026-10-29T10:06:00Z"], False, why="malformed")
    stmt_case("uw-end-equals-start", "end equal to start: well formed (end MUST NOT be earlier).",
              uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:00:00Z"),
              ["2026-10-29T10:06:00Z"], True, registration_time="2026-10-29T10:06:00Z")
    stmt_case("uw-neg-bad-signature", "A statement whose signature does not verify is not the "
              "responder's statement.",
              uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z", tamper=True),
              ["2026-10-29T10:06:00Z"], False, why="not_signed_by_responder")
    stmt_case("uw-neg-other-key", "A statement validly signed by a key other than the responder's.",
              uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z", private=OTHER, public=OTHER_PUB),
              ["2026-10-29T10:06:00Z"], False, why="not_signed_by_responder")
    stmt_case("uw-neg-unregistered", "A statement no receipt covers is not registered.",
              uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z"), [], False,
              why="not_registered")
    stmt_case("uw-neg-receipt-not-accepted", "The only receipt comes from a transparency service the "
              "responder operates: not accepted, so the statement is not registered.",
              uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z"),
              [{"time": "2026-10-29T10:06:00Z", "accepted": False}], False, why="not_registered")
    stmt_case("uw-registration-earliest-receipt", "Two receipts: the registration time is the earliest.",
              uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z"),
              ["2026-10-29T10:30:00Z", "2026-10-29T10:06:00Z"], True,
              registration_time="2026-10-29T10:06:00Z")

    flood = uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z", "flood")
    outage = uw_statement("2026-10-29T09:30:00Z", "2026-10-29T09:58:00Z", "outage")
    never = ["refusal", "proof_of_attack", "absence_without_statement"]

    def disp(case_id: str, description: str, absence: dict, statements: list[dict],
             covered_by: list[str], labels: dict[str, dict], *, section: list[str] | None = None,
             state: str = "recorded_absence", shown_as: str | None = None) -> None:
        if shown_as is None:
            shown_as = UW_SHOWN if covered_by else "recorded_absence"
        # §4.7 item 1: the reader shows each covering statement's stated period too.
        by_id = {entry["id"]: entry["statement"] for entry in statements}
        labels = {sid: {**label, "stated_period": [by_id[sid]["start"], by_id[sid]["end"]]}
                  for sid, label in labels.items()}
        expect: dict[str, Any] = {"state": state, "covered_by": covered_by, "shown_as": shown_as,
                                  "labels": labels}
        expect["must_not_show_as"] = never if covered_by else ["refusal", "proof_of_attack"]
        cases.append({"id": case_id, "kind": "display", "section": section or [S_UW, S_ABS],
                      "description": description, "responder_key": PRIMARY_PUB, "absence": absence,
                      "statements": statements, "expect": expect})

    def st(sid: str, statement: dict, receipts: list[str]) -> dict:
        return {"id": sid, "statement": statement, "receipts": receipts_of(receipts)}

    def lab(cls: str, afterwards: bool, registered: str) -> dict:
        return {"reason_class": cls, "registration_time": registered, "stated_afterwards": afterwards}

    a_window = {"sent_at": "2026-10-29T10:10:00Z", "closed_at": "2026-10-29T10:20:00Z",
                "received": "nothing"}
    b_window = {"sent_at": "2026-10-29T09:40:00Z", "closed_at": "2026-10-29T09:55:00Z",
                "received": "nothing"}
    disp("uw-show-stated-before-close", "The worked example's requester A: a flood statement "
         "registered at 10:06 covers an absence whose window closed at 10:20.",
         a_window, [st("s1", flood, ["2026-10-29T10:06:00Z"])], ["s1"],
         {"s1": lab("flood", False, "2026-10-29T10:06:00Z")},
         section=[S_UW, S_ABS, S_DISC])
    disp("uw-show-stated-afterwards", "The worked example's requester B: an outage statement "
         "registered at 11:31 covers an absence whose window closed at 09:55, so it is stated "
         "afterwards.",
         b_window, [st("s1", flood, ["2026-10-29T10:06:00Z"]),
                    st("s2", outage, ["2026-10-29T11:31:00Z"])], ["s2"],
         {"s2": lab("outage", True, "2026-10-29T11:31:00Z")},
         section=[S_UW, S_ABS, S_DISC])
    disp("uw-backdated-receipt-not-accepted", "Requester B again, but the outage statement also carries "
         "a receipt dated 09:50 from a service the responder runs. Only the accepted 11:31 receipt "
         "counts, so the statement is still stated afterwards.",
         b_window, [st("s2", outage, [{"time": "2026-10-29T09:50:00Z", "accepted": False},
                                      {"time": "2026-10-29T11:31:00Z", "accepted": True}])], ["s2"],
         {"s2": lab("outage", True, "2026-10-29T11:31:00Z")})
    disp("uw-registered-at-close", "Registration time equal to the window's close is not later than "
         "it: not stated afterwards.",
         a_window, [st("s1", flood, ["2026-10-29T10:20:00Z"])], ["s1"],
         {"s1": lab("flood", False, "2026-10-29T10:20:00Z")})
    disp("uw-registered-after-close-by-a-second", "Registration one second after the close: stated "
         "afterwards.",
         a_window, [st("s1", flood, ["2026-10-29T10:20:01Z"])], ["s1"],
         {"s1": lab("flood", True, "2026-10-29T10:20:01Z")})
    disp("uw-long-period-shown", "A flood statement stating a year-long period: the reader shows that "
         "period, so it does not read like a 40-minute window.",
         a_window, [st("s1", uw_statement("2026-01-01T00:00:00Z", "2026-12-31T23:59:59Z", "flood"),
                       ["2026-10-29T10:06:00Z"])], ["s1"],
         {"s1": lab("flood", False, "2026-10-29T10:06:00Z")})
    disp("uw-partial-overlap", "A statement that ends inside the waiting window still covers it.",
         a_window, [st("s1", uw_statement("2026-10-29T09:00:00Z", "2026-10-29T10:12:00Z", "maintenance"),
                       ["2026-10-29T08:55:00Z"])], ["s1"],
         {"s1": lab("maintenance", False, "2026-10-29T08:55:00Z")})
    disp("uw-touching-boundary", "A statement whose end equals the time the request was sent shares one "
         "instant with the window: it covers.",
         a_window, [st("s1", uw_statement("2026-10-29T09:00:00Z", "2026-10-29T10:10:00Z", "outage"),
                       ["2026-10-29T10:11:00Z"])], ["s1"],
         {"s1": lab("outage", False, "2026-10-29T10:11:00Z")})
    disp("uw-no-overlap", "A statement that ends before the request was sent does not cover the "
         "absence: the reader shows the absence as it is.",
         a_window, [st("s1", uw_statement("2026-10-29T09:00:00Z", "2026-10-29T10:09:59Z", "outage"),
                       ["2026-10-29T10:11:00Z"])], [], {})
    disp("uw-other-key-does-not-cover", "A statement signed by another key does not cover an absence "
         "from this responder.",
         a_window, [st("s1", uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z",
                                          private=OTHER, public=OTHER_PUB), ["2026-10-29T10:06:00Z"])],
         [], {})
    disp("uw-unregistered-does-not-cover", "An unregistered statement does not cover.",
         a_window, [st("s1", flood, [])], [], {})
    disp("uw-malformed-does-not-cover", "A statement with an unlisted class does not cover.",
         a_window, [st("s1", uw_statement("2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z", "ddos"),
                       ["2026-10-29T10:06:00Z"])], [], {})
    disp("uw-two-statements-cover", "Two statements cover one absence: the reader labels each.",
         a_window, [st("s1", flood, ["2026-10-29T10:06:00Z"]),
                    st("s2", uw_statement("2026-10-29T10:15:00Z", "2026-10-29T11:00:00Z", "maintenance"),
                       ["2026-10-29T12:00:00Z"])], ["s1", "s2"],
         {"s1": lab("flood", False, "2026-10-29T10:06:00Z"),
          "s2": lab("maintenance", True, "2026-10-29T12:00:00Z")})
    disp("uw-commitment-unchanged", "An absence citing a retention commitment and covered by a "
         "statement still cites the commitment and is still attributable to the responder.",
         {**a_window, "retention_commitment": "in_force"},
         [st("s1", flood, ["2026-10-29T10:06:00Z"])], ["s1"],
         {"s1": lab("flood", False, "2026-10-29T10:06:00Z")}, section=[S_UW, S_ABS, S_RET])
    cases[-1]["expect"]["retention_classification"] = "attributable_absence"
    disp("uw-refusal-not-affected", "A request that received a signed refusal has no absence: a "
         "statement over the same period changes nothing.",
         {**a_window, "received": "refusal", "refusal_reason": "policy_declined"},
         [st("s1", flood, ["2026-10-29T10:06:00Z"])], [], {}, section=[S_UW, S_DISC],
         state="refusal", shown_as="refusal")
    cases[-1]["expect"]["must_not_show_as"] = ["recorded_absence", UW_SHOWN]
    disp("uw-pending-not-absence", "A request still inside its window is pending; a statement does not "
         "make it an absence.",
         {"sent_at": "2026-10-29T10:10:00Z", "closed_at": None, "received": "nothing"},
         [st("s1", flood, ["2026-10-29T10:06:00Z"])], [], {}, section=[S_UW, S_PEND, S_DISC],
         state="pending", shown_as="pending")
    cases[-1]["expect"]["must_not_show_as"] = ["recorded_absence", "refusal", UW_SHOWN]
    for c in cases:
        if c["kind"] == "display" and c["expect"]["covered_by"]:
            c["section"] = list(dict.fromkeys(c["section"] + [S_MAP]))
    return cases


# ---------------------------------------------------------------------------
# refusal-02.json: the two refusal reasons -02 adds
# ---------------------------------------------------------------------------

S_SEC = "§11 Security Considerations"
REASONS_02_ADDED = ["capacity_exceeded", "request_unauthenticated"]
REASONS_02 = REASONS + REASONS_02_ADDED
REFUSAL_02_NOTES = (
    "-02 adds capacity_exceeded (a limit of the responder's own: load, a size limit, a full replay "
    "cache, a transient fault) and request_unauthenticated (a requester authentication a deployment "
    "profile defines does not verify). registry.json and refusal.json stay as -00 fixes them; under "
    "-00 and -01 both tokens are unregistered. Signatures use the profile in refusal.json."
)


def refusal_02_cases(requests: list[dict]) -> list[dict]:
    digest = {c["id"]: c for c in requests}["pos-subject-record"]["request_json_digest"]
    cases: list[dict] = []
    for reason in REASONS_02_ADDED:
        obj = refusal(digest, reason)
        cases.append({
            "id": f"r02-reason-{reason}", "section": [S_REF, S_IANA],
            "description": f"A signed refusal of request pos-subject-record (JSON binding) with reason {reason}, "
            "registered by -02.",
            "refusal": obj, "request_case": "pos-subject-record",
            "signing_body": jcs({k: obj[k] for k in ("issued_at", "reason", "request_digest")}),
            "expect": {"signature": "valid", "reason_registered": True, "conformant": True}})
    obj = refusal(digest, "rate_limited")
    cases.append({
        "id": "r02-neg-unregistered-rate_limited", "section": [S_REF, S_IANA],
        "description": "Correctly signed, but rate_limited is not registered: a limit of the responder's own is "
        "capacity_exceeded.",
        "refusal": obj, "request_case": "pos-subject-record",
        "expect": {"signature": "valid", "reason_registered": False, "conformant": False}})
    for reason in REASONS_02_ADDED:
        for commitment, side in (("in_force", "inside"), ("lapsed", "after")):
            cases.append({
                "id": f"r02-ret-{side}-{reason}", "section": [S_RET],
                "description": f"A refusal with reason {reason} {side} until: never a breach"
                + (" (flooding a responder cannot manufacture broken commitments)."
                   if reason == "capacity_exceeded" else " (a property of the request)."),
                "facts": {"commitment": commitment, "refusal_reason": reason},
                "expect": {"classification": "no_breach"}})
    cases.append({
        "id": "r02-load-shedding-is-capacity_exceeded", "section": [S_SEC, S_REF],
        "description": "A responder declines for its own load. It refuses capacity_exceeded; policy_declined and "
        "not_authorized are statements about policy and are not used for load shedding.",
        "facts": {"cause": "responder_load"},
        "expect": {"reason": "capacity_exceeded", "not_reason": ["policy_declined", "not_authorized"]}})
    cases.append({
        "id": "r02-deadline-missed-under-load", "section": [S_DEADLINE, S_SEC],
        "description": "A responder cannot answer by the deadline only because of its own load. It refuses "
        "capacity_exceeded, not deadline_unmet, which states that the deadline itself cannot be met.",
        "facts": {"cause": "responder_load", "deadline": "would_be_missed"},
        "expect": {"reason": "capacity_exceeded", "not_reason": ["deadline_unmet"]}})
    for reason in REASONS_02_ADDED:
        cases.append({
            "id": f"r02-map-{reason}", "section": [S_MAP],
            "description": f"The illustrative status mapping of a refusal with reason {reason}: the requirement's "
            "status stays unknown; never withheld by policy, never evidence of non-satisfaction.",
            "facts": {"refusal_reason": reason},
            "expect": {"status_unknown": True, "withheld_by_policy": False,
                       "evidence_of_non_satisfaction": False}})
    return cases


# ---------------------------------------------------------------------------
# registry.json: the exact strings -00 fixes
# ---------------------------------------------------------------------------


def registry() -> dict:
    return {
        "section": [S_REQ, S_SUBJ, S_COV, S_BIND, S_IANA],
        "request_fields": {
            "subject": "REQUIRED",
            "coverage": "REQUIRED",
            "derivation": "OPTIONAL",
            "deadline": "OPTIONAL",
            "nonce": "RECOMMENDED",
            "route": "OPTIONAL",
        },
        "subject_forms": SUBJECT_FORMS,
        "coverage_members": ["expected_pin", "min_freshness"],
        "refusal_reasons": REASONS,
        "derivations": {"history_card/1": {"declared_fields": []}},
        "outcomes": ["artifact", "refusal", "recorded_absence"],
        "request_states": ["pending"],
        "subprotocol": "evidence-request/1",
        "not_registered_examples": ["no_such_record", "recorded_absence", "chain_segment"],
    }


# ---------------------------------------------------------------------------
# history-card-2.json: history_card/2 (-03 §8.1.2) in Checkpointed Local Log form
# ---------------------------------------------------------------------------
#
# The stream is a CLL: checkpoint p covers entries 0..p, so it is the MMR of p + 1 leaves, and its
# log_size is that MMR's node count, as the consistency proofs count it. Checkpoints are the
# profile's COSE_Sign1 cll-checkpoint statements (interop profile §6.2.1 step 7) and proofs are
# cll-consistency-proof octets (MMR -02 §7.1), both as lowercase hex. Receipts use a form fixed for
# these vectors only (HC2_NOTES).

DRAFT_03 = "draft-mih-agent-evidence-request-03"
S_HC2 = "§8.1.2 history_card/2"
S_HCR = "§8.1.3 Checkpoints Between Listed Entries"
HC2_MAX_WINDOW = 64
HC2_CHECKPOINTS = 1100  # positions 0..1099: more than 1024 checkpoints
HC2_WINDOW = 8
HC2_START = 1793491200  # 2026-11-01T00:00:00Z; checkpoint p is issued 300 s after p - 1


def _hc2_key(label: str) -> tuple[Ed25519PrivateKey, str]:
    return _key(hashlib.sha256(f"{DRAFT_03} history_card/2 vectors: {label}".encode()).digest())


HC2_LOG, HC2_LOG_PUB = _hc2_key("log key")
HC2_OTHER_LOG, HC2_OTHER_LOG_PUB = _hc2_key("a log key the requester does not accept")
HC2_WITNESS, HC2_WITNESS_PUB = _hc2_key("witness key")


def hc2_positions(n: int, window: int) -> list[int]:
    """P(n, W) of -03 §8.1.2, written from the text: {0}, n - 2^k for every 2^k <= n, and
    max(0, n - W + 1) .. n, ascending, each once."""
    out = {0}
    k = 0
    while (1 << k) <= n:
        out.add(n - (1 << k))
        k += 1
    out.update(range(max(0, n - window + 1), n + 1))
    return sorted(out)


def _mmr_all_ones(pos: int) -> bool:
    return pos != 0 and pos & (pos + 1) == 0


def _mmr_height(i: int) -> int:
    pos = i + 1
    while not _mmr_all_ones(pos):
        pos = pos - (1 << (pos.bit_length() - 1)) + 1
    return pos.bit_length() - 1


def _mmr_pair(pos: int, a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(pos.to_bytes(8, "big") + a + b).digest()


def _mmr_peaks(i: int) -> list[int]:
    out, peak, size = [], 0, i + 1
    while size:
        highest = (1 << ((size + 1).bit_length() - 1)) - 1
        peak += highest
        out.append(peak - 1)
        size -= highest
    return out


def _mmr_path(i: int, last: int) -> list[int]:
    path, g = [], _mmr_height(i)
    while True:
        off = 2 << g
        if _mmr_height(i + 1) > g:
            sib = i - off + 1
            i += 1
        else:
            sib = i + off - 1
            i += off
        if sib > last:
            return path
        path.append(sib)
        g += 1


def _mmr_root(i: int, node: bytes, proof: list[bytes]) -> bytes:
    root, g = node, _mmr_height(i)
    for sib in proof:
        if _mmr_height(i + 1) > g:
            i += 1
            root = _mmr_pair(i + 1, sib, root)
        else:
            i += 2 << g
            root = _mmr_pair(i + 1, root, sib)
        g += 1
    return root


class _Hc2Log:
    """The MMR over HC2_CHECKPOINTS entries, with the node count after each leaf."""

    def __init__(self, leaves: int) -> None:
        self.db: list[bytes] = []
        self.sizes: list[int] = []
        for n in range(leaves):
            entry = hashlib.sha256(f"{DRAFT_03} history_card/2 vectors: entry {n}".encode()).digest()
            self.db.append(hashlib.sha256(b"\x00" + entry).digest())
            g = 0
            while _mmr_height(len(self.db)) > g:
                i = len(self.db)
                self.db.append(_mmr_pair(i + 1, self.db[i - (2 << g)], self.db[i - 1]))
                g += 1
            self.sizes.append(len(self.db))

    def peaks(self, size: int) -> list[bytes]:
        return [self.db[p] for p in _mmr_peaks(size - 1)]

    def consistency(self, old: int, new: int) -> bytes:
        paths, roots = [], []
        for p in _mmr_peaks(old - 1):
            path = [self.db[j] for j in _mmr_path(p, new - 1)]
            paths.append(path)
            root = _mmr_root(p, self.db[p], path)
            if not roots or roots[-1] != root:
                roots.append(root)
        new_peaks = self.peaks(new)
        assert new_peaks[:len(roots)] == roots
        return cbor([old, new, paths, new_peaks[len(roots):]])


HC2_STREAM = _Hc2Log(HC2_CHECKPOINTS)


def _hc2_time(position: int) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(HC2_START + 300 * position, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hc2_checkpoint(position: int, key: Ed25519PrivateKey = HC2_LOG, pub: str = HC2_LOG_PUB,
                   issued_at: str | None = None, extra_claim: bytes = b"") -> bytes:
    """The cll-checkpoint statement at ``position``: COSE_Sign1 (tag 18) over the claims, with
    prev_size the node count of the checkpoint before it (0 for the first)."""
    size = HC2_STREAM.sizes[position]
    prev = HC2_STREAM.sizes[position - 1] if position else 0
    protected = cbor({1: -8, 4: bytes.fromhex(pub), 15: {1: "https://log.example", 2: "stream-a"}})
    payload = cbor({
        "kind": "cll-checkpoint", "log_size": size, "prev_size": prev,
        "issued_at": issued_at if issued_at is not None else _hc2_time(position),
        "commitment": cbor(HC2_STREAM.peaks(size)),
        "prev_commitment": cbor(HC2_STREAM.peaks(prev)) if prev else b"",
    })
    if extra_claim:
        # one more claim, written raw (these vectors' cbor() has no floats): bump the map's count
        assert 0xa0 <= payload[0] < 0xb7
        payload = bytes([payload[0] + 1]) + payload[1:] + extra_claim
    signature = key.sign(cbor(["Signature1", protected, b"", payload]))
    return b"\xd2" + cbor([protected, {}, payload, signature])


def hc2_receipt(checkpoint: bytes, key: Ed25519PrivateKey = HC2_WITNESS, pub: str = HC2_WITNESS_PUB) -> dict:
    body = {"checkpoint": sha256_hex(checkpoint), "witness": pub}
    return {**body, "sig": key.sign(jcs(body).encode("utf-8")).hex()}


def hc2_entry(position: int, previous: int | None, *, receipt: bool = True) -> dict:
    checkpoint = hc2_checkpoint(position)
    proof = None
    if previous is not None:
        proof = HC2_STREAM.consistency(HC2_STREAM.sizes[previous], HC2_STREAM.sizes[position]).hex()
    return {"position": position, "checkpoint": checkpoint.hex(),
            "receipts": [hc2_receipt(checkpoint)] if receipt else [], "consistency_from_previous": proof}


def hc2_history(positions: list[int]) -> list[dict]:
    """Entries at ``positions`` in order, each with the proof from the one listed before it."""
    return [hc2_entry(p, positions[i - 1] if i else None) for i, p in enumerate(positions)]


def hc2_card(n: int, window: int) -> dict:
    return {"window": window, "history": hc2_history(hc2_positions(n, window))}


def hc2_anchor(position: int) -> str:
    return sha256_hex(hc2_checkpoint(position))


HC2_FINDINGS = [
    "card_malformed", "window_out_of_range", "positions_not_increasing_from_zero", "position_missing",
    "position_unexpected", "checkpoint_invalid", "first_checkpoint_has_predecessor", "checkpoint_shrinks",
    "proof_invalid",
    "receipt_invalid", "anchor_mismatch",
]

HC2_NOTES = {
    "inputs": "Each case gives a card (the result map of §8.1.2), the anchor the response resolved (SHA-256 "
              "of the anchor checkpoint's octets, 64 lowercase hex) and the log keys the requester accepts "
              "for the stream (log_keys at the top of the file).",
    "result": "expect.valid is true when every check of §8.1.2 'Verifying' passes. Otherwise expect.finding "
              "is the first check that fails, in the order of HC2_FINDINGS: card_malformed (the result or an "
              "entry is not the maps and types of §8.1.2), then checks 1 to 7. These finding names are fixed "
              "for these vectors only.",
    "checks": "card_malformed: the card is not a map; window is not an unsigned integer; history is not a "
              "list; an entry is not a map with position (unsigned integer), checkpoint (hex text), receipts "
              "(a list) and consistency_from_previous (hex text or null). Members a profile adds are "
              "ignored. 1 window_out_of_range: window outside 1..64. 2 "
              "positions_not_increasing_from_zero: history is empty, the first position is not 0, or the "
              "positions do not strictly increase. 3 position_missing / position_unexpected: with n the last "
              "position, a position of P(n, window) is not listed (missing is checked first) or a listed "
              "position is not in P(n, window). 4 checkpoint_invalid: a checkpoint is not a well-formed "
              "cll-checkpoint (interop profile §6.2.1 step 7), its kid is not in log_keys, or its COSE_Sign1 "
              "signature does not verify; first_checkpoint_has_predecessor: the checkpoint at position 0 "
              "has a prev_size other than 0; checkpoint_shrinks: its log_size is smaller than the previous "
              "entry's. Entries are checked in order, each fully, before the next. 5 proof_invalid: the first entry carries a proof, a later entry carries none, the "
              "proof is not cll-consistency-proof octets whose tree sizes are the two checkpoints' log_size "
              "values, or it does not prove the entry's commitment extends the previous entry's (MMR -02 "
              "§7.1). 6 receipt_invalid: a receipt is not {checkpoint, witness, sig}, its checkpoint is not "
              "SHA-256 of its own entry's checkpoint octets, or sig is not an Ed25519 signature by witness "
              "over UTF-8 of JCS of {checkpoint, witness}. 7 anchor_mismatch: SHA-256 of the last "
              "checkpoint's octets is not the anchor.",
    "log_size": "log_size counts MMR nodes, as the consistency proofs' tree sizes do and as known "
                "implementations write it (interop profile v1 open point on the unit of log_size).",
    "receipts": "The receipt form {checkpoint, witness, sig} is fixed for these vectors only and is not "
                "registered; -03 leaves receipt encodings to the evidence mechanism. Which witnesses count "
                "is requester policy; these vectors only check that each receipt covers its checkpoint.",
}


def _hc2_case(case_id: str, description: str, card: Any, anchor: str, expect_finding: str | None,
              section: list[str] | None = None) -> dict:
    return {"id": case_id, "section": section or [S_HC2], "description": description, "card": card,
            "anchor": anchor,
            "expect": {"valid": True, "finding": None} if expect_finding is None
            else {"valid": False, "finding": expect_finding}}


def hc2_position_cases() -> list[dict]:
    out = []
    for n in (0, 1, 2, 3, 7, 8, 9, 63, 64, 65, 1023, 1024, 1099, 1000000):
        for window in (1, 8, 64):
            out.append({"n": n, "window": window, "positions": hc2_positions(n, window)})
    return out


def hc2_cases() -> list[dict]:
    n, w = HC2_CHECKPOINTS - 1, HC2_WINDOW
    anchor = hc2_anchor(n)
    good = hc2_card(n, w)
    listed = [e["position"] for e in good["history"]]
    cases = [
        _hc2_case("valid-1100-checkpoints", f"A card over {HC2_CHECKPOINTS} checkpoints (anchor position {n}), "
                  f"window {w}: {len(listed)} entries.", good, anchor, None),
        _hc2_case("valid-single-checkpoint", "A stream of one checkpoint: the card lists position 0 only.",
                  hc2_card(0, 1), hc2_anchor(0), None),
        _hc2_case("valid-window-covers-stream", "Window 64 over a stream of six checkpoints: every position "
                  "is listed.", hc2_card(5, 64), hc2_anchor(5), None),
        _hc2_case("valid-window-cap", "Window 64, the cap, over 1100 checkpoints.", hc2_card(n, 64), anchor,
                  None),
        _hc2_case("valid-no-receipts", "Entries with no receipts verify: receipts may be empty.",
                  {"window": w, "history": [{**e, "receipts": []} for e in good["history"]]}, anchor, None),
        _hc2_case("valid-profile-members", "Members a deployment profile adds to the result are ignored.",
                  {**good, "anchor": anchor, "evidence_stream": "stream-a"}, anchor, None),
    ]

    def neg(case_id: str, description: str, card: Any, finding: str, the_anchor: str = anchor) -> None:
        cases.append(_hc2_case(case_id, description, card, the_anchor, finding))

    def at(position: int) -> int:
        return listed.index(position)

    def replaced(index: int, **members: Any) -> dict:
        history = [dict(e) for e in good["history"]]
        history[index] = {**history[index], **members}
        return {"window": w, "history": history}

    neg("malformed-card-not-a-map", "The result is a list, not a map.", good["history"], "card_malformed")
    neg("malformed-entry-missing-receipts", "An entry without receipts.",
        {"window": w, "history": [{k: v for k, v in e.items() if k != "receipts"} if i == 3 else e
                                  for i, e in enumerate(good["history"])]}, "card_malformed")
    neg("malformed-position-text", "A position given as text.", replaced(2, position=str(listed[2])),
        "card_malformed")
    neg("window-zero", "Window 0 is outside 1 to 64.", {**good, "window": 0}, "window_out_of_range")
    neg("window-over-cap", "Window 65 is over the cap, even with the positions P(n, 65) gives.",
        {"window": 65, "history": hc2_history(hc2_positions(n, 65))}, "window_out_of_range")
    neg("history-empty", "No entries.", {"window": w, "history": []}, "positions_not_increasing_from_zero")
    first_dropped = hc2_history(listed[1:])
    neg("first-checkpoint-missing", "The card starts at position 1, not 0.",
        {"window": w, "history": first_dropped}, "positions_not_increasing_from_zero")
    neg("positions-repeat", "A position listed twice.",
        {"window": w, "history": good["history"][:5] + [good["history"][4]] + good["history"][5:]},
        "positions_not_increasing_from_zero")
    sample = n - 512
    missing = [p for p in listed if p != sample]
    neg("sample-position-missing", f"The sample at position {sample} (512 back from the anchor) is left out; "
        "the proofs still chain.", {"window": w, "history": hc2_history(missing)}, "position_missing")
    window_gap = [p for p in listed if p != n - 3]
    neg("window-position-missing", f"Position {n - 3} inside the window is left out; the proofs still chain.",
        {"window": w, "history": hc2_history(window_gap)}, "position_missing")
    extra = sorted(listed + [500])
    neg("extra-position", "Position 500, not in P(n, W), is listed; the proofs still chain.",
        {"window": w, "history": hc2_history(extra)}, "position_unexpected")
    neg("window-mismatch", "The positions are P(n, 8) but the card states window 4.", {**good, "window": 4},
        "position_unexpected")
    other_key = hc2_checkpoint(listed[5], HC2_OTHER_LOG, HC2_OTHER_LOG_PUB)
    neg("checkpoint-unaccepted-key", "One checkpoint is signed by a log key the requester does not accept.",
        replaced(5, checkpoint=other_key.hex()), "checkpoint_invalid")
    good_cp = bytearray(bytes.fromhex(good["history"][5]["checkpoint"]))
    good_cp[-1] ^= 0x01
    neg("checkpoint-bad-signature", "One checkpoint's COSE_Sign1 signature does not verify.",
        replaced(5, checkpoint=bytes(good_cp).hex()), "checkpoint_invalid")
    neg("checkpoint-not-cose", "One checkpoint is not a cll-checkpoint statement.",
        replaced(5, checkpoint="a0"), "checkpoint_invalid")
    neg("checkpoint-shrinks", f"The entry at position {listed[6]} carries the checkpoint of position "
        f"{listed[4]}, which covers fewer entries than the one before it.",
        replaced(6, checkpoint=hc2_checkpoint(listed[4]).hex()), "checkpoint_shrinks")
    broken = HC2_STREAM.consistency(HC2_STREAM.sizes[listed[3]], HC2_STREAM.sizes[listed[5]]).hex()
    neg("proof-broken", f"The proof into position {listed[5]} is a valid proof from position {listed[3]}, not "
        f"from {listed[4]}, the entry before it.", replaced(5, consistency_from_previous=broken),
        "proof_invalid")
    tampered = bytearray(bytes.fromhex(good["history"][7]["consistency_from_previous"]))
    tampered[-1] ^= 0x01
    neg("proof-tampered", "One proof's last peak has a flipped bit.",
        replaced(7, consistency_from_previous=bytes(tampered).hex()), "proof_invalid")
    neg("proof-absent", "A later entry carries no proof.", replaced(4, consistency_from_previous=None),
        "proof_invalid")
    neg("first-entry-has-proof", "The first entry carries a proof.",
        replaced(0, consistency_from_previous=good["history"][1]["consistency_from_previous"]), "proof_invalid")
    other_receipt = hc2_receipt(hc2_checkpoint(listed[3]))
    neg("receipt-other-checkpoint", "A receipt covers another entry's checkpoint.",
        replaced(4, receipts=[other_receipt]), "receipt_invalid")
    bad_sig = dict(good["history"][4]["receipts"][0])
    bad_sig["sig"] = ("0" if bad_sig["sig"][0] != "0" else "1") + bad_sig["sig"][1:]
    neg("receipt-bad-signature", "A receipt's signature does not verify.", replaced(4, receipts=[bad_sig]),
        "receipt_invalid")
    hex_space = replaced(2, checkpoint="  " + good["history"][2]["checkpoint"])
    neg("hex-with-spaces", "A checkpoint's hex text with two leading spaces.", hex_space, "card_malformed")
    neg("hex-uppercase", "A checkpoint's hex text in upper case.",
        replaced(2, checkpoint=good["history"][2]["checkpoint"].upper()), "card_malformed")
    late = hc2_checkpoint(5)
    neg("first-checkpoint-has-predecessor", "A one-entry card whose position 0 carries the checkpoint of stream "
        "position 5, which commits to an earlier checkpoint (prev_size not 0).",
        {"window": 1, "history": [{"position": 0, "checkpoint": late.hex(), "receipts": [],
                                   "consistency_from_previous": None}]}, "first_checkpoint_has_predecessor",
        sha256_hex(late))
    for case_id, description, issued, finding in (
        ("issued-at-lowercase", "The first checkpoint's issued_at in lower-case t and z, an RFC 3339 form.",
         "2026-11-01t00:00:00z", None),
        ("issued-at-offset", "The first checkpoint's issued_at with a numeric offset.",
         "2026-10-31T19:00:00-05:00", None),
        ("issued-at-not-a-date", "The first checkpoint's issued_at names 30 February.",
         "2026-02-30T00:00:00Z", "checkpoint_invalid"),
    ):
        cp = hc2_checkpoint(0, issued_at=issued)
        card = {"window": 1, "history": [{"position": 0, "checkpoint": cp.hex(), "receipts": [],
                                          "consistency_from_previous": None}]}
        cases.append(_hc2_case(case_id, description, card, sha256_hex(cp), finding))
    float_cp = hc2_checkpoint(0, extra_claim=b"\x61x\xf9\x3e\x00")
    cases.append(_hc2_case("checkpoint-claim-float", "The first checkpoint's claims carry one more member, x, "
                           "whose value is the half-precision float 1.5 (f9 3e 00), signed: outside the "
                           "profile's data model, so not a well-formed cll-checkpoint.",
                           {"window": 1, "history": [{"position": 0, "checkpoint": float_cp.hex(), "receipts": [],
                                                      "consistency_from_previous": None}]},
                           sha256_hex(float_cp), "checkpoint_invalid"))
    long_tag = b"\xd8\x12" + hc2_checkpoint(0)[1:]
    cases.append(_hc2_case("checkpoint-tag-long-form", "The first checkpoint's tag 18 written in two octets "
                           "(d8 12), not one: still a well-formed cll-checkpoint, whose signature covers only "
                           "the protected header and payload.",
                           {"window": 1, "history": [{"position": 0, "checkpoint": long_tag.hex(), "receipts": [],
                                                      "consistency_from_previous": None}]},
                           sha256_hex(long_tag), None))
    neg("anchor-mismatch", f"The card ends at position {n}, but the response resolved the checkpoint at "
        f"position {n - 1}.", good, "anchor_mismatch", hc2_anchor(n - 1))
    return cases


# ---------------------------------------------------------------------------
# checkpoints-range.json: the checkpoint_range subject (-03 §3.1, §8.1.3)
# ---------------------------------------------------------------------------

# The -03 responder: RESPONDER's state, whose two anchors are its two checkpoints, at checkpoint
# positions 0 (size 40) and 1 (size 42) in the order listed, and which also supports history_card/2.
RESPONDER_03 = {**RESPONDER, "supported_derivations": {
    "history_card/1": ["full_history", "checkpoints"], "history_card/2": ["full_history", "checkpoints"]}}
PIN_40 = {"expected_pin": ANCHOR_40}


def checkpoints_range_request_cases() -> list[dict]:
    c = request_case
    return [
        c("pos-checkpoint-range", [S_SUBJ], "checkpoint_range at positions 0 through 1.",
          _req({"checkpoint_range": [0, 1]}, PIN_42, nonce="n-0301"), WELL_FORMED),
        c("pos-checkpoint-range-one", [S_SUBJ], "a range of one checkpoint, a = b.",
          _req({"checkpoint_range": [1, 1]}, PIN_42, nonce="n-0302"), WELL_FORMED),
        c("pos-checkpoints-unranged", [S_SUBJ], "checkpoints with null content, as in -02 and unchanged.",
          _req({"checkpoints": None}, PIN_42, nonce="n-0303"), WELL_FORMED),
        c("neg-checkpoint-range-reversed", [S_SUBJ], "a exceeds b.",
          _req({"checkpoint_range": [1, 0]}, PIN_42, nonce="n-0304"), MALFORMED("request_malformed")),
        c("neg-checkpoint-range-negative", [S_SUBJ], "a negative bound.",
          _req({"checkpoint_range": [-1, 1]}, PIN_42, nonce="n-0305"), MALFORMED("request_malformed")),
        c("neg-checkpoint-range-text", [S_SUBJ], "a bound given as text.",
          _req({"checkpoint_range": ["0", 1]}, PIN_42, nonce="n-0306"), MALFORMED("request_malformed")),
        c("neg-checkpoint-range-one-bound", [S_SUBJ], "one bound only.",
          _req({"checkpoint_range": [0]}, PIN_42, nonce="n-0307"), MALFORMED("request_malformed")),
        c("neg-checkpoint-range-three-bounds", [S_SUBJ], "three bounds.",
          _req({"checkpoint_range": [0, 1, 2]}, PIN_42, nonce="n-0308"), MALFORMED("request_malformed")),
        c("neg-checkpoints-content-text", [S_SUBJ], "checkpoints content that is not null.",
          _req({"checkpoints": "all"}, PIN_42, nonce="n-0309"), MALFORMED("request_malformed")),
        c("neg-checkpoints-content-range", [S_SUBJ], "checkpoints carrying two bounds: the range has its "
          "own form, checkpoint_range, and checkpoints carries no content.",
          _req({"checkpoints": [0, 1]}, PIN_42, nonce="n-0320"), MALFORMED("request_malformed")),
        c("neg-checkpoint-range-null", [S_SUBJ], "checkpoint_range with no bounds: its content is two "
          "unsigned integers.",
          _req({"checkpoint_range": None}, PIN_42, nonce="n-0321"), MALFORMED("request_malformed")),
    ]


def checkpoints_range_resolution_cases() -> list[dict]:
    art = {"answer": "artifact"}

    def ref(reason: str) -> dict:
        return {"answer": "refusal", "reason": reason}

    c = request_case
    return [
        c("res-checkpoint-range-served", [S_SUBJ, S_HCR], "positions 0 through 1 under the anchor at "
          "position 1: served.", _req({"checkpoint_range": [0, 1]}, PIN_42, nonce="n-0311"), art),
        c("res-checkpoint-range-past-anchor", [S_HCR], "position 1 is past the anchor at position 0.",
          _req({"checkpoint_range": [0, 1]}, PIN_40, nonce="n-0312"), ref("coverage_unsatisfiable")),
        c("res-checkpoint-range-at-anchor", [S_HCR], "position 0 under the anchor at position 0: served.",
          _req({"checkpoint_range": [0, 0]}, PIN_40, nonce="n-0313"), art),
        c("res-checkpoint-range-beyond-stream", [S_HCR], "position 2: no checkpoint there yet, past every "
          "anchor.", _req({"checkpoint_range": [0, 2]}, PIN_42, nonce="n-0314"), ref("coverage_unsatisfiable")),
        c("res-history-card-2", [S_DER, S_HC2], "history_card/2 over checkpoints: served.",
          _req({"checkpoints": None}, PIN_42, derivation="history_card/2", nonce="n-0315"), art),
        c("res-history-card-2-full-history", [S_DER, S_HC2], "history_card/2 over full_history: served.",
          _req({"full_history": None}, PIN_42, derivation="history_card/2", nonce="n-0316"), art),
        c("res-history-card-2-record", [S_DER, S_HC2], "history_card/2 is not defined for a record.",
          _req({"record": R1}, PIN_42, derivation="history_card/2", nonce="n-0317"), ref("no_such_subject")),
        c("res-history-card-2-checkpoint-range", [S_HCR], "history_card/2 over a checkpoint_range subject.",
          _req({"checkpoint_range": [0, 1]}, PIN_42, derivation="history_card/2", nonce="n-0318"),
          ref("no_such_subject")),
        c("res-history-card-1-checkpoint-range", [S_HCR], "history_card/1 over a checkpoint_range subject.",
          _req({"checkpoint_range": [0, 1]}, PIN_42, derivation="history_card/1", nonce="n-0319"),
          ref("no_such_subject")),
    ]


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _corpus(name: str, description: str, cases: list[dict], *, draft: str = DRAFT, **extra: Any) -> dict:
    out: dict[str, Any] = {
        "draft": draft,
        "provenance": "spec-derived",
        "corpus": name,
        "description": description,
    }
    out.update(extra)
    out["count"] = len(cases)
    out["cases"] = cases
    return out


def build() -> dict[str, bytes]:
    requests = request_cases()
    files: dict[str, bytes] = {
        "registry.json": _dump({"draft": DRAFT, "provenance": "spec-derived", **registry()}),
        "request.json": _dump(_corpus(
            "request", "Request map validation: well formed, or the exact refusal reason.", requests)),
        "resolution.json": _dump(_corpus(
            "resolution", "Exact-match subject resolution and the most specific refusal reason, against "
            "one declared responder state.", resolution_cases(), responder=RESPONDER)),
        "carries.json": _dump(_corpus(
            "carries", "Which record members carry a correlation identifier or cite an exchange half, "
            "per record format. Each record is reduced to the members the designation reads.",
            carries_cases(), draft=DRAFT_01)),
        "categories.json": _dump(_corpus(
            "categories", "The OPTIONAL categories request field, for a responder that implements it "
            "(one that does not ignores the field, §3.9): well formed or request_malformed, and "
            "categories as an input of the artifact for caller invariance.", categories_cases(),
            draft=DRAFT_01, notes=CATEGORIES_NOTES)),
        "carriage.json": _dump(_corpus(
            "carriage", "A2A and MCP carriage: the request digest over decoded octets, the envelope's "
            "request digest, media types, and classification by the reply alone.", carriage_cases(),
            draft=DRAFT_01)),
        "digest.json": _dump(_corpus(
            "digest", "The request digest: SHA-256 over the request bytes as received.", digest_cases())),
        "refusal.json": _dump(_corpus(
            "refusal", "Signed refusals: every registered reason, tampering, and non-conforming reasons.",
            refusal_cases(requests), signature_profile=SIGNATURE_PROFILE,
            keys={"primary": {"seed_hex": PRIMARY_SEED.hex(), "public_key_hex": PRIMARY_PUB},
                  "other": {"seed_hex": OTHER_SEED.hex(), "public_key_hex": OTHER_PUB}})),
        "refusal-imported.json": IMPORTED_REFUSAL_BYTES,
        "outcomes.json": _dump(_corpus(
            "outcomes", "The three outcomes, pending, and the three-state discipline.", outcome_cases())),
        "invariance.json": _dump(_corpus(
            "invariance", "Caller invariance: byte-identical artifacts for the same subject and anchor.",
            invariance_cases())),
        "retention.json": _dump(_corpus(
            "retention", "Retention commitments: the breach table and commitment subject forms.",
            retention_cases())),
        "refusal-02.json": _dump(_corpus(
            "refusal-02", "The two refusal reasons -02 adds: signed refusals, the retention breach table and "
            "the status mapping.", refusal_02_cases(requests), draft=DRAFT_02, notes=REFUSAL_02_NOTES,
            refusal_reasons=REASONS_02, signature_profile=SIGNATURE_PROFILE)),
        "unavailable-window.json": _dump(_corpus(
            "unavailable-window", "Unavailable-window statements: which a reader recognizes, which "
            "cover an absence, and how the reader shows a covered absence.", unavailable_window_cases(),
            draft=DRAFT_02, notes=UW_NOTES, reason_classes=UW_CLASSES, shown_as=UW_SHOWN,
            signature_profile=UW_SIGNATURE_PROFILE)),
        "history-card-2.json": _dump(_corpus(
            "history-card-2", "history_card/2 in Checkpointed Local Log form: the positions P(n, W), and "
            "whether a card verifies or the first check it fails.", hc2_cases(), draft=DRAFT_03,
            notes=HC2_NOTES, findings=HC2_FINDINGS, max_window=HC2_MAX_WINDOW, log_keys=[HC2_LOG_PUB],
            positions=hc2_position_cases())),
        "checkpoints-range.json": _dump(_corpus(
            "checkpoints-range", "The checkpoint_range subject and history_card/2 resolution: request "
            "validation (request_cases) and the most specific refusal reason against the -03 responder "
            "(cases).", checkpoints_range_resolution_cases(), draft=DRAFT_03, responder=RESPONDER_03,
            checkpoint_positions={ANCHOR_40: 0, ANCHOR_42: 1},
            derivations={"history_card/1": {"declared_fields": []}, "history_card/2": {"declared_fields": []}},
            request_cases=checkpoints_range_request_cases())),
    }
    if sha256_hex(files["refusal-imported.json"]) != IMPORTED_REFUSAL_SHA256:
        raise SystemExit("imported refusal vector bytes drifted")
    manifest = {
        "draft": DRAFT,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_evidence_request_vectors.py",
        "ambiguities": AMBIGUITY,
        "files": [
            {"path": name, "sha256": sha256_hex(data),
             "count": json.loads(data).get("count") if name != "refusal-imported.json" else 1}
            for name, data in sorted(files.items())
        ],
    }
    files["manifest.json"] = _dump(manifest)
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    files = build()
    for name, data in files.items():
        (out / name).write_bytes(data)
    lines = []
    for path in sorted(p for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS"):
        lines.append(f"{sha256_hex(path.read_bytes())}  {path.name}")
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
