#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the draft-mih-agent-evidence-request-00 conformance vectors.

Every expected result below is written by hand from the text of
``spec/draft-mih-agent-evidence-request-00.md`` and cites the section it comes
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
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "evidence-request"
DRAFT = "draft-mih-agent-evidence-request-00"

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


def refusal(request_digest: Any, reason: Any, issued_at: Any = ISSUED_AT) -> dict:
    """A refusal object signed with the primary key over the three members."""
    body = {"issued_at": issued_at, "reason": reason, "request_digest": request_digest}
    return {**body, "key_id": PRIMARY_PUB, "sig": sign_body(body)}


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
# Writing
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _corpus(name: str, description: str, cases: list[dict], **extra: Any) -> dict:
    out: dict[str, Any] = {
        "draft": DRAFT,
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
