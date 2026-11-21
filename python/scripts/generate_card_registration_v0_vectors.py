#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the card registration vectors of ``spec/standard-history-v0.md`` §13.

A card statement is a SCITT Transparent Statement about one card: a COSE_Sign1 under the holder
key whose attached payload is the SHA-256 of the card octets, with the transparency services'
Receipts in its unprotected ``receipts`` (394). Each Receipt is in the one form of
``spec/interop-profile-v1.md`` §6.2.2, with the statement entry (SHA-256 over the statement's
Sig_structure) as its leaf entry. Each case gives the card octets, the holder key, the statements
beside the card in the order received, a transparency policy and the ``card_registered`` report
§13.3 gives.

Every per-statement expected result is written here by hand from §13; the card-level status,
service and time are derived from those results by §13.3's aggregation rule in ``case()``. The CBOR encoder, the RFC 9162 tree and
the P-256 signer are those of ``generate_anchor_witness_v1_vectors.py``, a generator too; this
script imports no repository implementation. Keys are test keys derived from public labels, and
the output is deterministic.

Output: ``vectors/card-registration-v0/`` (or ``--out DIR``). ``README.md`` is hand-written; when
present in the output directory it is included in ``SHA256SUMS`` but never rewritten.
Dependencies: ``cryptography`` (Ed25519 signing only).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from generate_anchor_witness_v1_vectors import (  # noqa: E402
    P256Key,
    Raw,
    Tag,
    cbor,
    label_digest,
    mth,
    path,
    sig_structure,
    tampered,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "card-registration-v0"
SPEC = "spec/standard-history-v0.md"
CARD_SOURCE = ("vectors/standard-history-v0/vectors.json", "person-3-months")


def ed_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(label_digest("card-registration-v0 key " + label))


def ed_spki(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def raw_pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def jcs(value: Any) -> bytes:
    """JCS (RFC 8785) of a card: ASCII strings and integers only, so sorted compact JSON is JCS."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load_card() -> dict:
    corpus = json.loads((ROOT / CARD_SOURCE[0]).read_text())
    return next(c for c in corpus["cases"] if c["id"] == CARD_SOURCE[1])["inputs"]["card"]


CARD_OBJ = load_card()
CARD = jcs(CARD_OBJ)
OTHER_CARD = jcs({**CARD_OBJ, "since": "2026-04"})
CARD_DIGEST = hashlib.sha256(CARD).digest()
ANCHOR_HEX = CARD_OBJ["anchor"]

HOLDER, OTHER_HOLDER = ed_key("holder"), ed_key("other holder")
HOLDER_ID = raw_pub(HOLDER).hex()
SVC_A, SVC_C, SVC_OUTSIDE = ed_key("service a"), ed_key("service c"), ed_key("service outside")
SVC_B = P256Key("card-registration-v0 service b")
T1, T2 = 1795190400, 1795194000  # 2026-11-20T12:00:00Z and 13:00:00Z

POLICY = {"witnesses": [
    {"name": "service-a", "keys": [ed_spki(SVC_A).hex()]},
    {"name": "service-b", "keys": [SVC_B.spki().hex()]},
    {"name": "service-c", "keys": [ed_spki(SVC_C).hex()]},
]}
ED25519_ONLY = {"witnesses": [w for w in POLICY["witnesses"] if w["name"] != "service-b"]}


def protected(**over: Any) -> dict:
    headers: dict = {1: -8, 15: {1: HOLDER_ID, 2: ANCHOR_HEX}}
    headers.update({k: v for k, v in over.items()})
    return headers


def statement_parts(*, headers: dict | None = None, payload: Any = CARD_DIGEST,
                    key: Ed25519PrivateKey = HOLDER, protected_raw: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """``(protected octets, payload, signature)``; the signature is over the Sig_structure."""
    prot = protected_raw if protected_raw is not None else cbor(protected() if headers is None else headers)
    return prot, payload, key.sign(sig_structure(prot, payload))


def entry_of(prot: bytes, payload: bytes) -> bytes:
    """The statement entry E: SHA-256 over the Sig_structure (§13.1)."""
    return hashlib.sha256(sig_structure(prot, payload)).digest()


def entries_with(entry: bytes) -> tuple[list[bytes], int]:
    entries = [label_digest(f"card-registration-v0 entry {i}") for i in range(6)]
    entries[3] = entry
    return entries, 3


def receipt_over(entry: bytes, key: Any, *, iat: Any = None, proofs: list | None = None) -> bytes:
    """An IP1 §6.2.2 Receipt whose leaf entry is ``entry``."""
    entries, index = entries_with(entry)
    alg = -7 if isinstance(key, P256Key) else -8
    prot: dict = {1: alg, 395: 1}
    if iat is not None:
        prot[15] = {6: iat}
    prot_bytes = cbor(prot)
    proof = cbor([len(entries), index, path(index, entries)])
    body = [prot_bytes, {396: {-1: [proof] if proofs is None else proofs}}, None,
            key.sign(sig_structure(prot_bytes, mth(entries)))]
    return cbor(Tag(18, body))


def statement(receipts: list[bytes] | None = None, *, parts: tuple[bytes, bytes, bytes] | None = None,
              unprotected: dict | None = None, payload_slot: Any = None, tag: int | None = 18,
              signature: bytes | None = None) -> bytes:
    prot, payload, sig = parts if parts is not None else statement_parts()
    unprot = unprotected if unprotected is not None else {394: receipts or []}
    body = [prot, unprot, payload if payload_slot is None else payload_slot, sig if signature is None else signature]
    return cbor(Tag(tag, body) if tag is not None else body)


GOOD_PARTS = statement_parts()
E = entry_of(GOOD_PARTS[0], GOOD_PARTS[1])


def r(key: Any, iat: Any = None, entry: bytes = E) -> bytes:
    return receipt_over(entry, key, iat=iat)


def passed(service: str, time: int | None = None) -> dict:
    return {"status": "PASS", "service": service, "registration_time": time}


def status(value: str) -> dict:
    return {"status": value, "service": None, "registration_time": None}


def case(name: str, description: str, statements: list[bytes], results: list[dict], *,
         policy: dict | None = None, card: bytes = CARD) -> dict:
    statuses = {x["status"] for x in results}
    overall = ("NOT_PRESENT" if not results else "PASS" if "PASS" in statuses
               else "FAIL" if "FAIL" in statuses else "NOT_CHECKED")
    passing = [x for x in results if x["status"] == "PASS"]
    timed = [x for x in passing if x["registration_time"] is not None]
    chosen = min(timed, key=lambda x: x["registration_time"]) if timed else (passing[0] if passing else None)
    return {
        "name": name,
        "description": description,
        "card": card.hex(),
        "holder": HOLDER_ID,
        "anchor": ANCHOR_HEX,
        "statements": [s.hex() for s in statements],
        "policy": "default" if policy is None else policy,
        "expected": {
            "status": overall,
            "statements": results,
            "service": chosen["service"] if chosen else None,
            "registration_time": chosen["registration_time"] if chosen else None,
        },
    }


def with_headers(headers: dict, payload: bytes = CARD_DIGEST, key: Ed25519PrivateKey = HOLDER) -> bytes:
    """A statement under ``headers``, signed, with one passing-form Receipt over its own entry."""
    parts = statement_parts(headers=headers, payload=payload, key=key)
    entry = entry_of(parts[0], parts[1])
    return statement([receipt_over(entry, SVC_A, iat=T1)], parts=parts)


def cases() -> list[dict]:
    a1, a2, c1, a0 = r(SVC_A, T1), r(SVC_A, T2), r(SVC_C, T1), r(SVC_A)
    b1 = r(SVC_B, T1)
    good = statement([a1])
    # A statement over the other card, by the holder, with its own valid Receipt.
    other_parts = statement_parts(payload=hashlib.sha256(OTHER_CARD).digest())
    other_card_stmt = statement([receipt_over(entry_of(other_parts[0], other_parts[1]), SVC_A, iat=T1)],
                                parts=other_parts)
    other_key_parts = statement_parts(key=OTHER_HOLDER)
    other_key_stmt = statement([receipt_over(entry_of(other_key_parts[0], other_key_parts[1]), SVC_A, iat=T1)],
                               parts=other_key_parts)
    other_iss = with_headers({1: -8, 15: {1: raw_pub(OTHER_HOLDER).hex(), 2: ANCHOR_HEX}}, key=OTHER_HOLDER)
    return [
        # PASS
        case("pass-eddsa-time", "one statement with one EdDSA Receipt that carries a registration time",
             [good], [passed("service-a", T1)]),
        case("pass-eddsa-no-time", "a Receipt with no CWT_Claims: PASS with no registration time",
             [statement([a0])], [passed("service-a")]),
        case("pass-es256", "an ES256 Receipt under a P-256 service key", [statement([b1])],
             [passed("service-b", T1)]),
        case("pass-second-receipt", "a failing Receipt, then a passing one: the statement passes",
             [statement([tampered(c1), a1])], [passed("service-a", T1)]),
        case("pass-earliest-receipt", "two passing Receipts: the earlier time, with the service that signed it",
             [statement([a2, c1])], [passed("service-c", T1)]),
        case("pass-kid-content-type", "a kid byte string, a content type and another CWT claim",
             [with_headers({1: -8, 3: "application/json", 4: b"holder", 15: {1: HOLDER_ID, 2: ANCHOR_HEX, 6: T1}})],
             [passed("service-a", T1)]),
        case("pass-private-label", "a private-use protected label (below -65536)",
             [with_headers({1: -8, 15: {1: HOLDER_ID, 2: ANCHOR_HEX}, -65537: "x"})], [passed("service-a", T1)]),
        case("pass-large-protected", "a private-use value of 65,536 octets: a protected header over 64 KiB",
             [with_headers({1: -8, 15: {1: HOLDER_ID, 2: ANCHOR_HEX}, -65537: b"\x00" * 65536})],
             [passed("service-a", T1)]),
        case("large-bad-signature-beside-pass", "a large statement whose signature fails, then a passing one",
             [statement([a1], parts=(cbor({1: -8, 15: {1: HOLDER_ID, 2: ANCHOR_HEX}, -65537: b"\x00" * 65536}),
                                     CARD_DIGEST, GOOD_PARTS[2])), statement([a2])],
             [status("FAIL"), passed("service-a", T2)]),
        case("pass-beside-fail", "a failing statement takes nothing from a passing one",
             [other_card_stmt, statement([a2])], [status("FAIL"), passed("service-a", T2)]),
        case("two-statements-earliest", "two passing statements: the earlier time and its service",
             [statement([a2]), statement([c1])], [passed("service-a", T2), passed("service-c", T1)]),
        # NOT_PRESENT and NOT_CHECKED
        case("no-statement", "nothing beside the card", [], []),
        case("policy-empty", "the policy lists no service", [good], [status("NOT_CHECKED")],
             policy={"witnesses": []}),
        case("es256-no-p256-key", "an ES256 Receipt and a policy with Ed25519 keys only", [statement([b1])],
             [status("NOT_CHECKED")], policy=ED25519_ONLY),
        case("not-checked-beside-pass", "a statement not checked beside a passing one: PASS",
             [statement([b1]), good], [status("NOT_CHECKED"), passed("service-a", T1)], policy=ED25519_ONLY),
        case("not-checked-beside-fail", "a statement not checked beside a failing one: FAIL",
             [statement([b1]), other_card_stmt], [status("NOT_CHECKED"), status("FAIL")], policy=ED25519_ONLY),
        case("receipt-not-checked-and-failing", "one Receipt not checked and one failing in a statement: FAIL (step 5)",
             [statement([b1, tampered(a1)])], [status("FAIL")], policy=ED25519_ONLY),
        # FAIL: about another card, by another key, or not by an accepted service (steps 2 to 5)
        case("other-card", "a statement over another card's digest", [other_card_stmt], [status("FAIL")]),
        case("card-changed", "the card octets beside the statement are another card's", [good],
             [status("FAIL")], card=OTHER_CARD),
        case("other-key", "signed by another key, iss still naming the holder", [other_key_stmt], [status("FAIL")]),
        case("other-iss", "iss names another key, which signed it", [other_iss], [status("FAIL")]),
        case("other-sub", "sub names another anchor",
             [with_headers({1: -8, 15: {1: HOLDER_ID, 2: "00" * 32}})], [status("FAIL")]),
        case("signature-tampered", "one bit of the statement's signature flipped",
             [statement([a1], signature=tampered(GOOD_PARTS[2]))], [status("FAIL")]),
        case("receipt-over-card-digest", "a Receipt whose leaf entry is the card digest, not the statement entry",
             [statement([r(SVC_A, T1, entry=CARD_DIGEST)])], [status("FAIL")]),
        case("receipt-unlisted-service", "a Receipt by a key the policy does not list",
             [statement([r(SVC_OUTSIDE, T1)])], [status("FAIL")]),
        case("receipt-tampered", "the statement's only Receipt is tampered", [statement([tampered(a1)])],
             [status("FAIL")]),
        # FAIL: not of the form (step 1)
        case("untagged", "a COSE_Sign1 without tag 18", [statement([a1], tag=None)], [status("FAIL")]),
        case("tag-17", "an outer tag 17 in place of 18", [statement([a1], tag=17)], [status("FAIL")]),
        case("signature-63", "a signature of 63 octets", [statement([a1], signature=b"\x00" * 63)], [status("FAIL")]),
        case("kid-text", "a kid that is text", [with_headers({1: -8, 4: "holder", 15: {1: HOLDER_ID, 2: ANCHOR_HEX}})],
             [status("FAIL")]),
        case("content-type-int", "a content type that is an integer",
             [with_headers({1: -8, 3: 50, 15: {1: HOLDER_ID, 2: ANCHOR_HEX}})], [status("FAIL")]),
        case("cwt-not-map", "CWT_Claims that is not a map", [with_headers({1: -8, 15: [HOLDER_ID, ANCHOR_HEX]})],
             [status("FAIL")]),
        case("iss-bytes", "an iss that is a byte string",
             [with_headers({1: -8, 15: {1: bytes.fromhex(HOLDER_ID), 2: ANCHOR_HEX}})], [status("FAIL")]),
        case("sub-bytes", "a sub that is a byte string",
             [with_headers({1: -8, 15: {1: HOLDER_ID, 2: bytes.fromhex(ANCHOR_HEX)}})], [status("FAIL")]),
        case("receipt-not-bytes", "a receipts element that is not a byte string",
             [statement(unprotected={394: [a1, 5]})], [status("FAIL")]),
        case("alg-es256", "alg ES256: a card statement is EdDSA under the holder key",
             [with_headers({1: -7, 15: {1: HOLDER_ID, 2: ANCHOR_HEX}})], [status("FAIL")]),
        case("crit-present", "a crit label", [with_headers({1: -8, 2: [1], 15: {1: HOLDER_ID, 2: ANCHOR_HEX}})],
             [status("FAIL")]),
        case("hash-envelope-label", "payload_hash_alg (258), outside the closed set",
             [with_headers({1: -8, 15: {1: HOLDER_ID, 2: ANCHOR_HEX}, 258: -16})], [status("FAIL")]),
        case("no-cwt-claims", "no CWT_Claims", [with_headers({1: -8})], [status("FAIL")]),
        case("no-iss", "CWT_Claims without iss", [with_headers({1: -8, 15: {2: ANCHOR_HEX}})], [status("FAIL")]),
        case("no-sub", "CWT_Claims without sub", [with_headers({1: -8, 15: {1: HOLDER_ID}})], [status("FAIL")]),
        case("payload-31", "a payload of 31 octets", [with_headers(protected(), payload=CARD_DIGEST[:31])],
             [status("FAIL")]),
        case("payload-detached", "a detached payload (nil)", [statement([a1], payload_slot=Raw(b"\xf6"))],
             [status("FAIL")]),
        case("unprotected-extra", "an unprotected label besides receipts",
             [statement(unprotected={4: b"k", 394: [a1]})], [status("FAIL")]),
        case("no-receipt", "receipts is an empty array", [statement([])], [status("FAIL")]),
        case("no-receipts-label", "no receipts label", [statement(unprotected={})], [status("FAIL")]),
        case("seventeen-receipts", "17 Receipts", [statement([a1] * 17)], [status("FAIL")]),
        case("trailing-octets", "an octet after the COSE_Sign1", [good + b"\x00"], [status("FAIL")]),
        case("not-cbor", "octets that are not CBOR", [b"\xff\xff"], [status("FAIL")]),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    corpus = {
        "description": "Card statements beside a Standard History card and the card_registered report (§13). "
                       "Generated by python/scripts/generate_card_registration_v0_vectors.py. The card is "
                       f"{CARD_SOURCE[1]} of {CARD_SOURCE[0]}, as JCS octets. Times are NumericDates; service keys are "
                       "hex DER SubjectPublicKeyInfo test keys and the holder key a raw Ed25519 key identifier, all "
                       "derived from public labels.",
        "spec": SPEC,
        "sections": ["§13"],
        "policies": {"default": POLICY},
        "cases": cases(),
    }
    vectors = json.dumps(corpus, indent=2, sort_keys=False) + "\n"
    (out / "vectors.json").write_text(vectors)
    manifest = {
        "spec": SPEC,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_card_registration_v0_vectors.py",
        "files": [{"path": "vectors.json", "sha256": hashlib.sha256(vectors.encode()).hexdigest(),
                   "count": len(corpus["cases"])}],
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    names = sorted(p.name for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    sums = "".join(f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n" for n in names)
    (out / "SHA256SUMS").write_text(sums)


if __name__ == "__main__":
    main()
