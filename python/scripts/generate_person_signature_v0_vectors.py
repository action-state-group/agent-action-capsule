#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the person signature vectors (``spec/person-signature-v0.md``, cited as PS).

Each case is one signed record's digest, the verifier inputs of PS §6.1, a ``person_signatures``
array (or none) and the expected result: each matching person signature's status and reason
(PS §6.2) and the record's ``person_signature`` status (PS §6.3). The cases cover:

- valid assertions under ES256 and Ed25519 keys, with the UV flag clear, a non-zero signature
  counter, extra client data members in another order, client data with whitespace or a byte order
  mark, extension output, a permitted cross-origin ceremony, a required UV flag that is set, and
  person and excluded keys under an undefined algorithm among the inputs;
- policy negatives whose assertions are correctly signed over what they hold, so a verifier that
  checks only the signature fails them: a wrong type, a wrong challenge (another record's, the
  digest in hexadecimal, the signed octets with padding), an origin outside the allowed set with
  the correct relying party hash, cross-origin ceremonies (not allowed, under another top-level
  origin, with no topOrigin, a topOrigin without crossOrigin), a wrong relying party, the UP flag
  clear, the UV flag clear when required, another valid credential that is not a person key, and a
  record signer key enrolled as a person key, given as a key or as a raw Ed25519 identifier;
- a bad signature, an ES256 signature as raw r||s or BER, and client data re-serialized after
  signing;
- an unknown key type, an unsupported algorithm, and no person key (``NOT_CHECKED``);
- malformed objects: an extra or duplicate member, an upper-case digest, padding in a binary
  value, a key whose ``spki`` does not match its ``alg``; authenticator data that is short, has the
  AT flag, BS without BE, or extension octets that are not exactly one well-formed definite-length
  CBOR map; client data that holds NaN or a duplicate member; duplicate members inside key or
  proof;
- no person signature, and one for another record only (``NOT_PRESENT``); and several for one
  record, where any ``PASS`` decides and otherwise any ``FAIL``.

It states every expected status and reason by hand from PS §6. Nothing here imports or runs a
verifier.

Output: ``vectors/person-signature-v0/`` (or ``--out DIR``). Deterministic: no clock, no
randomness. ES256 signatures use deterministic ECDSA (RFC 6979) and Ed25519 is deterministic.
``README.md`` is never rewritten; every file in the directory is listed in ``SHA256SUMS``.
Dependencies: the standard library and ``cryptography`` (44 or later, for RFC 6979 signing).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "person-signature-v0"
SET = "aac-person-signature-v0"
SPEC = "spec/person-signature-v0.md"
STATUS = ("Conformance vectors for the informational Person Signature v0 (spec/person-signature-v0.md). "
          "Every key is a test key derived from a public seed, and the relying party and origins are "
          "example names; never use one for anything else.")
VERSION = "person-signature/0"
RP_ID = "rp.example"
ORIGIN = "https://rp.example"
OTHER_ORIGIN = "https://other.example"
TOP_ORIGIN = "https://top.example"

SEED_LABELS = {
    "person-es256": "person-signature-v0 vectors: the person's ES256 credential",
    "person-ed25519": "person-signature-v0 vectors: the person's Ed25519 credential",
    "other-es256": "person-signature-v0 vectors: another ES256 credential, not the person's",
    "record-signer": "person-signature-v0 vectors: the key that signed the record",
}
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def shx(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _seed(name: str) -> bytes:
    return sha(SEED_LABELS[name].encode())


def _ec_key(name: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(_seed(name), "big") % (_P256_N - 1) + 1, ec.SECP256R1())


PRIV: dict[str, Any] = {
    "person-es256": _ec_key("person-es256"),
    "other-es256": _ec_key("other-es256"),
    "person-ed25519": Ed25519PrivateKey.from_private_bytes(_seed("person-ed25519")),
    "record-signer": Ed25519PrivateKey.from_private_bytes(_seed("record-signer")),
}
ALG = {"person-es256": -7, "other-es256": -7, "person-ed25519": -8, "record-signer": -8}


def spki(name: str) -> bytes:
    return PRIV[name].public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def key(name: str) -> dict:
    return {"alg": ALG[name], "spki": b64u(spki(name))}


def sign(name: str, msg: bytes) -> bytes:
    if ALG[name] == -7:
        return PRIV[name].sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    return PRIV[name].sign(msg)


def record_digest(label: str) -> str:
    """A stand-in record digest. The using profile defines the real one (PS §1)."""
    return shx(json.dumps({"record": label}, separators=(",", ":"), sort_keys=True).encode())


TARGET = record_digest("an approval the person answered")
OTHER = record_digest("another record")


def signed_octets(digest: str) -> bytes:
    return f"{VERSION}:{digest}".encode()


def client_data(challenge: str, *, typ: str = "webauthn.get", origin: str = ORIGIN,
                cross_origin: bool | None = False, top_origin: str | None = None,
                extra_first: bool = False) -> bytes:
    """Client data serialized as WebAuthn's "limited verification" form does: type, challenge,
    origin, crossOrigin, then topOrigin. ``extra_first`` builds a valid variant with an extra member
    and another order, which a verifier must accept (PS §6.2 step 5)."""
    members: list[tuple[str, Any]] = [("type", typ), ("challenge", challenge), ("origin", origin)]
    if cross_origin is not None:
        members.append(("crossOrigin", cross_origin))
    if top_origin is not None:
        members.append(("topOrigin", top_origin))
    if extra_first:
        members = [("other_keys_can_be_added_here", "do not compare clientDataJSON against a template"),
                   members[2], members[0], members[1], *members[3:]]
    return json.dumps(dict(members), separators=(",", ":")).encode()


def auth_data(*, rp_id: str = RP_ID, up: bool = True, uv: bool = True, be: bool = True, bs: bool = True,
              at: bool = False, ed: bool = False, counter: int = 0, tail: bytes = b"") -> bytes:
    flags = ((0x01 if up else 0) | (0x04 if uv else 0) | (0x08 if be else 0) | (0x10 if bs else 0)
             | (0x40 if at else 0) | (0x80 if ed else 0))
    return sha(rp_id.encode()) + bytes([flags]) + counter.to_bytes(4, "big") + tail


# A one-entry CBOR map, {"credProps": {"rk": true}}, as extension output (RFC 8949).
EXTENSIONS = bytes.fromhex("a1") + bytes([0x69]) + b"credProps" + bytes.fromhex("a1") + bytes([0x62]) + b"rk" + b"\xf5"


def person_signature(signer: str, digest: str = TARGET, *, challenge: str | None = None,
                     cdata: bytes | None = None, adata: bytes | None = None, **cd: Any) -> dict:
    """A webauthn person signature, correctly signed over whatever authenticator and client data it
    holds, so that each policy negative fails only the check it is there to fail."""
    if challenge is None:
        challenge = b64u(signed_octets(digest))
    if cdata is None:
        cdata = client_data(challenge, **cd)
    if adata is None:
        adata = auth_data()
    sig = sign(signer, adata + sha(cdata))
    return {"person_signature_version": VERSION, "record_digest": digest, "key_type": "webauthn",
            "key": key(signer), "proof": {"authenticator_data": b64u(adata), "client_data_json": b64u(cdata),
                                          "signature": b64u(sig)}}


def inputs(**over: Any) -> dict:
    base = {
        "target_record_digest": TARGET,
        "person_keys": [key("person-es256"), key("person-ed25519")],
        "excluded_keys": [key("record-signer")],
        "relying_party_id": RP_ID,
        "allowed_origins": [ORIGIN],
        "allowed_top_origins": [],
        "user_verification_required": False,
    }
    base.update(over)
    return base


def checked(status: str, reason: str | None = None, *, flags: dict | None = None, counter: int | None = None,
            alg: int | None = None, index: int = 0) -> dict:
    out: dict[str, Any] = {"index": index, "status": status, "reason": reason}
    if flags is not None:
        out["flags"] = flags
        out["sign_count"] = counter
    if alg is not None:
        out["method"] = {-7: "webauthn ES256 over person-signature/0", -8: "webauthn EdDSA over person-signature/0"}[alg]
    return out


def flags(up: bool = True, uv: bool = True, be: bool = True, bs: bool = True) -> dict:
    return {"up": up, "uv": uv, "be": be, "bs": bs}


def case(cid: str, title: str, cites: list[str], sigs: list[dict] | None, expected_sigs: list[dict],
         status: str, *, fails: str | None = None, **inp: Any) -> dict:
    c: dict[str, Any] = {"id": cid, "title": title, "cites": cites, "inputs": inputs(**inp)}
    if sigs is not None:
        c["person_signatures"] = sigs
    c["expected"] = {"signatures": expected_sigs, "person_signature": status, "fails": fails}
    return c


def _raw_rs(der: bytes) -> bytes:
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def cases() -> list[dict]:
    out: list[dict] = []
    add = out.append
    ok7 = checked("PASS", flags=flags(), counter=0, alg=-7)

    # Valid.
    add(case("valid-es256", "A valid ES256 assertion under the person's key",
             ["PS §4.1", "PS §4.2", "PS §6.2", "PS §6.3"], [person_signature("person-es256")], [ok7], "PASS"))
    add(case("valid-ed25519", "A valid Ed25519 assertion under the person's key",
             ["PS §4.2", "PS §6.2"], [person_signature("person-ed25519")],
             [checked("PASS", flags=flags(), counter=0, alg=-8)], "PASS"))
    add(case("valid-uv-clear", "The UV flag is clear and the using profile does not require it: PASS, UV reported false",
             ["PS §6.1", "PS §6.2 step 6", "PS §7"], [person_signature("person-es256", adata=auth_data(uv=False))],
             [checked("PASS", flags=flags(uv=False), counter=0, alg=-7)], "PASS"))
    add(case("valid-sign-count-nonzero", "A non-zero signature counter is reported and never checked",
             ["PS §6.2 step 6", "PS §8.2"],
             [person_signature("person-es256", adata=auth_data(counter=42, be=False, bs=False))],
             [checked("PASS", flags=flags(be=False, bs=False), counter=42, alg=-7)], "PASS"))
    add(case("valid-extra-client-data-members", "Client data with an extra member, in another order, is accepted",
             ["PS §6.2 step 5"], [person_signature("person-es256", extra_first=True)], [ok7], "PASS"))
    spaced = json.dumps({"type": "webauthn.get", "challenge": b64u(signed_octets(TARGET)), "origin": ORIGIN,
                         "crossOrigin": False}, indent=1).encode()
    add(case("valid-client-data-not-compact", "Client data with whitespace: the exact octets are hashed, never re-serialized",
             ["PS §4.2", "PS §6.2 step 5", "PS §6.2 step 7"], [person_signature("person-es256", cdata=spaced)], [ok7],
             "PASS"))
    add(case("valid-uv-required-set", "The using profile requires UV and the UV flag is set",
             ["PS §6.1", "PS §6.2 step 6"], [person_signature("person-es256")], [ok7], "PASS",
             user_verification_required=True))
    add(case("valid-cross-origin-allowed", "A cross-origin ceremony the using profile allows, with an allowed top-level origin",
             ["PS §6.1", "PS §6.2 step 5"],
             [person_signature("person-es256", cross_origin=True, top_origin=TOP_ORIGIN)], [ok7], "PASS",
             allowed_top_origins=[TOP_ORIGIN]))
    add(case("valid-client-data-bom", "Client data with a leading UTF-8 byte order mark, which UTF-8 decoding removes",
             ["PS §6.2 step 5"],
             [person_signature("person-es256", cdata=b"\xef\xbb\xbf" + client_data(b64u(signed_octets(TARGET))))],
             [ok7], "PASS"))
    add(case("valid-extensions", "Authenticator data with the ED flag and one CBOR map of extension output",
             ["PS §6.2 step 6"], [person_signature("person-es256", adata=auth_data(ed=True, tail=EXTENSIONS))],
             [ok7], "PASS"))
    rsa_key = {"alg": -257, "spki": key("person-es256")["spki"]}
    add(case("valid-unsupported-key-in-inputs", "A person key and an excluded key under an undefined algorithm are the same key as no other",
             ["PS §4.2", "PS §6.2 step 3", "PS §6.2 step 4"], [person_signature("person-es256")], [ok7], "PASS",
             person_keys=[rsa_key, key("person-es256")], excluded_keys=[rsa_key, key("record-signer")]))

    # Absent.
    add(case("not-present", "No person_signatures beside the record: not signed by the person",
             ["PS §5", "PS §6.3"], None, [], "NOT_PRESENT"))
    add(case("other-record-only", "A valid person signature for another record only",
             ["PS §5", "PS §6.3"], [person_signature("person-es256", OTHER)], [], "NOT_PRESENT"))

    # Policy negatives, each correctly signed over what it holds.
    add(case("wrong-type", "Client data type webauthn.create",
             ["PS §6.2 step 5"], [person_signature("person-es256", typ="webauthn.create")],
             [checked("FAIL", "wrong type")], "FAIL", fails="type"))
    add(case("wrong-challenge-other-record", "record_digest names the target, but the challenge is another record's signed octets",
             ["PS §4.1", "PS §6.2 step 5", "PS §8.2"],
             [person_signature("person-es256", challenge=b64u(signed_octets(OTHER)))],
             [checked("FAIL", "wrong challenge")], "FAIL", fails="challenge"))
    add(case("wrong-challenge-hex-digest", "The challenge is the record digest in hexadecimal, not the signed octets",
             ["PS §4.1", "PS §6.2 step 5"], [person_signature("person-es256", challenge=TARGET)],
             [checked("FAIL", "wrong challenge")], "FAIL", fails="challenge"))
    add(case("wrong-challenge-bare-digest", "The challenge is the 32 raw digest octets, with no version prefix",
             ["PS §4.1", "PS §6.2 step 5"],
             [person_signature("person-es256", challenge=b64u(bytes.fromhex(TARGET)))],
             [checked("FAIL", "wrong challenge")], "FAIL", fails="challenge"))
    padded = base64.urlsafe_b64encode(signed_octets(TARGET)).decode()
    assert padded.endswith("="), "the signed octets must need padding for this case"
    add(case("wrong-challenge-padded", "The challenge is the signed octets in base64url with padding",
             ["PS §1", "PS §6.2 step 5"], [person_signature("person-es256", challenge=padded)],
             [checked("FAIL", "wrong challenge")], "FAIL", fails="challenge"))
    add(case("origin-not-allowed", "The ceremony ran at an origin outside the allowed set; the relying party hash is correct",
             ["PS §6.1", "PS §6.2 step 5"], [person_signature("person-es256", origin=OTHER_ORIGIN)],
             [checked("FAIL", "origin not allowed")], "FAIL", fails="origin"))
    add(case("cross-origin-not-allowed", "crossOrigin is true and the using profile does not allow it",
             ["PS §6.1", "PS §6.2 step 5"], [person_signature("person-es256", cross_origin=True, top_origin=TOP_ORIGIN)],
             [checked("FAIL", "cross-origin")], "FAIL", fails="cross_origin"))
    add(case("top-origin-not-allowed", "A cross-origin ceremony under a top-level origin the using profile does not allow",
             ["PS §6.1", "PS §6.2 step 5"],
             [person_signature("person-es256", cross_origin=True, top_origin=OTHER_ORIGIN)],
             [checked("FAIL", "cross-origin")], "FAIL", fails="cross_origin",
             allowed_top_origins=[TOP_ORIGIN]))
    add(case("cross-origin-no-top-origin", "crossOrigin is true and topOrigin is absent, under a profile that allows a top-level origin",
             ["PS §6.1", "PS §6.2 step 5"], [person_signature("person-es256", cross_origin=True)],
             [checked("FAIL", "cross-origin")], "FAIL", fails="cross_origin", allowed_top_origins=[TOP_ORIGIN]))
    add(case("top-origin-without-cross-origin", "crossOrigin is false but topOrigin is present, and no top-level origin is allowed",
             ["PS §6.1", "PS §6.2 step 5"], [person_signature("person-es256", top_origin=TOP_ORIGIN)],
             [checked("FAIL", "cross-origin")], "FAIL", fails="cross_origin"))
    add(case("wrong-relying-party", "The authenticator data names another relying party id",
             ["PS §6.2 step 6"], [person_signature("person-es256", adata=auth_data(rp_id="other.example"))],
             [checked("FAIL", "wrong relying party")], "FAIL", fails="rp_id"))
    add(case("user-not-present", "The UP flag is clear",
             ["PS §6.2 step 6"], [person_signature("person-es256", adata=auth_data(up=False))],
             [checked("FAIL", "user not present")], "FAIL", fails="up"))
    add(case("user-not-verified", "The using profile requires UV and the UV flag is clear",
             ["PS §6.1", "PS §6.2 step 6"], [person_signature("person-es256", adata=auth_data(uv=False))],
             [checked("FAIL", "user not verified")], "FAIL", fails="uv", user_verification_required=True))
    add(case("not-a-person-key", "A valid assertion under another credential, which the using profile has not enrolled",
             ["PS §6.2 step 3", "PS §8.1"], [person_signature("other-es256")],
             [checked("FAIL", "not a person key")], "FAIL", fails="person_key"))
    add(case("record-signer-key", "The record signer's key, enrolled as a person key by mistake",
             ["PS §6.2 step 4", "PS §8.1"], [person_signature("record-signer")],
             [checked("FAIL", "record signer key")], "FAIL", fails="excluded_key",
             person_keys=[key("person-es256"), key("record-signer")]))

    # Signature defects.
    bad = person_signature("person-es256")
    raw = base64.urlsafe_b64decode(bad["proof"]["signature"] + "==")
    bad["proof"]["signature"] = b64u(raw[:-1] + bytes([raw[-1] ^ 0x01]))
    add(case("bad-signature", "The assertion signature does not verify",
             ["PS §6.2 step 7"], [bad], [checked("FAIL", "bad signature", flags=flags(), counter=0)], "FAIL",
             fails="signature"))
    rs = person_signature("person-es256")
    rs["proof"]["signature"] = b64u(_raw_rs(base64.urlsafe_b64decode(rs["proof"]["signature"] + "==")))
    add(case("es256-raw-rs-signature", "An ES256 signature as raw r||s rather than DER",
             ["PS §4.2", "PS §6.2 step 7"], [rs], [checked("FAIL", "bad signature", flags=flags(), counter=0)], "FAIL",
             fails="signature"))
    replay = person_signature("person-es256")
    reordered = {"challenge": b64u(signed_octets(TARGET)), "type": "webauthn.get", "origin": ORIGIN, "crossOrigin": False}
    replay["proof"]["client_data_json"] = b64u(json.dumps(reordered, separators=(",", ":")).encode())
    add(case("client-data-reserialized", "Client data re-serialized after signing: same members, other octets",
             ["PS §4.2", "PS §6.2 step 5", "PS §6.2 step 7"], [replay],
             [checked("FAIL", "bad signature", flags=flags(), counter=0)], "FAIL", fails="signature"))

    der = base64.urlsafe_b64decode(person_signature("person-es256")["proof"]["signature"] + "==")
    assert der[1] < 0x80, "short-form length expected"
    ber = person_signature("person-es256")
    ber["proof"]["signature"] = b64u(der[:1] + b"\x81" + der[1:])
    add(case("es256-ber-signature", "An ES256 signature with a long-form length: BER, not DER",
             ["PS §6.2 step 7"], [ber], [checked("FAIL", "bad signature", flags=flags(), counter=0)], "FAIL",
             fails="signature"))
    add(case("excluded-key-raw-identifier", "The record signer's key, given as a raw Ed25519 key identifier, enrolled by mistake",
             ["PS §4.2", "PS §6.1", "PS §6.2 step 4"], [person_signature("record-signer")],
             [checked("FAIL", "record signer key")], "FAIL", fails="excluded_key",
             person_keys=[key("person-es256"), key("record-signer")],
             excluded_keys=[PRIV["record-signer"].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()]))

    # Not checked.
    unknown = person_signature("person-es256")
    unknown["key_type"] = "example-wallet"
    add(case("unknown-key-type", "A key type this revision does not define never reads as signed",
             ["PS §3.2", "PS §6.2 step 2", "PS §6.3"], [unknown],
             [checked("NOT_CHECKED", "unsupported key type")], "NOT_CHECKED"))
    rsa = person_signature("person-es256")
    rsa["key"] = {"alg": -257, "spki": rsa["key"]["spki"]}
    add(case("unsupported-algorithm", "A webauthn key under an algorithm this revision does not define (-257)",
             ["PS §4.2", "PS §6.2 step 2"], [rsa], [checked("NOT_CHECKED", "unsupported algorithm")], "NOT_CHECKED"))
    add(case("no-person-key", "The using profile has no person key for the person",
             ["PS §6.1"], [person_signature("person-es256")], [checked("NOT_CHECKED", "no person key")], "NOT_CHECKED",
             person_keys=[]))

    # Malformed.
    extra = person_signature("person-es256")
    extra["note"] = "an extra member"
    add(case("malformed-extra-member", "A member PS §3.1 does not list",
             ["PS §3.1", "PS §6.2 step 1"], [extra], [checked("FAIL", "malformed")], "FAIL", fails="form"))
    upper = person_signature("person-es256")
    upper["record_digest"] = TARGET.upper()
    add(case("upper-case-digest-names-no-record", "record_digest in upper-case hexadecimal names no record",
             ["PS §1", "PS §3.1", "PS §6.2"], [upper], [], "NOT_PRESENT"))
    pad = person_signature("person-es256")
    pad["proof"]["signature"] = base64.urlsafe_b64encode(
        base64.urlsafe_b64decode(pad["proof"]["signature"] + "==")).decode()
    if not pad["proof"]["signature"].endswith("="):
        pad["proof"]["signature"] += "=="
    add(case("malformed-padded-binary", "A binary value with base64 padding",
             ["PS §1", "PS §6.2 step 1"], [pad], [checked("FAIL", "malformed")], "FAIL", fails="form"))
    mismatch = person_signature("person-es256")
    mismatch["key"]["alg"] = -8
    add(case("malformed-alg-spki-mismatch", "A P-256 spki under alg -8",
             ["PS §4.2", "PS §6.2 step 1"], [mismatch], [checked("FAIL", "malformed")], "FAIL", fails="form"))
    short = person_signature("person-es256", adata=auth_data()[:36])
    add(case("malformed-short-authenticator-data", "Authenticator data of 36 octets",
             ["PS §6.2 step 6"], [short], [checked("FAIL", "malformed")], "FAIL", fails="authenticator_data"))
    for cid, title, adata in (
        ("malformed-backup-flags", "The BS flag set while the BE flag is clear", auth_data(be=False, bs=True)),
        ("malformed-at-flag", "The AT flag set: an assertion carries no attested credential data", auth_data(at=True)),
        ("malformed-ed-flag-no-extensions", "The ED flag set with no extension octets", auth_data(ed=True)),
        ("malformed-trailing-octets", "The ED flag clear and one octet after the first 37", auth_data(tail=b"\x00")),
        ("malformed-octets-after-extensions", "The ED flag set and an octet after the extension map",
         auth_data(ed=True, tail=EXTENSIONS + b"\x00")),
        ("malformed-indefinite-length-extensions", "Extension output as an indefinite-length map",
         auth_data(ed=True, tail=bytes.fromhex("bf6272") + b"k" + bytes.fromhex("f5ff"))),
        ("malformed-cbor-simple-value", "Extension output holding a two-octet simple value below 32, which CBOR forbids",
         auth_data(ed=True, tail=bytes.fromhex("a16178f818"))),
    ):
        add(case(cid, title + "; correctly signed", ["PS §6.2 step 6"], [person_signature("person-es256", adata=adata)],
                 [checked("FAIL", "malformed")], "FAIL", fails="authenticator_data"))
    nan = client_data(b64u(signed_octets(TARGET)))[:-1] + b',"extra":NaN}'
    dup = (b'{"type":"webauthn.get","challenge":"' + b64u(signed_octets(TARGET)).encode()
           + b'","origin":"' + OTHER_ORIGIN.encode() + b'","origin":"' + ORIGIN.encode() + b'","crossOrigin":false}')
    for cid, title, cdata in (
        ("malformed-client-data-nan", "Client data holding NaN, which is not JSON", nan),
        ("malformed-client-data-duplicate-member", "Client data naming origin twice, the second time an allowed origin", dup),
    ):
        add(case(cid, title + "; correctly signed", ["PS §6.2 step 5"], [person_signature("person-es256", cdata=cdata)],
                 [checked("FAIL", "malformed")], "FAIL", fails="client_data"))
    dup_ps = person_signature("person-es256")
    text = json.dumps([dup_ps], separators=(",", ":"))
    text = text.replace('"key_type":"webauthn"', '"key_type":"example-wallet","key_type":"webauthn"', 1)
    dup_case = case("malformed-duplicate-member", "A person signature naming key_type twice, given as JSON text",
                    ["PS §3.1", "PS §6.2 step 1"], None, [checked("FAIL", "malformed")], "FAIL", fails="form")
    dup_case["person_signatures_json"] = text
    dup_case["expected"] = dup_case.pop("expected")
    add(dup_case)
    for cid, title, old, new in (
        ("malformed-duplicate-key-member", "A person signature whose key names alg twice, given as JSON text",
         '"key":{"alg":-7', '"key":{"alg":-8,"alg":-7'),
        ("malformed-duplicate-proof-member", "A person signature whose proof names signature twice, given as JSON text",
         '"proof":{', '"proof":{"signature":"AA",'),
    ):
        nested = case(cid, title, ["PS §3.1", "PS §4.2", "PS §6.2 step 1"], None, [checked("FAIL", "malformed")],
                      "FAIL", fails="form")
        nested["person_signatures_json"] = json.dumps([person_signature("person-es256")],
                                                       separators=(",", ":")).replace(old, new, 1)
        assert new in nested["person_signatures_json"]
        nested["expected"] = nested.pop("expected")
        add(nested)

    # Several for one record.
    add(case("several-one-passes", "One person signature fails and one passes: the record is PASS",
             ["PS §5", "PS §6.3"], [person_signature("other-es256"), person_signature("person-ed25519")],
             [checked("FAIL", "not a person key", index=0),
              checked("PASS", flags=flags(), counter=0, alg=-8, index=1)], "PASS"))
    add(case("several-fail-and-unchecked", "One fails, one is not checked, one names another record: the record is FAIL",
             ["PS §5", "PS §6.3"], [person_signature("person-es256", OTHER), unknown, bad],
             [checked("NOT_CHECKED", "unsupported key type", index=1),
              checked("FAIL", "bad signature", flags=flags(), counter=0, index=2)], "FAIL", fails="signature"))
    return out


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    all_cases = cases()
    ids = [c["id"] for c in all_cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    corpus = {
        "set": SET,
        "status": STATUS,
        "spec": SPEC,
        "test_keys": {
            "note": ("TEST-ONLY. Each Ed25519 private key is the 32-byte seed SHA-256(seed_label). Each P-256 "
                     "private scalar is int(SHA-256(seed_label)) mod (n - 1) + 1."),
            "keys": {name: {"seed_label": SEED_LABELS[name], "key": key(name)} for name in SEED_LABELS},
        },
        "count": len(all_cases),
        "cases": all_cases,
    }
    files = {"vectors.json": _dump(corpus)}
    files["manifest.json"] = _dump({
        "set": SET,
        "status": STATUS,
        "spec": SPEC,
        "generator": "python/scripts/generate_person_signature_v0_vectors.py",
        "files": [{"path": name, "sha256": shx(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    files = sorted((p.relative_to(out).as_posix(), p) for p in out.rglob("*") if p.is_file())
    lines = [f"{shx(p.read_bytes())}  {rel}" for rel, p in files if rel != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    write(args.out)


if __name__ == "__main__":
    main()
