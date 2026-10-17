#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the UCP adapter vectors of spec/adapters/ucp-v0.md, section 3.

The object is a UCP checkout carrying ``ap2.merchant_authorization``: a JWS
with detached content (RFC 7515 Appendix F) over the RFC 8785 form of the
checkout without ``ap2`` (UCP v2026-08-25, AP2 Mandates Extension,
Business Authorization). Two cases: ``positive``, where every check of section
3(e) passes, and ``native-check-fails``, the same checkout with the ``total``
amount changed after signing, where the signature check fails.

The signing key is the ES256 example key of RFC 7515, Appendix A.3, a
published example key; UCP publishes no test key. ES256 signatures are
randomized, and these vectors must be reproducible, so the nonce is derived as
RFC 6979 specifies (Section 3.2, HMAC-SHA-256). The script signs with its own
P-256 arithmetic and checks every signature with ``cryptography``.

Expected results are written by hand from the declaration. Nothing here runs
an adapter. Schema validity against UCP's published JSON Schema is checked
outside this script, with UCP's ``ucp-schema`` validator; the vectors' README
records the command.

Output: ``vectors/adapters/ucp/`` (or ``--out DIR``). The run is a pure function
of this file. ``README.md`` is hand-written; when present in the output
directory it is included in ``SHA256SUMS`` but never rewritten.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from agent_action_capsule.canonical import jcs

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "adapters" / "ucp"
DECLARATION = "spec/adapters/ucp-v0.md"
UCP_VERSION = "2026-08-25"
UCP_COMMIT = "cd78fb38e819de77d9b527d110476eccb876f1bd"
KID = "rfc7515-appendix-a3"
UCP_BASE = f"https://ucp.dev/{UCP_VERSION}"

# RFC 7515, Appendix A.3.1: the ECDSA P-256 example key, as published.
RFC7515_A3_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
}

# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dumps(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------
# P-256 and deterministic ECDSA (RFC 6979)
# ---------------------------------------------------------------------------

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def _point_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0:
        return None
    if p1 == p2:
        slope = (3 * p1[0] * p1[0] + A) * pow(2 * p1[1], -1, P) % P
    else:
        slope = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, P) % P
    x = (slope * slope - p1[0] - p2[0]) % P
    return x, (slope * (p1[0] - x) - p1[1]) % P


def scalar_mult(k: int, point: tuple[int, int] = G) -> tuple[int, int]:
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    assert result is not None
    return result


def _int2octets(value: int) -> bytes:
    return value.to_bytes(32, "big")


def rfc6979_nonce(private: int, digest: bytes) -> int:
    """RFC 6979, Section 3.2, for P-256 with HMAC-SHA-256 (qlen = hlen = 256)."""
    h1 = _int2octets(int.from_bytes(digest, "big") % N)
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + _int2octets(private) + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + _int2octets(private) + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_es256(private: int, message: bytes) -> tuple[int, int]:
    """ECDSA P-256 SHA-256 with the RFC 6979 nonce; returns (r, s)."""
    digest = hashlib.sha256(message).digest()
    e = int.from_bytes(digest, "big")
    k = rfc6979_nonce(private, digest)
    r = scalar_mult(k)[0] % N
    s = pow(k, -1, N) * (e + r * private) % N
    if r == 0 or s == 0:
        raise ValueError("degenerate signature")
    return r, s


def public_key(jwk: dict) -> ec.EllipticCurvePublicKey:
    x = int.from_bytes(b64u_decode(jwk["x"]), "big")
    y = int.from_bytes(b64u_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def verify_es256(jwk: dict, message: bytes, signature: bytes) -> bool:
    """Check a JWS ES256 signature (RFC 7518 Section 3.4: 64-octet r || s)."""
    if len(signature) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    try:
        public_key(jwk).verify(der, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def _private_scalar() -> int:
    private = int.from_bytes(b64u_decode(RFC7515_A3_JWK["d"]), "big")
    x, y = scalar_mult(private)
    expected = (
        int.from_bytes(b64u_decode(RFC7515_A3_JWK["x"]), "big"),
        int.from_bytes(b64u_decode(RFC7515_A3_JWK["y"]), "big"),
    )
    if (x, y) != expected:
        raise ValueError("RFC 7515 A.3 private key does not match its public key")
    return private


# ---------------------------------------------------------------------------
# UCP objects
# ---------------------------------------------------------------------------


def business_keys() -> dict:
    """The business profile's ``keys[]``, as a retained JWK Set."""
    public = {key: RFC7515_A3_JWK[key] for key in ("kty", "crv", "x", "y")}
    return {"keys": [{"kid": KID, **public, "use": "sig", "alg": "ES256"}]}


def checkout() -> dict:
    """A ``complete_checkout`` response, before signing (no ``ap2``)."""
    return {
        "ucp": {
            "version": UCP_VERSION,
            "status": "success",
            "capabilities": {
                "dev.ucp.shopping.checkout": [
                    {
                        "version": UCP_VERSION,
                        "spec": f"{UCP_BASE}/specification/shopping/checkout",
                        "schema": f"{UCP_BASE}/schemas/shopping/checkout.json",
                    }
                ],
                "dev.ucp.common.payment.ap2_mandate": [
                    {
                        "version": UCP_VERSION,
                        "spec": f"{UCP_BASE}/specification/payment/extensions/ap2-mandates",
                        "schema": f"{UCP_BASE}/schemas/common/payment_ap2_mandate.json",
                        "extends": "dev.ucp.shopping.checkout",
                    }
                ],
            },
            "payment_handlers": {},
        },
        "id": "chk_abc123",
        "status": "completed",
        "currency": "USD",
        "line_items": [
            {
                "id": "li_1",
                "item": {"id": "item_123", "title": "Widget", "price": 2500},
                "quantity": 2,
                "totals": [
                    {"type": "subtotal", "amount": 5000},
                    {"type": "total", "amount": 5000},
                ],
            }
        ],
        "totals": [
            {"type": "subtotal", "amount": 5000},
            {"type": "tax", "amount": 400},
            {"type": "total", "amount": 5400},
        ],
        "links": [{"type": "terms_of_service", "url": "https://merchant.example/terms"}],
        "order": {"id": "ord_456", "permalink_url": "https://merchant.example/orders/ord_456"},
    }


def signing_input(encoded_header: str, checkout_object: dict) -> bytes:
    """AP2 Mandates Extension: header || "." || base64url(JCS(checkout without ap2))."""
    payload = {key: value for key, value in checkout_object.items() if key != "ap2"}
    return f"{encoded_header}.{b64u(jcs(payload))}".encode("ascii")


def sign_checkout(checkout_object: dict, private: int) -> dict:
    encoded_header = b64u(json.dumps({"alg": "ES256", "kid": KID}, separators=(",", ":")).encode("ascii"))
    r, s = sign_es256(private, signing_input(encoded_header, checkout_object))
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    signed = copy.deepcopy(checkout_object)
    signed["ap2"] = {"merchant_authorization": f"{encoded_header}..{b64u(signature)}"}
    return signed


def merchant_authorization_valid(signed: dict, key_set: dict) -> bool:
    encoded_header, empty, encoded_signature = signed["ap2"]["merchant_authorization"].split(".")
    if empty:
        return False
    header = json.loads(b64u_decode(encoded_header))
    key = next(k for k in key_set["keys"] if k["kid"] == header["kid"])
    return verify_es256(key, signing_input(encoded_header, signed), b64u_decode(encoded_signature))


# ---------------------------------------------------------------------------
# Expected reports (spec/adapters/ucp-v0.md, section 3(e))
# ---------------------------------------------------------------------------

SCHEMA_METHOD = f"ucp-schema validate --response --op complete, UCP v{UCP_VERSION}"
CHECKS = (
    ("ucp.checkout.schema", SCHEMA_METHOD),
    ("ucp.merchant_authorization.present", "UCP AP2 Mandates §Business Authorization"),
    ("ucp.merchant_authorization.form", "RFC 7515 Appendix F detached JWS"),
    ("ucp.merchant_authorization.alg", "AP2 v0.2 algorithm rule"),
    ("ucp.merchant_authorization.key", "retained keys[] (key-set.json)"),
    ("ucp.merchant_authorization.signature", "ES256 over JWS signing input of JCS(checkout − ap2)"),
)


def reports(failing: str | None = None) -> list[dict]:
    return [
        {
            "property": "native_check",
            "status": "FAIL" if name == failing else "PASS",
            "method": method,
            "detail": name,
        }
        for name, method in CHECKS
    ]


def wrapped(signed: dict) -> dict:
    """The proposed ``ucp.checkout`` wrapped entry: RFC 8785 form, ``ap2`` included."""
    octets = jcs(signed)
    return {"type": "ucp.checkout", "digest_alg": "SHA-256", "digest": sha256_hex(octets), "content": b64u(octets)}


def build(out: Path) -> None:
    private = _private_scalar()
    keys = business_keys()
    positive = sign_checkout(checkout(), private)
    tampered = copy.deepcopy(positive)
    tampered["totals"][2]["amount"] = 540

    if not merchant_authorization_valid(positive, keys):
        raise AssertionError("positive: the signature must verify")
    if merchant_authorization_valid(tampered, keys):
        raise AssertionError("native-check-fails: the signature must not verify")

    cases = [
        {
            "name": "positive",
            "description": "complete_checkout response with ap2.merchant_authorization; every check passes.",
            "checkout": "positive.checkout.json",
            "key_set": "key-set.json",
            "wrapped": wrapped(positive),
            "expected": {"reports": reports(), "business_trust": "NOT_CHECKED"},
        },
        {
            "name": "native-check-fails",
            "description": (
                "The positive checkout with totals[2].amount (type total) changed from 5400 to 540 "
                "after signing; ap2.merchant_authorization unchanged."
            ),
            "checkout": "native-check-fails.checkout.json",
            "key_set": "key-set.json",
            "mutation": {"pointer": "/totals/2/amount", "from": 5400, "to": 540},
            "wrapped": wrapped(tampered),
            "expected": {
                "reports": reports(failing="ucp.merchant_authorization.signature"),
                "business_trust": "NOT_CHECKED",
                "mapping": {
                    "requirement_is_the_check": {"row": 5, "status": "SATISFIED", "sufficiency": "SATISFIED", "verdict": "not_met"},
                    "requirement_rests_on_the_check": {
                        "row": 6, "status": "INSUFFICIENT", "sufficiency": "INSUFFICIENT", "verdict": "not_evaluable",
                    },
                },
            },
        },
    ]

    out.mkdir(parents=True, exist_ok=True)
    files = {
        "key-set.json": dumps(keys),
        "positive.checkout.json": dumps(positive),
        "native-check-fails.checkout.json": dumps(tampered),
        "cases.json": dumps({"declaration": DECLARATION, "ucp_version": UCP_VERSION, "ucp_commit": UCP_COMMIT, "cases": cases}),
    }
    for name, text in files.items():
        (out / name).write_text(text, encoding="utf-8")
    manifest = {
        "declaration": DECLARATION,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_ucp_adapter_vectors.py",
        "files": [
            {"path": name, "sha256": sha256_hex(text.encode("utf-8"))} for name, text in sorted(files.items())
        ],
        "count": len(cases),
    }
    (out / "manifest.json").write_text(dumps(manifest), encoding="utf-8")
    lines = [f"{sha256_hex(p.read_bytes())}  {p.name}"
             for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    build(parser.parse_args().out)


if __name__ == "__main__":
    main()
