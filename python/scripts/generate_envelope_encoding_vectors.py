#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Add the Producer Envelope CBOR-encoding cases to vectors/producer-envelope.

The draft's Producer Envelope wire profile requires definite lengths, the
preferred (shortest) serialization of every argument and float, unique map
keys, no tag but the outermost tag 18, a map as the unprotected header, and
byte strings as payload and signature. These cases pin that paragraph, on
which the Go, Python, Rust and TypeScript verifiers once disagreed. Each
envelope is written byte by byte and, where the protected bytes change,
signed honestly with the public test seed, so only the encoding under test
can fail. Map-key order is not constrained, so one positive case reorders the
protected labels.

Only these cases are written; existing, released cases are left untouched.
The manifest gains the new entries and SHA256SUMS is refreshed. Every
expected verdict is checked against the Python reference before it is
written. The run is deterministic.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_action_capsule.producer_envelope import verify_producer_envelope

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_parity_hardening_vectors import VECTORS, _append, _dump, update_checksums  # noqa: E402

CONTENT_TYPE = "application/agent-action-capsule-id"
# Public test seed, never a production key.
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes_raw()
PAYLOAD = bytes(range(32, 64))

ALG = bytes([0x01, 0x27])
CT = bytes([0x03]) + cbor2.dumps(CONTENT_TYPE)
KID = bytes([0x04]) + cbor2.dumps(PUBLIC_KEY)
LABELS = ALG + CT + KID
PROTECTED = bytes([0xA3]) + LABELS


def _bstr(value: bytes, width: int = 0) -> bytes:
    """A byte string whose length argument has ``width`` bytes (0: shortest)."""
    if not width:
        return cbor2.dumps(value)
    return bytes([0x40 | {1: 24, 2: 25, 4: 26, 8: 27}[width]]) + len(value).to_bytes(width, "big") + value


def _signature(protected: bytes) -> bytes:
    return PRIVATE_KEY.sign(cbor2.dumps(["Signature1", protected, b"", PAYLOAD]))


def _envelope(
    protected: bytes = PROTECTED,
    *,
    head: bytes = b"\xd2\x84",
    protected_item: bytes | None = None,
    unprotected: bytes = b"\xa0",
    payload: bytes | None = None,
    signature: bytes | None = None,
) -> bytes:
    """A COSE_Sign1 over PAYLOAD, signed for ``protected``, with each outer item overridable."""
    return (
        head
        + (_bstr(protected) if protected_item is None else protected_item)
        + unprotected
        + (_bstr(PAYLOAD) if payload is None else payload)
        + (_bstr(_signature(protected)) if signature is None else signature)
    )


def _protected_map(head: bytes, *entries: bytes) -> bytes:
    return head + b"".join(entries)


def _float_alg(fmt: str, value: float) -> bytes:
    """A signed envelope whose protected alg is ``value`` packed with ``fmt``."""
    head = b"\xfa" if fmt == ">f" else b"\xfb"
    return _envelope(_protected_map(b"\xa3", b"\x01" + head + struct.pack(fmt, value), CT, KID))


def producer_envelope_cases() -> list[dict]:
    out = VECTORS / "producer-envelope"
    malformed = "envelope_malformed"
    cases = [
        (
            "protected-label-order",
            "protected labels in the order kid, content type, alg: map-key order is not constrained",
            _envelope(_protected_map(b"\xa3", KID, CT, ALG)),
            None,
        ),
        (
            "unprotected-null",
            "unprotected header is CBOR null, not a map",
            _envelope(unprotected=b"\xf6"),
            malformed,
        ),
        (
            "unprotected-undefined",
            "unprotected header is CBOR undefined, not a map",
            _envelope(unprotected=b"\xf7"),
            malformed,
        ),
        (
            "unprotected-tagged",
            "unprotected header is an empty map under tag 6",
            _envelope(unprotected=b"\xc6\xa0"),
            malformed,
        ),
        (
            "unprotected-length-nonshortest",
            "unprotected empty map with its length in a one-byte argument",
            _envelope(unprotected=b"\xb8\x00"),
            malformed,
        ),
        (
            "payload-tagged",
            "attached payload is the right byte string under tag 6",
            _envelope(payload=b"\xc6" + _bstr(PAYLOAD)),
            malformed,
        ),
        (
            "payload-bignum",
            "attached payload is the right byte string under bignum tag 2",
            _envelope(payload=b"\xc2" + _bstr(PAYLOAD)),
            malformed,
        ),
        (
            "payload-null",
            "attached payload is CBOR null",
            _envelope(payload=b"\xf6"),
            malformed,
        ),
        (
            "signature-null",
            "signature is CBOR null",
            _envelope(signature=b"\xf6"),
            malformed,
        ),
        (
            "doubly-tagged",
            "COSE_Sign1 tag 18 applied twice",
            _envelope(head=b"\xd2\xd2\x84"),
            malformed,
        ),
        (
            "self-described",
            "COSE_Sign1 under the self-described CBOR tag 55799",
            _envelope(head=b"\xd9\xd9\xf7\xd2\x84"),
            malformed,
        ),
        (
            "outer-tag-nonshortest",
            "tag 18 with its number in a one-byte argument",
            _envelope(head=b"\xd8\x12\x84"),
            malformed,
        ),
        (
            "outer-array-length-nonshortest",
            "COSE_Sign1 array with its length in a one-byte argument",
            _envelope(head=b"\xd2\x98\x04"),
            malformed,
        ),
        (
            "outer-payload-length-nonshortest",
            "attached payload with its length in a two-byte argument",
            _envelope(payload=_bstr(PAYLOAD, 2)),
            malformed,
        ),
        (
            "outer-protected-length-nonshortest",
            "protected-header byte string with its length in a two-byte argument",
            _envelope(protected_item=_bstr(PROTECTED, 2)),
            malformed,
        ),
        (
            "protected-map-length-u8",
            "signed protected map with its length in a one-byte argument",
            _envelope(_protected_map(b"\xb8\x03", LABELS)),
            malformed,
        ),
        (
            "protected-map-length-u16",
            "signed protected map with its length in a two-byte argument",
            _envelope(_protected_map(b"\xb9\x00\x03", LABELS)),
            malformed,
        ),
        (
            "protected-map-length-u32",
            "signed protected map with its length in a four-byte argument",
            _envelope(_protected_map(b"\xba\x00\x00\x00\x03", LABELS)),
            malformed,
        ),
        (
            "protected-map-length-u64",
            "signed protected map with its length in an eight-byte argument",
            _envelope(_protected_map(b"\xbb" + (3).to_bytes(8, "big"), LABELS)),
            malformed,
        ),
        (
            "protected-label-nonshortest",
            "protected alg label 1 in a one-byte argument",
            _envelope(_protected_map(b"\xa3", b"\x18\x01\x27", CT, KID)),
            malformed,
        ),
        (
            "protected-alg-nonshortest",
            "protected alg -8 in a one-byte argument",
            _envelope(_protected_map(b"\xa3", b"\x01\x38\x07", CT, KID)),
            malformed,
        ),
        (
            "protected-kid-length-nonshortest",
            "protected kid with its length in a two-byte argument",
            _envelope(_protected_map(b"\xa3", ALG, CT, b"\x04" + _bstr(PUBLIC_KEY, 2))),
            malformed,
        ),
        (
            "protected-alg-float32",
            "protected alg is -8.0 in single precision, which half precision represents exactly",
            _float_alg(">f", -8.0),
            malformed,
        ),
        (
            "protected-alg-float64-nan",
            "protected alg is a double-precision NaN, which belongs in half precision",
            _envelope(_protected_map(b"\xa3", b"\x01\xfb\x7f\xf8" + bytes(6), CT, KID)),
            malformed,
        ),
        (
            "protected-alg-float64",
            "protected alg is -8.0 in double precision, which half precision represents exactly",
            _float_alg(">d", -8.0),
            malformed,
        ),
        (
            "protected-alg-float64-infinity",
            "protected alg is infinity in double precision, which belongs in half precision",
            _float_alg(">d", float("inf")),
            malformed,
        ),
        (
            "protected-alg-float32-half-subnormal",
            "protected alg is 2^-24 in single precision, the smallest half-precision subnormal",
            _float_alg(">f", 2.0**-24),
            malformed,
        ),
        (
            "protected-alg-float32-below-half",
            "protected alg is 2^-25 in single precision, its shortest form, so only the alg check fails",
            _float_alg(">f", 2.0**-25),
            "envelope_algorithm_mismatch",
        ),
        (
            "protected-alg-float64-needed",
            "protected alg is 1.1 in double precision, its shortest form, so only the alg check fails",
            _float_alg(">d", 1.1),
            "envelope_algorithm_mismatch",
        ),
        (
            "protected-alg-map-duplicate-keys",
            "protected alg is a map whose two keys are one map with its entries in two orders",
            _envelope(_protected_map(b"\xa3", b"\x01\xa2\xa2\x01\x02\x03\x04\x00\xa2\x03\x04\x01\x02\x01", CT, KID)),
            malformed,
        ),
        (
            "protected-label-tagged",
            "protected alg label 1 under tag 6",
            _envelope(_protected_map(b"\xa3", b"\xc6\x01\x27", CT, KID)),
            malformed,
        ),
        (
            "protected-kid-tagged",
            "protected kid is the right public key under tag 6",
            _envelope(_protected_map(b"\xa3", ALG, CT, b"\x04\xc6" + cbor2.dumps(PUBLIC_KEY))),
            malformed,
        ),
        (
            "protected-label-beyond-int64",
            "an extra protected label -2^64, a CBOR integer outside int64",
            _envelope(_protected_map(b"\xa4", LABELS, b"\x3b" + b"\xff" * 8 + b"\x00")),
            "envelope_protected_headers_invalid",
        ),
    ]
    entries = []
    for name, description, encoded, code in cases:
        result = verify_producer_envelope(PAYLOAD.hex(), encoded)
        codes = [finding.code for finding in result.findings]
        if result.ok != (code is None) or codes != ([] if code is None else [code]):
            raise SystemExit(f"{name}: the Python reference returned {codes or 'ok'}, not {code or 'ok'}")
        directory = out / name
        directory.mkdir(exist_ok=True)
        (directory / "capsule_id.txt").write_text(PAYLOAD.hex() + "\n", encoding="ascii")
        (directory / "envelope.cose").write_bytes(encoded)
        _dump(
            directory / "expected.json",
            {
                "ok": code is None,
                "finding_codes": [] if code is None else [code],
                "public_key_hex": PUBLIC_KEY.hex() if code is None else None,
            },
        )
        entries.append({"name": name, "description": description})
    _append(out / "vectors.json", entries)
    return entries


def main() -> None:
    directory = VECTORS / "producer-envelope"
    names = [entry["name"] for entry in producer_envelope_cases()]
    files = [directory / "vectors.json"] + [
        path for name in names for path in sorted((directory / name).iterdir()) if path.is_file()
    ]
    update_checksums(directory, files)
    update_checksums(VECTORS, files)


if __name__ == "__main__":
    main()
