# SPDX-License-Identifier: BSD-3-Clause
"""Generate deterministic cross-runtime AAC producer-envelope vectors."""
from __future__ import annotations

import json
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scitt_cose.cose_sign1 import sign_sign1

CONTENT_TYPE = "application/agent-action-capsule-id"
OUT = Path(__file__).resolve().parents[2] / "producer-envelope-vectors"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
PRIVATE_PEM = PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
PAYLOAD = bytes(range(32, 64))


def sign(*, protected: dict | None = None, unprotected: dict | None = None) -> bytes:
    headers = {3: CONTENT_TYPE, 4: PUBLIC_KEY}
    headers.update(protected or {})
    return sign_sign1(
        PAYLOAD,
        alg="EdDSA",
        private_key_pem=PRIVATE_PEM,
        protected=headers,
        unprotected=unprotected or {},
    )


def bad_signature(encoded: bytes) -> bytes:
    tagged = cbor2.loads(encoded)
    values = list(tagged.value)
    signature = bytearray(values[3])
    signature[-1] ^= 1
    values[3] = bytes(signature)
    return cbor2.dumps(cbor2.CBORTag(18, values), canonical=True)


def wrong_algorithm(encoded: bytes) -> bytes:
    """Return an otherwise valid Ed25519 envelope declaring ES256."""
    tagged = cbor2.loads(encoded)
    values = list(tagged.value)
    protected = cbor2.loads(values[0])
    protected[1] = -7
    protected_bytes = cbor2.dumps(protected, canonical=True)
    sig_structure = cbor2.dumps(
        ["Signature1", protected_bytes, b"", values[2]],
        canonical=True,
    )
    values[0] = protected_bytes
    values[3] = PRIVATE_KEY.sign(sig_structure)
    return cbor2.dumps(cbor2.CBORTag(18, values), canonical=True)


def write_case(name: str, description: str, capsule_id: str, encoded: bytes, *, code: str | None = None) -> dict:
    directory = OUT / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "capsule_id.txt").write_text(capsule_id + "\n", encoding="ascii")
    (directory / "envelope.cose").write_bytes(encoded)
    expected = {
        "ok": code is None,
        "finding_codes": [] if code is None else [code],
        "public_key_hex": PUBLIC_KEY.hex() if code is None else None,
    }
    (directory / "expected.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
    return {"name": name, "description": description}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    valid = sign()
    cases = [
        write_case("valid", "valid self-contained Ed25519 producer envelope", PAYLOAD.hex(), valid),
        write_case(
            "bad-signature",
            "signature byte changed after signing",
            PAYLOAD.hex(),
            bad_signature(valid),
            code="envelope_signature_invalid",
        ),
        write_case(
            "payload-mismatch",
            "valid envelope presented for a different Capsule ID",
            bytes(range(64, 96)).hex(),
            valid,
            code="envelope_payload_mismatch",
        ),
        write_case(
            "wrong-algorithm",
            "otherwise valid Ed25519 envelope declares ES256",
            PAYLOAD.hex(),
            wrong_algorithm(valid),
            code="envelope_algorithm_mismatch",
        ),
        write_case(
            "wrong-content-type",
            "signed envelope declares the wrong payload media type",
            PAYLOAD.hex(),
            sign(protected={3: "application/octet-stream"}),
            code="envelope_content_type_mismatch",
        ),
        write_case(
            "nonempty-unprotected",
            "unprotected header carries a profile-forbidden member",
            PAYLOAD.hex(),
            sign(unprotected={9: True}),
            code="envelope_malformed",
        ),
        write_case(
            "extra-protected-header",
            "protected header carries a profile-forbidden extra member",
            PAYLOAD.hex(),
            sign(protected={99: "extra"}),
            code="envelope_protected_headers_invalid",
        ),
        write_case(
            "invalid-kid",
            "protected kid is not a raw 32-byte Ed25519 public key",
            PAYLOAD.hex(),
            sign(protected={4: PUBLIC_KEY[:-1]}),
            code="envelope_kid_invalid",
        ),
    ]
    manifest = {
        "format_version": "1",
        "profile": "draft-mih-scitt-agent-action-capsule-04#producer-envelope",
        "count": len(cases),
        "cases": cases,
    }
    (OUT / "vectors.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
