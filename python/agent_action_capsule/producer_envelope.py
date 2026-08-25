# SPDX-License-Identifier: BSD-3-Clause
"""Verify AAC producer envelopes over signer-independent Capsule IDs.

This optional module requires ``agent-action-capsule[envelope]``. It reuses the
public ``scitt-cose`` COSE_Sign1 verifier and adds the exact AAC profile checks:
raw 32-byte Capsule-ID payload, EdDSA, the AAC Capsule-ID media type, raw
Ed25519-public-key ``kid``, and an empty unprotected map. Signer authorization
is deliberately outside this cryptographic self-attestation verdict.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from scitt_cose.cose_sign1 import CoseError, strict_decode, verify_sign1

from .media_types import CAPSULE_ID_MEDIA_TYPE

CONTENT_TYPE = CAPSULE_ID_MEDIA_TYPE
COSE_ALGORITHM_EDDSA = -8
MAX_ENVELOPE_BYTES = 4096

_CAPSULE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_PROTECTED_LABELS = frozenset({1, 3, 4})


@dataclass(frozen=True)
class Finding:
    """One structured producer-envelope verification failure."""

    code: str
    detail: str


@dataclass
class VerificationResult:
    """Never-raising result returned by :func:`verify_producer_envelope`."""

    ok: bool = False
    findings: list[Finding] = field(default_factory=list)
    capsule_id: str = ""
    public_key: bytes | None = None


def _failed(result: VerificationResult, code: str, detail: str) -> VerificationResult:
    result.findings.append(Finding(code, detail))
    return result


def _plain_map(value: object) -> dict:
    if not hasattr(value, "items"):
        raise CoseError("header is not a CBOR map")
    return dict(value.items())  # type: ignore[union-attr]


def verify_producer_envelope(capsule_id: str, data: bytes) -> VerificationResult:
    """Authenticate one producer envelope against ``capsule_id``.

    The function never raises on malformed or unverifiable input. A successful
    result returns the authenticated raw Ed25519 public key. Whether that key is
    authorized for the Capsule's operator or developer is a caller policy.
    """
    result = VerificationResult(capsule_id=capsule_id)
    if not isinstance(capsule_id, str) or _CAPSULE_ID_RE.fullmatch(capsule_id) is None:
        return _failed(result, "capsule_id_malformed", "capsule_id MUST be 64 lowercase hexadecimal characters")
    expected_payload = bytes.fromhex(capsule_id)
    if not isinstance(data, (bytes, bytearray)):
        return _failed(result, "envelope_malformed", "producer envelope MUST be bytes")
    data = bytes(data)
    if len(data) > MAX_ENVELOPE_BYTES:
        return _failed(
            result,
            "envelope_too_large",
            f"producer envelope is {len(data)} bytes; maximum is {MAX_ENVELOPE_BYTES}",
        )

    try:
        outer = strict_decode(data)
        if outer.tag != 18 or not isinstance(outer.value, (list, tuple)) or len(outer.value) != 4:
            raise CoseError("top-level value MUST be a four-element COSE_Sign1 tag 18")
        protected_bytes, unprotected_value, payload_value, signature_value = outer.value
        if not isinstance(protected_bytes, bytes) or not protected_bytes:
            raise CoseError("protected header MUST be a non-empty byte string")
        protected = _plain_map(cbor2.loads(protected_bytes))
        unprotected = _plain_map(unprotected_value)
        if unprotected:
            raise CoseError("unprotected header MUST be an empty map")
        if not isinstance(payload_value, bytes):
            raise CoseError("attached payload MUST be a byte string")
        if not isinstance(signature_value, bytes):
            raise CoseError("signature MUST be a byte string")
    except Exception as exc:  # parser boundary: never raise
        return _failed(result, "envelope_malformed", str(exc))

    if protected.get(1) != COSE_ALGORITHM_EDDSA:
        return _failed(result, "envelope_algorithm_mismatch", "protected alg (label 1) MUST be EdDSA (-8)")
    if protected.get(3) != CONTENT_TYPE:
        return _failed(
            result,
            "envelope_content_type_mismatch",
            f"protected content type (label 3) MUST be {CONTENT_TYPE!r}",
        )
    public_key = protected.get(4)
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        return _failed(
            result,
            "envelope_kid_invalid",
            "protected kid (label 4) MUST be the raw 32-byte Ed25519 public key",
        )
    if set(protected) != _PROTECTED_LABELS:
        return _failed(
            result,
            "envelope_protected_headers_invalid",
            "protected header MUST contain exactly alg, content type, and kid",
        )
    if payload_value != expected_payload:
        return _failed(result, "envelope_payload_mismatch", "attached payload MUST equal the raw 32-byte Capsule ID")
    if len(signature_value) != 64:
        return _failed(result, "envelope_signature_invalid", "Ed25519 signature MUST be 64 bytes")

    try:
        pem = Ed25519PublicKey.from_public_bytes(public_key).public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        verify_sign1(data, public_key_pem=pem, understood_labels=_PROTECTED_LABELS)
    except (CoseError, ValueError) as exc:
        return _failed(result, "envelope_signature_invalid", str(exc))

    result.ok = True
    result.public_key = public_key
    return result


__all__ = [
    "CONTENT_TYPE",
    "COSE_ALGORITHM_EDDSA",
    "Finding",
    "VerificationResult",
    "verify_producer_envelope",
]
