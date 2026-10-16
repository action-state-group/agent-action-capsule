# SPDX-License-Identifier: BSD-3-Clause
"""Verify AAC producer envelopes over signer-independent Capsule IDs.

This optional module requires ``agent-action-capsule[envelope]``. It reuses the
public ``scitt-cose`` COSE_Sign1 verifier and adds the exact AAC profile checks:
raw 32-byte Capsule-ID payload, EdDSA, the AAC Capsule-ID media type, raw
Ed25519-public-key ``kid``, an empty unprotected map, and the CBOR encoding
rules (shortest-form, definite-length, no tag but the outer tag 18). Signer
authorization is deliberately outside this cryptographic self-attestation
verdict.
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


def _untagged(data: bytes) -> bool:
    """Whether no data item in ``data`` carries a CBOR tag.

    ``data`` has already passed ``strict_decode``, so it is one well-formed,
    definite-length item and only the heads need walking. cbor2 resolves some
    tags into other types (tag 2 into an integer, tag 55799 into its content),
    so a tag is visible only in the encoded bytes.
    """
    offset, pending = 0, 1
    while pending:
        pending -= 1
        major, info = data[offset] >> 5, data[offset] & 31
        width = {24: 1, 25: 2, 26: 4, 27: 8}.get(info, 0)
        argument = int.from_bytes(data[offset + 1 : offset + 1 + width], "big") if width else info
        offset += 1 + width
        if major == 6:
            return False
        if major in (2, 3):
            offset += argument
        elif major == 4:
            pending += argument
        elif major == 5:
            pending += 2 * argument
    return True


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
        # strict_decode has already required the shortest form of every
        # argument and float, inside the protected header too. The profile
        # also allows no tag but the single outer tag 18.
        if data[0] != 0xD2 or not _untagged(data[1:]):
            raise CoseError("only the outer COSE_Sign1 tag 18 may be a CBOR tag")
        protected_bytes, unprotected_value, payload_value, signature_value = outer.value
        if not isinstance(protected_bytes, bytes) or not protected_bytes:
            raise CoseError("protected header MUST be a non-empty byte string")
        if not _untagged(protected_bytes):
            raise CoseError("protected header MUST NOT contain a CBOR tag")
        protected = _plain_map(cbor2.loads(protected_bytes))
        # Labels are CBOR integers. Python treats True as 1 and -8.0 as -8, so
        # check types explicitly, as the Go decoder's int64 labels do.
        if any(type(label) is not int for label in protected):
            raise CoseError("protected header labels MUST be integers")
        unprotected = _plain_map(unprotected_value)
        if unprotected:
            raise CoseError("unprotected header MUST be an empty map")
        if not isinstance(payload_value, bytes):
            raise CoseError("attached payload MUST be a byte string")
        if not isinstance(signature_value, bytes):
            raise CoseError("signature MUST be a byte string")
    except Exception as exc:  # parser boundary: never raise
        return _failed(result, "envelope_malformed", str(exc))

    algorithm = protected.get(1)
    if type(algorithm) is not int or algorithm != COSE_ALGORITHM_EDDSA:
        return _failed(result, "envelope_algorithm_mismatch", "protected alg (label 1) MUST be EdDSA (-8)")
    if type(protected.get(3)) is not str or protected.get(3) != CONTENT_TYPE:
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
    "AUTHORED",
    "INVALID",
    "UNCLAIMED",
    "CONTENT_TYPE",
    "COSE_ALGORITHM_EDDSA",
    "Finding",
    "VerificationResult",
    "verify_producer_envelope",
    "verify_record_signature",
]


# -- a record's producer signature ---------------------------------------------

AUTHORED = "authored"
UNCLAIMED = "unclaimed"
INVALID = "invalid"

# The local-only producer-envelope fields; never part of a Capsule ID preimage.
_LOCAL_ONLY_FIELDS = ("signature", "key_id")


def _record_capsule_id(record: dict) -> str:
    """The Capsule ID ``record`` declares by its ``canonicalization_id``.

    ``jcs`` (format 4) commits every member but ``capsule_id`` and the
    local-only envelope fields. A record without the slot (or with JSON
    ``null``) predates it and keeps the vintage ``jcs-n`` reading, which also
    drops ``chain`` and removes null and empty members before JCS. Any other
    algorithm raises ``ValueError``.
    """
    import hashlib

    from .canonical import jcs, normalize

    declared = record.get("canonicalization_id")
    algorithm = "jcs-n" if declared is None else declared
    canonical = {k: v for k, v in record.items() if k != "capsule_id" and k not in _LOCAL_ONLY_FIELDS}
    if algorithm == "jcs-n":
        canonical.pop("chain", None)
        return hashlib.sha256(jcs(normalize(canonical))).hexdigest()
    if algorithm == "jcs":
        return hashlib.sha256(jcs(canonical)).hexdigest()
    raise ValueError(f"cannot compute capsule_id with canonicalization_id {algorithm!r}")


def verify_record_signature(record: object) -> tuple[str, list[str]]:
    """Grade a record's producer signature: ``authored``, ``unclaimed`` or ``invalid``.

    ``record["signature"]`` is the hex producer envelope and
    ``record["key_id"]`` the hex raw Ed25519 public key. Neither present is
    ``unclaimed`` (an unsigned record, not a forgery); one without the other,
    or an envelope that does not verify over the Capsule ID recomputed from the
    record's own content (``jcs`` or vintage ``jcs-n``) under ``key_id``, is
    ``invalid``. The carried ``capsule_id`` is not read. Returns ``(verdict,
    messages)``; ``messages`` is empty unless ``invalid``. Never raises.
    """
    if not isinstance(record, dict):
        return INVALID, ["not a mapping"]
    cid = record.get("capsule_id", "<none>")
    has_signature, has_key_id = "signature" in record, "key_id" in record
    if not has_signature and not has_key_id:
        return UNCLAIMED, []
    if has_signature != has_key_id:
        return INVALID, [f"capsule_id={cid}: only one of signature/key_id present -- malformed producer envelope"]
    try:
        result = verify_producer_envelope(_record_capsule_id(record), bytes.fromhex(record["signature"]))
        ok = result.ok and result.public_key == bytes.fromhex(record["key_id"])
    except (KeyError, ValueError, TypeError) as exc:
        return INVALID, [f"capsule_id={cid}: producer envelope malformed: {exc}"]
    if ok:
        return AUTHORED, []
    return INVALID, [
        f"capsule_id={cid}: self-attested Ed25519 signature does not verify against key_id -- "
        "content, signature, or key_id was tampered or forged"
    ]
