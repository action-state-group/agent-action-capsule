# SPDX-License-Identifier: BSD-3-Clause
"""Offline checks of the witness receipts an Evidence Bundle's checkpoint carries.

A witness is a transparency service that took a log's signed checkpoint and
returned a receipt a verifier can check offline. ``checkpoint.witnesses`` in
an Evidence Bundle lists them as CLL ``WitnessRecord`` objects (``ts_url``,
``entry_hash``, ``receipt_b64``, ``leaf_index``, ``tree_size``, optional
``is_stub``). The Bundle draft defines no witness member, so this check is an
opt-in verifier extension (``verify_bundle(..., strict=True)``): only a
receipt that fails changes the verdict.

No witness is trusted by default. The caller supplies a witness directory (a
parsed ``witnesses.json``: ``{"witnesses": [row, ...]}``, or the row list),
and every row is read the same way. A receipt whose witness has no row, or
whose row has no usable key, is not checked (``withheld``), never failed.

Three bindings, named by the ``ts_url`` scheme:

* ``https://host`` (``cll``): a COSE Receipt (RFC 9162 inclusion) whose leaf
  is ``entry_hash``, which must equal SHA-256 of the checkpoint digest (the
  SHA-256 of CLL's checkpoint signing body).
* ``rekor+https://host`` (``rekor``): a Sigstore Rekor ``dsse`` entry. Its
  Signed Entry Timestamp verifies under the row's ECDSA P-256 key, its
  ``logID`` is that key's RFC 6962 log ID, its ``payloadHash`` is SHA-256 of
  the checkpoint's COSE statement, and its only verifier is the checkpoint's
  own key.
* ``scrapi+https://host`` (``scrapi``): a SCITT COSE Receipt (RFC 9162) whose
  leaf is SHA-256 of the checkpoint's COSE statement.

Requires ``agent-action-capsule[bundle,envelope]`` (``scitt-cose`` and
``cryptography``). Never raises.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ._ed25519_strict import strict_encoding as _strict_ed25519
from .canonical import loads_bounded

__all__ = [
    "ANCHOR_WITNESS_KIND",
    "ANCHOR_WITNESS_PROPERTY",
    "AnchorReceiptReport",
    "AnchorWitnessReport",
    "BINDING_CLL",
    "BINDING_REKOR",
    "BINDING_SCRAPI",
    "GRADE_MMR_VERIFIED",
    "GRADE_OBSERVED_ONLY",
    "REGISTRATION_TIME_REASONS",
    "WitnessReceiptResult",
    "binding_of",
    "check_anchor_receipt",
    "check_anchor_witnessed",
    "checkpoint_digest",
    "endpoint_of",
    "row_for",
    "row_public_keys_pem",
    "verify_receipt",
    "verify_rekor_receipt",
    "verify_scrapi_receipt",
    "verify_witness_receipts",
]

BINDING_CLL = "cll"
BINDING_REKOR = "rekor"
BINDING_SCRAPI = "scrapi"

#: The two receipt grades a witness may sign into its receipt's protected
#: header (private-use label -65537): existence and time only, and MMR
#: consistency checked. ``countersigned-observed`` is the pre-rename spelling
#: of ``observed-only`` and is read as it.
GRADE_OBSERVED_ONLY = "observed-only"
GRADE_MMR_VERIFIED = "mmr-verified"
_GRADES = {
    GRADE_OBSERVED_ONLY: GRADE_OBSERVED_ONLY,
    "countersigned-observed": GRADE_OBSERVED_ONLY,
    GRADE_MMR_VERIFIED: GRADE_MMR_VERIFIED,
}
_GRADE_LABEL = -65537

#: Why a receipt result has no ``registration_time``: the receipt did not
#: pass; it passed with no ``iat`` in its protected CWT claims; its protected
#: ``iat`` is not an integer number of seconds from 0 to 2^53 - 1; or its
#: binding (``rekor``) is no COSE Receipt and so carries no ``iat``.
REGISTRATION_TIME_REASONS = ("receipt_not_passed", "iat_absent", "iat_invalid", "binding_without_iat")
_CWT_CLAIMS_LABEL = 15
_CWT_IAT = 6
#: The largest ``iat`` reported: every language reads it as an exact integer.
_MAX_IAT = 2**53 - 1

# The CLL checkpoint fields its signing body covers, besides ``v``/``kind``.
_SIGNED_FIELDS = ("log_id", "mmr_size", "root", "prev_size", "prev_root", "key_id", "timestamp")
_RECORD_FIELDS = ("ts_url", "entry_hash", "receipt_b64", "leaf_index", "tree_size")
#: The WitnessRecord members that must be non-empty strings.
_TEXT_FIELDS = ("ts_url", "entry_hash", "receipt_b64")


@dataclass(frozen=True)
class WitnessReceiptResult:
    """One receipt's outcome: ``status`` is ``pass``, ``withheld`` or ``fail``.

    ``reason`` is a human-readable explanation and is not part of the
    cross-language contract; ``grade`` is the verified receipt grade, or
    ``None``. A passing receipt names the directory ``key_id`` it verified
    under. ``registration_time`` is the ``iat`` the witness signed into a
    passing COSE Receipt's protected header, in seconds since the epoch;
    otherwise it is ``None`` and ``registration_time_reason`` (one of
    :data:`REGISTRATION_TIME_REASONS`) says why.
    """

    ts_url: str
    binding: str
    status: str
    reason: str
    grade: str | None = None
    key_id: str | None = None
    registration_time: int | None = None
    registration_time_reason: str | None = None


def binding_of(url: str) -> str:
    """The binding a witness URL names: ``rekor+...`` -> ``rekor``,
    ``scrapi+...`` -> ``scrapi``, anything else -> ``cll``."""
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    if scheme.startswith(BINDING_REKOR + "+"):
        return BINDING_REKOR
    if scheme.startswith(BINDING_SCRAPI + "+"):
        return BINDING_SCRAPI
    return BINDING_CLL


def endpoint_of(url: str) -> str:
    """The base URL with any binding prefix removed and no trailing slash."""
    if binding_of(url) != BINDING_CLL:
        url = url.split("+", 1)[1]
    return url.rstrip("/")


def _rows(directory: Any) -> list[Any]:
    if isinstance(directory, Mapping):
        rows = directory.get("witnesses")
        return list(rows) if isinstance(rows, list) else []
    return list(directory) if isinstance(directory, list) else []


def row_for(directory: Any, ts_url: str) -> Mapping[str, Any] | None:
    """The directory row a receipt's witness URL belongs to: the same binding
    (a row without ``binding`` is ``cll``) and the same endpoint, trailing
    slash ignored. ``None`` when no row matches."""
    binding = binding_of(ts_url)
    endpoint = endpoint_of(ts_url)
    for row in _rows(directory):
        if not isinstance(row, Mapping):
            continue
        row_endpoint = row.get("endpoint", "")
        if (
            row.get("binding", BINDING_CLL) == binding
            and isinstance(row_endpoint, str)
            and row_endpoint.rstrip("/") == endpoint
        ):
            return row
    return None


def _b64_canonical(text: Any) -> bytes:
    """Strict standard base64 with padding, in its one canonical spelling:
    ``validate=True`` still ignores non-zero trailing bits, which other
    languages' decoders refuse, so the bytes must re-encode to ``text``."""
    if not isinstance(text, str):
        raise TypeError("base64 member is not a string")
    raw = base64.b64decode(text, validate=True)
    if base64.b64encode(raw).decode("ascii") != text:
        raise binascii.Error("non-canonical base64")
    return raw


def _der(b64: Any) -> bytes | None:
    try:
        return _b64_canonical(b64) if isinstance(b64, str) else None
    except (binascii.Error, ValueError):
        return None


def _raw_ed25519(der: bytes) -> str | None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

    try:
        key = load_der_public_key(der)
    except Exception:  # noqa: BLE001 -- any unreadable key is "not an Ed25519 key"
        return None
    if not isinstance(key, Ed25519PublicKey):
        return None
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def row_public_keys_pem(row: Mapping[str, Any]) -> list[bytes]:
    """Every key a row lists, as SubjectPublicKeyInfo PEM, in ``key_ids``
    order: the ``public_keys`` entry the key id names (by SHA-256 of its DER,
    or an Ed25519 key by its raw bytes) when there is one, else the key id read
    as a raw Ed25519 key. In a ``rekor`` row a key id is an RFC 6962 log ID,
    so one with no ``public_keys`` entry raises ``ValueError``."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

    by_id: dict[str, bytes] = {}
    public_keys, key_ids = row.get("public_keys", []), row.get("key_ids", [])
    if not isinstance(public_keys, list) or not isinstance(key_ids, list):
        raise ValueError("key_ids and public_keys must be lists")
    for b64 in public_keys:
        der = _der(b64)
        try:
            # Only an Ed25519 or an ECDSA P-256 public key counts: the only
            # keys any receipt verifies under. An entry that is not a
            # SubjectPublicKeyInfo, holds another algorithm or curve (RSA,
            # secp256k1, an unknown OID) or does not load is skipped, like one
            # that is not base64.
            key = load_der_public_key(der) if der is not None else None
            if not (
                isinstance(key, Ed25519PublicKey)
                or (isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1))
            ):
                der = None
        except Exception:  # noqa: BLE001
            der = None
        if der is not None:
            by_id[hashlib.sha256(der).hexdigest()] = der
            raw = _raw_ed25519(der)
            if raw is not None:
                by_id[raw] = der
    pems = []
    for key_id in key_ids:
        if not isinstance(key_id, str) or not re.fullmatch(r"[0-9a-f]{64}", key_id):
            raise ValueError("a key id is not 64 lowercase hex characters")
        if key_id in by_id:
            key = load_der_public_key(by_id[key_id])
        elif row.get("binding") == BINDING_REKOR:
            raise ValueError(f"rekor row {row.get('name')!r}: no public key for log ID {str(key_id)[:16]}...")
        else:
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_id))
        pems.append(key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    return pems


def checkpoint_digest(signed: Mapping[str, Any]) -> str:
    """CLL's checkpoint digest: SHA-256 of the checkpoint signing body, the
    JSON object of ``v`` (1), ``kind`` (``mmr_checkpoint``) and the signed
    fields, keys sorted, no whitespace, non-ASCII escaped as ``\\uXXXX``."""
    body = {"v": 1, "kind": "mmr_checkpoint", **{name: signed[name] for name in _SIGNED_FIELDS}}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _receipt_shape_error(receipt: bytes, key_pem: bytes | str | None = None) -> str | None:
    """Refuse what ``scitt_cose.verify_receipt`` would read differently from
    this profile: a receipt must be a tag-18 COSE_Sign1 with a detached
    (``nil``) payload, so its signature covers the rebuilt Merkle root, and its
    protected ``vds`` (label 395) must be 1, RFC9162_SHA256."""
    import cbor2

    try:
        outer = cbor2.loads(receipt)
        if not isinstance(outer, cbor2.CBORTag) or outer.tag != 18:
            return "receipt is not a COSE_Sign1 message"
        value = outer.value
        if not isinstance(value, (list, tuple)) or len(value) != 4 or not isinstance(value[0], bytes):
            return "receipt is not a COSE_Sign1 message"
        if value[2] is not None:
            return "receipt payload is attached; a receipt's payload must be detached"
        protected = cbor2.loads(value[0]) if value[0] else {}
    except Exception as exc:  # noqa: BLE001
        return f"receipt could not be decoded: {type(exc).__name__}"
    vds, alg = (protected.get(395), protected.get(1)) if isinstance(protected, dict) else (None, None)
    if type(vds) is not int or vds != 1:
        return "receipt vds is not RFC9162_SHA256 (1)"
    if type(alg) is not int or alg not in (-8, -7):
        return "receipt alg is not EdDSA (-8) or ES256 (-7)"
    if key_pem is not None:
        # The algorithm fixes the key type: ES256 is ECDSA over P-256 only and
        # EdDSA is Ed25519 here. scitt_cose checks neither curve nor type.
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        try:
            key = load_pem_public_key(key_pem.encode() if isinstance(key_pem, str) else key_pem)
        except Exception:  # noqa: BLE001
            return "the key is not a usable public key"
        if alg == -7 and not (isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)):
            return "receipt alg ES256 needs an ECDSA P-256 key"
        if alg == -8 and not isinstance(key, Ed25519PublicKey):
            return "receipt alg EdDSA needs an Ed25519 key"
        if alg == -8:
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            if not isinstance(value[3], bytes) or not _strict_ed25519(raw, value[3]):
                return "receipt EdDSA signature is not strict Ed25519: a non-canonical or small-order key or R, or S >= L"
    return None


def _grade(result: Any) -> str | None:
    label = (getattr(result, "protected_header_ext", None) or {}).get(_GRADE_LABEL)
    return _GRADES.get(label) if isinstance(label, str) else None


def _integer_key(mapping: dict, key: int, default: Any) -> Any:
    """``mapping``'s value under the CBOR integer ``key``. A float or boolean
    key that Python hashes equal (``6.0``, ``True`` for 1) is another key, as
    the other languages read it."""
    return next((v for k, v in mapping.items() if type(k) is int and k == key), default)


def _registration_time(receipt: bytes) -> tuple[int | None, str | None]:
    """The ``iat`` (claim 6) of a verified COSE Receipt's protected CWT claims
    (label 15), as ``(time, None)``, or ``(None, reason)``. Read only after the
    signature verified: only the protected header is signed."""
    import cbor2

    try:
        protected_bytes = cbor2.loads(receipt).value[0]
        protected = cbor2.loads(protected_bytes) if protected_bytes else {}
    except Exception:  # noqa: BLE001 -- a verified receipt decodes; never raise
        return None, "iat_invalid"
    absent = object()
    claims = _integer_key(protected, _CWT_CLAIMS_LABEL, absent)
    if claims is absent:
        return None, "iat_absent"
    if not isinstance(claims, dict):
        return None, "iat_invalid"
    iat = _integer_key(claims, _CWT_IAT, absent)
    if iat is absent:
        return None, "iat_absent"
    if type(iat) is not int or not 0 <= iat <= _MAX_IAT:
        return None, "iat_invalid"
    return iat, None


def _verify_cll(signed: Mapping[str, Any], record: Mapping[str, Any], pem: bytes) -> tuple[bool, str, str | None]:
    """A CLL witness stamp under one pinned key: bound to this checkpoint
    (``entry_hash``), then the COSE Receipt verifies over that leaf."""
    try:
        expected = hashlib.sha256(bytes.fromhex(checkpoint_digest(signed))).hexdigest()
    except Exception as exc:  # noqa: BLE001
        return False, f"checkpoint digest could not be computed: {exc}", None
    if record["entry_hash"] != expected:
        return False, (
            "witness.entry_hash does not match this checkpoint's digest -- stamp is not bound to this checkpoint"
        ), None
    try:
        receipt = _b64_canonical(record["receipt_b64"])
    except Exception as exc:  # noqa: BLE001
        return False, f"receipt_b64 is not valid base64: {exc}", None
    try:
        from scitt_cose import verify_receipt
    except ImportError:
        return False, "not checked: scitt-cose is not installed (agent-action-capsule[envelope])", None
    shape = _receipt_shape_error(receipt, pem)
    if shape is not None:
        return False, shape, None
    try:
        result = verify_receipt(receipt, leaf_entry_hex=record["entry_hash"], log_public_key_pem=pem)
    except Exception as exc:  # noqa: BLE001
        return False, f"receipt could not be evaluated: {exc}", None
    if not result.ok:
        return False, "; ".join(result.errors) or "receipt signature does not verify under the pinned/supplied key", None
    grade = _grade(result)
    return True, "ok" if grade is not None else "ok (receipt carries no grade label)", grade


def _sorted_json(value: Any) -> bytes:
    # Rekor's canonical JSON: keys sorted, no whitespace. Every value signed
    # here is a string or an integer.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _ed25519_spki_pem(raw: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return Ed25519PublicKey.from_public_bytes(raw).public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def verify_rekor_receipt(
    receipt: Any, *, checkpoint_cose: bytes, checkpoint_key_id: str, rekor_public_key_pem: bytes
) -> tuple[bool, str]:
    """Offline check of one Rekor ``dsse`` entry (a parsed log entry) against
    the checkpoint it claims: the Signed Entry Timestamp verifies under
    ``rekor_public_key_pem`` and ``logID`` is that key's, the entry's
    ``payloadHash`` is SHA-256 of ``checkpoint_cose``, and its only verifier
    key is the Ed25519 key ``checkpoint_key_id`` names. Returns ``(ok,
    reason)``; never raises."""
    cose, pem = checkpoint_cose, rekor_public_key_pem
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

        rekor_key = load_pem_public_key(pem)
        if not isinstance(rekor_key, ec.EllipticCurvePublicKey) or not isinstance(rekor_key.curve, ec.SECP256R1):
            return False, "the Rekor key is not an ECDSA P-256 key"
        log_id = hashlib.sha256(rekor_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        if receipt.get("logID") != log_id:
            return False, "logID is not the pinned Rekor key"
        set_b64 = (receipt.get("verification") or {}).get("signedEntryTimestamp")
        if not set_b64:
            return False, "no signedEntryTimestamp"
        integrated, index = receipt["integratedTime"], receipt["logIndex"]
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (integrated, index)):
            return False, "integratedTime and logIndex must be JSON integers"
        if not isinstance(receipt["body"], str):
            return False, "body must be a string"
        signed = _sorted_json(
            {"body": receipt["body"], "integratedTime": integrated, "logID": receipt["logID"], "logIndex": index}
        )
        try:
            rekor_key.verify(_b64_canonical(set_b64), signed, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False, "signedEntryTimestamp does not verify under the pinned Rekor key"
        entry = loads_bounded(_b64_canonical(receipt["body"]))
        if entry.get("kind") != "dsse":
            return False, f"entry kind {entry.get('kind')!r}, expected 'dsse'"
        spec = entry.get("spec") or {}
        payload_hash = spec.get("payloadHash") or {}
        if payload_hash.get("algorithm") != "sha256" or payload_hash.get("value") != hashlib.sha256(cose).hexdigest():
            return False, "entry payloadHash is not this checkpoint's bytes"
        verifiers = {
            _b64_canonical(s.get("verifier", "")).replace(b"\r", b"").strip()
            for s in spec.get("signatures") or []
        }
        if verifiers != {_ed25519_spki_pem(bytes.fromhex(checkpoint_key_id)).strip()}:
            return False, "entry is not signed by the checkpoint's key"
        return True, "ok"
    except Exception as exc:  # noqa: BLE001 -- verification degrades to "no", never raises
        return False, f"unreadable receipt: {exc}"


def verify_scrapi_receipt(
    receipt: bytes, *, checkpoint_cose: bytes, service_public_key_pem: bytes | str | None
) -> tuple[bool, str, str | None]:
    """Offline check of a SCRAPI receipt: a SCITT COSE Receipt (RFC 9162) over
    the leaf SHA-256(``checkpoint_cose``), signed under the pinned key.
    Without a key nothing is checked. Returns ``(ok, reason, grade)``."""
    cose, pem = checkpoint_cose, service_public_key_pem
    if pem is None:
        return False, "not checked: no key pinned for this service", None
    try:
        from scitt_cose import verify_receipt
    except ImportError:
        return False, "not checked: scitt_cose not installed", None
    shape = _receipt_shape_error(receipt, pem)
    if shape is not None:
        return False, f"unreadable receipt: {shape}", None
    try:
        result = verify_receipt(receipt, leaf_entry_hex=hashlib.sha256(cose).hexdigest(), log_public_key_pem=pem)
    except Exception as exc:  # noqa: BLE001
        return False, f"unreadable receipt: {exc}", None
    if not result.ok:
        return False, "receipt does not verify for this checkpoint under the pinned key", None
    label = (getattr(result, "protected_header_ext", None) or {}).get(_GRADE_LABEL)
    if label is None:
        return True, "ok", GRADE_OBSERVED_ONLY
    grade = _GRADES.get(label) if isinstance(label, str) else None
    if grade is not None:
        return True, "ok", grade
    return True, "ok (unknown grade label ignored)", GRADE_OBSERVED_ONLY


def verify_receipt(
    signed: Mapping[str, Any], record: Mapping[str, Any], key_pem: bytes, checkpoint_cose: bytes | None
) -> tuple[bool, str, str | None]:
    """One receipt (a ``WitnessRecord`` mapping) under one key, for the
    checkpoint whose signed fields are ``signed`` and whose COSE statement is
    ``checkpoint_cose``. The binding comes from ``record["ts_url"]``. Returns
    ``(ok, reason, grade)``; never raises on a malformed receipt."""
    pem, cose = key_pem, checkpoint_cose
    binding = binding_of(record["ts_url"])
    if binding == BINDING_CLL:
        return _verify_cll(signed, record, pem)
    if cose is None:
        return False, "not checked: checkpoint COSE statement not available", None
    if binding == BINDING_REKOR:
        try:
            receipt = loads_bounded(_b64_canonical(record["receipt_b64"]))
        except (ValueError, TypeError, RecursionError) as exc:
            return False, f"unreadable receipt: {exc}", None
        ok, reason = verify_rekor_receipt(
            receipt, checkpoint_cose=cose, checkpoint_key_id=signed["key_id"], rekor_public_key_pem=pem
        )
        return ok, reason, GRADE_OBSERVED_ONLY if ok else None
    try:
        receipt_bytes = _b64_canonical(record["receipt_b64"])
    except (ValueError, TypeError) as exc:
        return False, f"unreadable receipt: {exc}", None
    return verify_scrapi_receipt(receipt_bytes, checkpoint_cose=cose, service_public_key_pem=pem)


def _is_record(entry: Any) -> bool:
    """A WitnessRecord: every member present; ``ts_url``, ``entry_hash`` and
    ``receipt_b64`` non-empty strings; ``receipt_b64`` canonical standard
    base64. Anything else is malformed, never merely not checked."""
    if not isinstance(entry, Mapping) or not all(k in entry for k in _RECORD_FIELDS):
        return False
    if not all(isinstance(entry[k], str) and entry[k] for k in _TEXT_FIELDS):
        return False
    try:
        _b64_canonical(entry["receipt_b64"])
    except ValueError:  # binascii.Error included
        return False
    return True


def verify_witness_receipts(
    receipts: Any,
    signed: Mapping[str, Any] | None,
    checkpoint_cose: bytes | None,
    directory: Any = None,
) -> tuple[str, tuple[str, ...], tuple[WitnessReceiptResult, ...]]:
    """Check every receipt in ``receipts`` (a Bundle's ``checkpoint.witnesses``)
    against the SIGNED checkpoint ``signed`` (its fields as the COSE statement
    states them; ``None`` when it did not verify) and its COSE bytes, under the
    keys of ``directory``. ``None`` trusts no witness.

    Returns ``(status, findings, receipts)``. ``status`` is ``fail`` when a
    receipt is malformed or does not verify, else ``pass`` when one verifies,
    else ``withheld``.
    """
    if not isinstance(receipts, list) or not receipts:
        return "withheld", ("witness_receipt_absent",), ()
    if signed is None or checkpoint_cose is None:
        return "withheld", ("checkpoint_unverified",), ()
    # Malformed entries are listed first, then one finding per checked receipt.
    findings = [f"witness_receipt_malformed:{i}" for i, record in enumerate(receipts) if not _is_record(record)]
    malformed = bool(findings)
    results: list[WitnessReceiptResult] = []
    for record in receipts:
        if not _is_record(record):
            continue
        ts_url = record["ts_url"]
        row = row_for(directory, ts_url)
        ok, reason, grade, key_id = False, "", None, None
        if record.get("is_stub") is True:
            reason = "stub receipt (never reached a witness)"
        elif row is None:
            reason = "not checked: no directory row for this witness"
        else:
            try:
                pems = row_public_keys_pem(row)
            except Exception as exc:  # noqa: BLE001 -- an unusable row key is "not checked"
                pems, reason = [], f"not checked: unusable key in directory row ({exc})"
            for index, pem in enumerate(pems):
                ok, reason, grade = verify_receipt(signed, record, pem, checkpoint_cose)
                if ok:
                    # row_public_keys_pem returns one key per key id, in order.
                    key_id = row["key_ids"][index]
                    break
        registration_time, time_reason = None, "receipt_not_passed"
        if ok:
            status = "pass"
            if binding_of(ts_url) == BINDING_REKOR:
                time_reason = "binding_without_iat"
            else:
                registration_time, time_reason = _registration_time(_b64_canonical(record["receipt_b64"]))
        elif not reason or reason.startswith(("not checked", "stub receipt")):
            status = "withheld"
            reason = reason or "not checked: no key in the directory row for this witness"
            findings.append(f"witness_unverified:{ts_url}")
        else:
            status = "fail"
            findings.append(f"witness_receipt_invalid:{ts_url}")
        results.append(WitnessReceiptResult(
            ts_url, binding_of(ts_url), status, reason, grade if ok else None, key_id, registration_time, time_reason,
        ))
    statuses = {r.status for r in results}
    if malformed or "fail" in statuses:
        overall = "fail"
    elif "pass" in statuses:
        overall = "pass"
    else:
        overall = "withheld"
    return overall, tuple(findings), tuple(results)


#: The verification-material kind of a witness Receipt over a Checkpointed Local
#: Log anchor, and the check over it (``spec/interop-profile-v1.md`` §6.2.2).
#: ``anchor_witnessed`` is not an envelope property and never enters the
#: profile's §8 mapping: it says when a witness the relying party accepts
#: registered the anchor, and nothing about any artifact under it. Statuses
#: are the profile's §7.1 values.
ANCHOR_WITNESS_KIND = "cll-witness-receipt"
ANCHOR_WITNESS_PROPERTY = "anchor_witnessed"
_PASS, _FAIL, _NOT_PRESENT, _NOT_CHECKED = "PASS", "FAIL", "NOT_PRESENT", "NOT_CHECKED"
_ANCHOR_DIGEST = re.compile(r"[0-9a-f]{64}")

_ALG_EDDSA, _ALG_ES256 = -8, -7
_METHOD = "RFC 9942 Receipt (RFC9162_SHA256) over the CLL-01 anchor digest (§6.2.2)"


@dataclass(frozen=True)
class AnchorReceiptReport:
    """One Receipt's status, its witness's name when it passed, and its registration time
    (a NumericDate) when it passed with a protected ``iat``."""

    status: str
    witness: str | None = None
    registration_time: int | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "witness": self.witness, "registration_time": self.registration_time}


@dataclass(frozen=True)
class AnchorWitnessReport:
    """``anchor_witnessed`` over every Receipt for one anchor (§6.2.2). ``witness`` and
    ``witnessed_time`` always come from the same Receipt."""

    status: str
    method: str
    receipts: tuple[AnchorReceiptReport, ...]
    witness: str | None
    witnessed_time: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "property": ANCHOR_WITNESS_PROPERTY,
            "status": self.status,
            "receipts": [r.to_dict() for r in self.receipts],
            "witness": self.witness,
            "witnessed_time": self.witnessed_time,
        }


_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")
_P256_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
_LOWER_HEX = re.compile(r"(?:[0-9a-f]{2})*")
_MAX_RECEIPT_OCTETS = 10 * 1024 * 1024
_MAX_PROOFS = 16
_MAX_TREE_SIZE = 1 << 62
_MAX_DEPTH = 16
_PRIVATE_LABEL = -65536  # labels below this are private use (RFC 9052 §16.4)


class _NotTheForm(Exception):
    pass


def _anchor_key_type(spki: bytes) -> str:
    """``ed25519`` or ``p256`` for the two exact SubjectPublicKeyInfo shapes of §6.2.2 step 2,
    else ``other``."""
    if len(spki) == 44 and spki.startswith(_ED25519_PREFIX):
        return "ed25519"
    if len(spki) == 91 and spki.startswith(_P256_PREFIX):
        return "p256"
    return "other"


def _anchor_policy_keys(policy: Any) -> list[tuple[str, bytes]]:
    """``(name, spki)`` in policy order: every key entry that is lowercase hex. An entry of any
    other shape lists no key."""
    rows = policy.get("witnesses") if isinstance(policy, Mapping) else None
    out: list[tuple[str, bytes]] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, Mapping) or not isinstance(row.get("name"), str):
            continue
        for key in row.get("keys") if isinstance(row.get("keys"), list) else []:
            if isinstance(key, str) and _LOWER_HEX.fullmatch(key):
                out.append((row["name"], bytes.fromhex(key)))
    return out


def _strict(octets: bytes, top_tag: bool = False) -> Any:
    """One CBOR item under the §6.2.2 encoding rules: no trailing octet, definite lengths, every
    argument shortest, no repeated key, no float, no tag but an outer 18 when ``top_tag``."""
    from .interop_profile._cbor import CborError, Tag, decode

    try:
        decoded = decode(octets)
    except CborError as exc:
        raise _NotTheForm(str(exc)) from exc
    if decoded.duplicate_keys or decoded.irregular or not decoded.shortest:
        raise _NotTheForm("not strict CBOR: a repeated key, a float or a longer argument")

    def walk(value: Any, depth: int) -> None:
        if depth > _MAX_DEPTH:
            raise _NotTheForm("an item nested more than 16 levels deep")
        if _int(value) and not -(1 << 63) <= value < (1 << 64):
            raise _NotTheForm("an integer below -2^63")
        if isinstance(value, Tag):
            if not (depth == 0 and top_tag and value.number == 18):
                raise _NotTheForm("a CBOR tag other than the outer tag 18")
            walk(value.value, depth + 1)
        elif isinstance(value, list):
            for item in value:
                walk(item, depth + 1)
        elif isinstance(value, dict):
            for key, item in value.items():
                if not (_int(key) or isinstance(key, str)):
                    raise _NotTheForm("a map key that is not an integer or a text string")
                walk(key, depth + 1)
                walk(item, depth + 1)

    walk(decoded.value, 0)
    return decoded.value


def _int(value: Any) -> bool:
    return type(value) is int


def _anchor_path_length(size: int, index: int) -> int:
    count = 0
    while size > 1:
        k = 1 << ((size - 1).bit_length() - 1)
        size, index = (k, index) if index < k else (size - k, index - k)
        count += 1
    return count


def _anchor_root(entry: bytes, index: int, size: int, path: list[bytes]) -> bytes:
    """The RFC 9162 §2.1.3.2 root from leaf ``entry`` up ``path`` (outermost sibling last)."""
    siblings = list(path)

    def fold(n: int, m: int) -> bytes:
        if n == 1:
            return hashlib.sha256(b"\x00" + entry).digest()
        k = 1 << ((n - 1).bit_length() - 1)
        sibling = siblings.pop()
        if m < k:
            return hashlib.sha256(b"\x01" + fold(k, m) + sibling).digest()
        return hashlib.sha256(b"\x01" + sibling + fold(n - k, m - k)).digest()

    return fold(size, index)


def _anchor_parse(octets: Any) -> tuple[int, bytes, list[tuple[int, int, list[bytes]]], bytes, int | None]:
    """Step 1 of §6.2.2: ``(alg, protected, proofs, signature, registration_time)`` of a Receipt
    in the one form, or :class:`_NotTheForm`."""
    from .interop_profile._cbor import Tag

    if not isinstance(octets, (bytes, bytearray)) or not 0 < len(octets) <= _MAX_RECEIPT_OCTETS:
        raise _NotTheForm("not 1 to 10,485,760 octets")
    outer = _strict(bytes(octets), top_tag=True)
    if not isinstance(outer, Tag) or outer.number != 18 or not isinstance(outer.value, list) \
            or len(outer.value) != 4:
        raise _NotTheForm("not a tag-18 COSE_Sign1")
    protected, unprotected, payload, signature = outer.value
    if not isinstance(protected, bytes) or not protected or payload is not None:
        raise _NotTheForm("no protected header, or an attached payload")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise _NotTheForm("the signature is not 64 octets")
    headers = _strict(protected)
    if not isinstance(headers, dict):
        raise _NotTheForm("the protected header is not a map")
    for label, value in headers.items():
        known = {1: lambda v: v in (_ALG_EDDSA, _ALG_ES256), 395: lambda v: v == 1,
                 4: lambda v: isinstance(v, bytes), 15: lambda v: isinstance(v, dict)}
        if _int(label) and label in known:
            if not (_int(value) or label in (4, 15)) or not known[label](value):
                raise _NotTheForm(f"protected label {label} has the wrong value")
        elif not (_int(label) and label < _PRIVATE_LABEL):
            raise _NotTheForm(f"protected label {label!r} is not allowed")
    if 1 not in headers or 395 not in headers:
        raise _NotTheForm("the protected header lacks alg or vds")
    if not isinstance(unprotected, dict) or list(unprotected) != [396]:
        raise _NotTheForm("the unprotected header is not exactly vdp")
    vdp = unprotected[396]
    if not isinstance(vdp, dict) or list(vdp) != [-1]:
        raise _NotTheForm("vdp is not exactly the inclusion proofs (-1)")
    raw_proofs = vdp[-1]
    if not isinstance(raw_proofs, list) or not 1 <= len(raw_proofs) <= _MAX_PROOFS:
        raise _NotTheForm("not one to 16 inclusion proofs")
    proofs = []
    for raw in raw_proofs:
        proof = _strict(raw) if isinstance(raw, bytes) else None
        if not isinstance(proof, list) or len(proof) != 3:
            raise _NotTheForm("an inclusion proof is not [tree_size, leaf_index, inclusion_path]")
        size, index, path = proof
        if not (_int(size) and _int(index)) or not 0 <= index < size <= _MAX_TREE_SIZE:
            raise _NotTheForm("an inclusion proof's tree_size or leaf_index is out of range")
        if not isinstance(path, list) or len(path) != _anchor_path_length(size, index) or not all(
                isinstance(node, bytes) and len(node) == 32 for node in path):
            raise _NotTheForm("an inclusion path does not fit its tree_size and leaf_index")
        proofs.append((size, index, path))
    iat = headers.get(15, {}).get(6)
    time = iat if _int(iat) and 0 <= iat <= _MAX_IAT else None
    return headers[1], protected, proofs, signature, time


def _anchor_sig_structure(protected: bytes, root: bytes) -> bytes:
    """The ``Signature1`` Sig_structure with an empty external AAD (RFC 9052 §4.4)."""
    from .interop_profile._cbor import encode_head

    out = encode_head(4, 4) + encode_head(3, 10) + b"Signature1"
    for part in (protected, b"", root):
        out += encode_head(2, len(part)) + part
    return out


def _anchor_verify(alg: int, spki: bytes, signature: bytes, message: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature

    from ._ed25519_strict import verify_strict

    if alg == _ALG_EDDSA:
        return verify_strict(spki[-32:], message, signature)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), spki[-65:])
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        key.verify(der, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True


def check_anchor_receipt(anchor_digest: str, octets: bytes, policy: Any) -> AnchorReceiptReport:
    """Steps 1 to 5 of §6.2.2 for one Receipt over the anchor whose digest is ``anchor_digest``
    (64 lowercase hex characters), under the relying party's witness ``policy``. Needs
    ``cryptography``; without it a Receipt in the form is ``NOT_CHECKED``."""
    if not isinstance(anchor_digest, str) or not _ANCHOR_DIGEST.fullmatch(anchor_digest):
        return AnchorReceiptReport(_FAIL, detail="the anchor digest is not 64 lowercase hex characters")
    try:
        alg, protected, proofs, signature, time = _anchor_parse(octets)
    except _NotTheForm as exc:
        return AnchorReceiptReport(_FAIL, detail=str(exc))
    wanted = "ed25519" if alg == _ALG_EDDSA else "p256"
    keys = [(name, spki) for name, spki in _anchor_policy_keys(policy) if _anchor_key_type(spki) == wanted]
    if not keys:
        return AnchorReceiptReport(_NOT_CHECKED, detail=f"the witness policy lists no {wanted} key")
    entry = bytes.fromhex(anchor_digest)
    roots = [_anchor_root(entry, index, size, path) for size, index, path in proofs]
    try:
        for name, spki in keys:
            for root in roots:
                if _anchor_verify(alg, spki, signature, _anchor_sig_structure(protected, root)):
                    return AnchorReceiptReport(_PASS, witness=name, registration_time=time)
    except ImportError:
        return AnchorReceiptReport(_NOT_CHECKED, detail="the cryptography package is not installed")
    return AnchorReceiptReport(_FAIL, detail="no accepted witness key verifies the Receipt over this anchor")


def check_anchor_witnessed(anchor_digest: str, receipts: Sequence[bytes] | None, policy: Any) -> AnchorWitnessReport:
    """``anchor_witnessed`` over ``receipts`` (each the octets of a ``cll-witness-receipt``, in the
    order received) for the anchor ``anchor_digest``, under the relying party's witness
    ``policy`` (§6.2.2)."""
    method = _METHOD
    reports = tuple(check_anchor_receipt(anchor_digest, octets, policy) for octets in receipts or ())
    statuses = {r.status for r in reports}
    if not reports:
        status = _NOT_PRESENT
    elif _PASS in statuses:
        status = _PASS
    elif _FAIL in statuses:
        status = _FAIL
    else:
        status = _NOT_CHECKED
    passed = [r for r in reports if r.status == _PASS]
    timed = [r for r in passed if r.registration_time is not None]
    # min keeps the first of equal times; with no time, the first passing Receipt names the witness.
    chosen = min(timed, key=lambda r: r.registration_time) if timed else (passed[0] if passed else None)
    return AnchorWitnessReport(
        status=status,
        method=method,
        receipts=reports,
        witness=chosen.witness if chosen else None,
        witnessed_time=chosen.registration_time if chosen else None,
    )
