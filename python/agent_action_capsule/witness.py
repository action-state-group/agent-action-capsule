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
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "BINDING_CLL",
    "BINDING_REKOR",
    "BINDING_SCRAPI",
    "GRADE_MMR_VERIFIED",
    "GRADE_OBSERVED_ONLY",
    "WitnessReceiptResult",
    "binding_of",
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

# The CLL checkpoint fields its signing body covers, besides ``v``/``kind``.
_SIGNED_FIELDS = ("log_id", "mmr_size", "root", "prev_size", "prev_root", "key_id", "timestamp")
_RECORD_FIELDS = ("ts_url", "entry_hash", "receipt_b64", "leaf_index", "tree_size")


@dataclass(frozen=True)
class WitnessReceiptResult:
    """One receipt's outcome: ``status`` is ``pass``, ``withheld`` or ``fail``.

    ``reason`` is a human-readable explanation and is not part of the
    cross-language contract; ``grade`` is the verified receipt grade, or
    ``None``.
    """

    ts_url: str
    binding: str
    status: str
    reason: str
    grade: str | None = None


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


def _der(b64: Any) -> bytes | None:
    try:
        return base64.b64decode(b64, validate=True) if isinstance(b64, str) else None
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
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

    by_id: dict[str, bytes] = {}
    for b64 in row.get("public_keys", []) or []:
        der = _der(b64)
        if der is not None:
            by_id[hashlib.sha256(der).hexdigest()] = der
            raw = _raw_ed25519(der)
            if raw is not None:
                by_id[raw] = der
    pems = []
    for key_id in row.get("key_ids", []) or []:
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


def _receipt_shape_error(receipt: bytes) -> str | None:
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
    if not isinstance(protected, dict) or protected.get(395) != 1:
        return "receipt vds is not RFC9162_SHA256 (1)"
    if protected.get(1) not in (-8, -7):
        return "receipt alg is not EdDSA (-8) or ES256 (-7)"
    return None


def _grade(result: Any) -> str | None:
    label = (getattr(result, "protected_header_ext", None) or {}).get(_GRADE_LABEL)
    return _GRADES.get(label) if isinstance(label, str) else None


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
        receipt = base64.b64decode(record["receipt_b64"], validate=True)
    except Exception as exc:  # noqa: BLE001
        return False, f"receipt_b64 is not valid base64: {exc}", None
    try:
        from scitt_cose import verify_receipt
    except ImportError:
        return False, "scitt-cose is not installed; run: pip install 'agent-action-capsule[envelope]'", None
    shape = _receipt_shape_error(receipt)
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
            rekor_key.verify(base64.b64decode(set_b64, validate=True), signed, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False, "signedEntryTimestamp does not verify under the pinned Rekor key"
        entry = json.loads(base64.b64decode(receipt["body"], validate=True))
        if entry.get("kind") != "dsse":
            return False, f"entry kind {entry.get('kind')!r}, expected 'dsse'"
        spec = entry.get("spec") or {}
        if (spec.get("payloadHash") or {}).get("value") != hashlib.sha256(cose).hexdigest():
            return False, "entry payloadHash is not this checkpoint's bytes"
        verifiers = {
            base64.b64decode(s.get("verifier", ""), validate=True).replace(b"\r", b"").strip()
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
    shape = _receipt_shape_error(receipt)
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
            receipt = json.loads(base64.b64decode(record["receipt_b64"], validate=True))
        except (ValueError, TypeError) as exc:
            return False, f"unreadable receipt: {exc}", None
        ok, reason = verify_rekor_receipt(
            receipt, checkpoint_cose=cose, checkpoint_key_id=signed["key_id"], rekor_public_key_pem=pem
        )
        return ok, reason, GRADE_OBSERVED_ONLY if ok else None
    try:
        receipt_bytes = base64.b64decode(record["receipt_b64"], validate=True)
    except (ValueError, TypeError) as exc:
        return False, f"unreadable receipt: {exc}", None
    return verify_scrapi_receipt(receipt_bytes, checkpoint_cose=cose, service_public_key_pem=pem)


def _is_record(entry: Any) -> bool:
    return isinstance(entry, Mapping) and isinstance(entry.get("ts_url"), str) and all(k in entry for k in _RECORD_FIELDS)


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
        ok, reason, grade = False, "", None
        if record.get("is_stub") is True:
            reason = "stub receipt (never reached a witness)"
        elif row is None:
            reason = "not checked: no directory row for this witness"
        else:
            try:
                pems = row_public_keys_pem(row)
            except Exception as exc:  # noqa: BLE001 -- an unusable row key is "not checked"
                pems, reason = [], f"not checked: unusable key in directory row ({exc})"
            for pem in pems:
                ok, reason, grade = verify_receipt(signed, record, pem, checkpoint_cose)
                if ok:
                    break
        if ok:
            status = "pass"
        elif not reason or reason.startswith(("not checked", "stub receipt")):
            status = "withheld"
            reason = reason or "not checked: no key in the directory row for this witness"
            findings.append(f"witness_unverified:{ts_url}")
        else:
            status = "fail"
            findings.append(f"witness_receipt_invalid:{ts_url}")
        results.append(WitnessReceiptResult(ts_url, binding_of(ts_url), status, reason, grade if ok else None))
    statuses = {r.status for r in results}
    if malformed or "fail" in statuses:
        overall = "fail"
    elif "pass" in statuses:
        overall = "pass"
    else:
        overall = "withheld"
    return overall, tuple(findings), tuple(results)
