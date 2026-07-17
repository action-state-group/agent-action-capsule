# SPDX-License-Identifier: BSD-3-Clause
"""Binding-only verifier for the PermitReceipt + MachineMandate profile-defined
payload extension.

This module verifies **cryptographic binding only** — it confirms that the
typed references in ``effect.authorization`` commit to the expected companion
documents.  It does NOT perform owner appraisal of those documents.

Callers MUST supply the result of each artifact's owner appraisal as a separate
mandatory input (``permit_receipt_appraised``, ``machine_mandate_appraised``).
A positive digest-match without a corresponding appraisal MUST NOT be read as
authorization success.

See ``docs/interop/aac-permitreceipt-mandate-binding-profile.md`` for the full
profile definition including gate semantics and preimage specification.

    ``verify_permitreceipt_mandate(
        capsule,
        permit_receipt,
        machine_mandate,
        *,
        permit_receipt_appraised,
        machine_mandate_appraised,
    )``

Returns a result dict:

    bindings_ok          : bool  — True iff ALL four gates pass
    gates                : list of {name, passed, reason}

Gate names (evaluated independently):
    permit_receipt_bound      — digest binding check
    permit_receipt_appraised  — owner-appraisal result (caller-supplied)
    machine_mandate_bound     — digest binding check
    machine_mandate_appraised — owner-appraisal result (caller-supplied)

Gate failure semantics: "no effect-commit marker" means zero external-effect
commits may proceed.  A capsule whose gates fail MAY still be signed and
registered as audit evidence.

Preimage conventions (profile-defined):
    PREIMAGE_JSON_JCS       — SHA-256(JCS(normalize(companion_dict)))
    PREIMAGE_JWS_ISSUER     — SHA-256(exact issuer-signed JWS component bytes)
"""
from __future__ import annotations

import hashlib

from .canonical import json_digest

__all__ = [
    "verify_permitreceipt_mandate",
    "PREIMAGE_JSON_JCS",
    "PREIMAGE_JWS_ISSUER",
]

PREIMAGE_JSON_JCS = "json/jcs"
PREIMAGE_JWS_ISSUER = "jws/issuer-signed"

_REQUIRED_REF_FIELDS = ("type", "digest_alg", "digest")


def _gate(name: str, passed: bool, reason: str) -> dict:
    return {"name": name, "passed": passed, "reason": reason}


def _compute_ref_digest(companion: dict | bytes, preimage: str | None) -> str:
    """Compute the expected digest for a companion document.

    ``preimage`` selects the preimage convention:
    - ``PREIMAGE_JSON_JCS`` (default for dict companions): SHA-256(JCS(normalize(companion)))
    - ``PREIMAGE_JWS_ISSUER`` (for SD-JWT companions supplied as bytes):
      SHA-256(exact issuer-signed JWS component bytes)
    """
    if isinstance(companion, (bytes, bytearray)):
        if preimage is None:
            preimage = PREIMAGE_JWS_ISSUER
        if preimage != PREIMAGE_JWS_ISSUER:
            raise ValueError(
                f"bytes companion requires preimage={PREIMAGE_JWS_ISSUER!r}; got {preimage!r}"
            )
        return hashlib.sha256(companion).hexdigest()
    # dict companion
    if preimage is None:
        preimage = PREIMAGE_JSON_JCS
    if preimage != PREIMAGE_JSON_JCS:
        raise ValueError(
            f"dict companion requires preimage={PREIMAGE_JSON_JCS!r}; got {preimage!r}"
        )
    return json_digest(companion)


def _check_typed_reference(
    ref: object,
    expected_type: str,
    companion: dict | bytes,
    gate_name: str,
) -> dict:
    """Appraise one typed authorization reference against its companion document.

    Checks (in order):
    1. Reference is a JSON object.
    2. Required fields present: ``type``, ``digest_alg``, ``digest``.
    3. ``type`` matches expected_type.
    4. ``digest`` is a 64-char hex string matching ``^[0-9a-f]{64}$``.
    5. ``digest`` == digest computed from companion using the declared preimage.
    """
    if not isinstance(ref, dict):
        return _gate(gate_name, False, "authorization reference is not an object")

    for field in _REQUIRED_REF_FIELDS:
        if field not in ref:
            return _gate(gate_name, False, f"authorization reference missing required field: {field!r}")

    if ref.get("type") != expected_type:
        return _gate(
            gate_name, False,
            f"type mismatch: expected {expected_type!r}, got {ref.get('type')!r}",
        )

    digest_in_ref = ref.get("digest")
    if not isinstance(digest_in_ref, str) or len(digest_in_ref) != 64 or not all(
        c in "0123456789abcdef" for c in digest_in_ref
    ):
        return _gate(gate_name, False, "reference.digest must be a 64-char lowercase hex string")

    preimage = ref.get("preimage")
    try:
        expected_digest = _compute_ref_digest(companion, preimage)
    except Exception as exc:  # noqa: BLE001
        return _gate(gate_name, False, f"failed to compute companion digest: {exc}")

    if digest_in_ref == expected_digest:
        return _gate(gate_name, True, f"reference.digest matches {preimage or 'default preimage'}({expected_type})")
    return _gate(
        gate_name, False,
        f"digest mismatch: reference has {digest_in_ref!r}, computed {expected_digest!r}",
    )


def verify_permitreceipt_mandate(
    capsule: dict,
    permit_receipt: dict | bytes,
    machine_mandate: dict | bytes,
    *,
    permit_receipt_appraised: bool | None,
    machine_mandate_appraised: bool | None,
) -> dict:
    """Binding-only verifier for the PermitReceipt + MachineMandate extension.

    Verifies cryptographic binding via ``effect.authorization`` typed references
    AND incorporates owner-appraisal results as mandatory gate inputs.

    Parameters
    ----------
    capsule:
        The AAC capsule dict.  Authorization references live in
        ``capsule.effect.authorization.permit_receipt_digest`` and
        ``capsule.effect.authorization.machine_mandate_digest``.
    permit_receipt:
        The PermitReceipt companion document — either a parsed JSON dict
        (preimage: json/jcs) or raw issuer-signed JWS bytes (preimage:
        jws/issuer-signed).
    machine_mandate:
        The MachineMandate companion document — either a dict or bytes.
    permit_receipt_appraised:
        True if the owner verifier accepted the PermitReceipt; False if
        rejected; None if the appraisal was not performed (gate fails).
    machine_mandate_appraised:
        True if the owner verifier accepted the MachineMandate; False if
        rejected; None if the appraisal was not performed (gate fails).

    Returns
    -------
    dict with keys ``bindings_ok`` (bool) and ``gates`` (list of gate result
    dicts).  ``bindings_ok`` is True only when ALL four gates pass.
    A digest match without a True appraisal is NOT authorization success.
    """
    gates: list[dict] = []

    effect = capsule.get("effect") if isinstance(capsule, dict) else None
    authorization = effect.get("authorization") if isinstance(effect, dict) else None

    if not isinstance(authorization, dict):
        gates.append(_gate(
            "permit_receipt_bound", False,
            "effect.authorization is missing or not an object",
        ))
        gates.append(_gate(
            "permit_receipt_appraised", False,
            "effect.authorization is missing — appraisal not applicable",
        ))
        gates.append(_gate(
            "machine_mandate_bound", False,
            "effect.authorization is missing or not an object",
        ))
        gates.append(_gate(
            "machine_mandate_appraised", False,
            "effect.authorization is missing — appraisal not applicable",
        ))
        return {"bindings_ok": False, "gates": gates}

    # Gate 1 — permit_receipt_bound (digest binding)
    permit_ref = authorization.get("permit_receipt_digest")
    if permit_ref is None:
        gates.append(_gate(
            "permit_receipt_bound", False,
            "effect.authorization.permit_receipt_digest is missing",
        ))
    else:
        gates.append(_check_typed_reference(
            permit_ref, "PermitReceipt", permit_receipt, "permit_receipt_bound",
        ))

    # Gate 2 — permit_receipt_appraised (owner appraisal, caller-supplied)
    if permit_receipt_appraised is True:
        gates.append(_gate("permit_receipt_appraised", True, "owner verifier accepted PermitReceipt"))
    elif permit_receipt_appraised is False:
        gates.append(_gate("permit_receipt_appraised", False, "owner verifier rejected PermitReceipt"))
    else:
        gates.append(_gate(
            "permit_receipt_appraised", False,
            "owner appraisal result not provided — caller must supply the result of the owner verifier",
        ))

    # Gate 3 — machine_mandate_bound (digest binding)
    mandate_ref = authorization.get("machine_mandate_digest")
    if mandate_ref is None:
        gates.append(_gate(
            "machine_mandate_bound", False,
            "effect.authorization.machine_mandate_digest is missing",
        ))
    else:
        gates.append(_check_typed_reference(
            mandate_ref, "MachineMandate", machine_mandate, "machine_mandate_bound",
        ))

    # Gate 4 — machine_mandate_appraised (owner appraisal, caller-supplied)
    if machine_mandate_appraised is True:
        gates.append(_gate("machine_mandate_appraised", True, "owner verifier accepted MachineMandate"))
    elif machine_mandate_appraised is False:
        gates.append(_gate("machine_mandate_appraised", False, "owner verifier rejected MachineMandate"))
    else:
        gates.append(_gate(
            "machine_mandate_appraised", False,
            "owner appraisal result not provided — caller must supply the result of the owner verifier",
        ))

    bindings_ok = all(g["passed"] for g in gates)
    return {"bindings_ok": bindings_ok, "gates": gates}
