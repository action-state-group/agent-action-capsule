# SPDX-License-Identifier: BSD-3-Clause
"""PermitReceipt + MachineMandate composition verifier.

Implements the fail-closed gate checks defined in
``docs/interop/aac-permitreceipt-mandate-binding-profile.md``.

Each companion document is bound via a typed reference in the capsule's
``effect.authorization`` payload extension — NOT via ``effect.request_digest``
or ``effect.response_digest``, which retain their -02 semantics (actual
protected-action request / actual observed response).

    ``verify_permitreceipt_mandate(capsule, permit_receipt, machine_mandate)``

Returns a result dict with:

    ok    : bool  — True iff ALL gates pass
    gates : list of {name, passed, reason}

Both companion documents are resolved by the caller and passed directly.
This function never raises on bad input — all failure modes produce ok=False
with a descriptive reason.  A gate failure means zero external-effect commits
may proceed; the capsule itself may still be signed and registered as audit
evidence.
"""
from __future__ import annotations

from .canonical import json_digest

__all__ = ["verify_permitreceipt_mandate"]

_REQUIRED_REF_FIELDS = ("type", "digest_alg", "digest")


def _gate(name: str, passed: bool, reason: str) -> dict:
    return {"name": name, "passed": passed, "reason": reason}


def _check_typed_reference(
    ref: object,
    expected_type: str,
    companion: dict,
    gate_name: str,
) -> dict:
    """Appraise one typed authorization reference against its companion doc.

    Checks (in order):
    1. Reference is a JSON object.
    2. Required fields present: ``type``, ``digest_alg``, ``digest``.
    3. ``type`` matches expected_type.
    4. ``digest`` is a 64-char hex string.
    5. ``digest`` == SHA-256(JCS(companion)).
    """
    if not isinstance(ref, dict):
        return _gate(gate_name, False, "authorization reference is not an object")

    for field in _REQUIRED_REF_FIELDS:
        if field not in ref:
            return _gate(gate_name, False, f"authorization reference missing required field: {field!r}")

    if ref.get("type") != expected_type:
        return _gate(
            gate_name,
            False,
            f"type mismatch: expected {expected_type!r}, got {ref.get('type')!r}",
        )

    digest_in_ref = ref.get("digest")
    if not isinstance(digest_in_ref, str) or len(digest_in_ref) != 64:
        return _gate(gate_name, False, "reference.digest is missing or not a 64-char hex string")

    try:
        expected_digest = json_digest(companion)
    except Exception as exc:  # noqa: BLE001
        return _gate(gate_name, False, f"failed to canonicalize companion document: {exc}")

    if digest_in_ref == expected_digest:
        return _gate(
            gate_name,
            True,
            f"reference.digest matches SHA-256(JCS({expected_type}))",
        )
    return _gate(
        gate_name,
        False,
        f"digest mismatch: reference has {digest_in_ref!r}, computed {expected_digest!r}",
    )


def verify_permitreceipt_mandate(
    capsule: dict,
    permit_receipt: dict,
    machine_mandate: dict,
) -> dict:
    """Verify that *capsule* cryptographically binds *permit_receipt* and
    *machine_mandate* via ``effect.authorization`` typed references.

    Parameters
    ----------
    capsule:
        The AAC capsule dict (parsed JSON).  The binding is in
        ``capsule.effect.authorization.permit_receipt_digest`` (typed reference
        to PermitReceipt) and ``capsule.effect.authorization.machine_mandate_digest``
        (typed reference to MachineMandate).
    permit_receipt:
        The PermitReceipt companion document (parsed JSON).
    machine_mandate:
        The MachineMandate companion document (parsed JSON).

    Returns
    -------
    dict with keys ``ok`` (bool) and ``gates`` (list of gate result dicts).
    ``ok`` is True only when ALL gates pass.

    Gate failure semantics (per Scott Lee's correction):
    "no effect-commit marker" means zero external-effect commits may proceed;
    a failed capsule MAY still be signed and registered as audit evidence.
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
            "machine_mandate_bound", False,
            "effect.authorization is missing or not an object",
        ))
        return {"ok": False, "gates": gates}

    # Gate 1 — permit_receipt_bound
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

    # Gate 2 — machine_mandate_bound
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

    ok = all(g["passed"] for g in gates)
    return {"ok": ok, "gates": gates}
