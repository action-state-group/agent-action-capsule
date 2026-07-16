# SPDX-License-Identifier: BSD-3-Clause
"""PermitReceipt + MachineMandate composition verifier.

Implements the fail-closed gate checks defined in
``docs/interop/aac-permitreceipt-mandate-binding-profile.md``.

    ``verify_permitreceipt_mandate(capsule, permit_receipt, machine_mandate)``

Returns a result dict with:

    ok    : bool  — True iff ALL gates pass
    gates : list of {name, passed, reason}

Both companion documents are resolved by the caller and passed directly;
this function only performs digest verification.  It never raises on bad
input — all failure modes produce ok=False with a descriptive reason.
"""
from __future__ import annotations

from .canonical import json_digest

__all__ = ["verify_permitreceipt_mandate"]


def _gate(name: str, passed: bool, reason: str) -> dict:
    return {"name": name, "passed": passed, "reason": reason}


def verify_permitreceipt_mandate(
    capsule: dict,
    permit_receipt: dict,
    machine_mandate: dict,
) -> dict:
    """Verify that *capsule* cryptographically binds *permit_receipt* and
    *machine_mandate* via its ``effect.request_digest`` and
    ``effect.response_digest`` fields.

    Parameters
    ----------
    capsule:
        The AAC capsule dict (parsed JSON).  ``effect.request_digest`` must be
        the SHA-256(JCS(permit_receipt)) and ``effect.response_digest`` must be
        the SHA-256(JCS(machine_mandate)).
    permit_receipt:
        The PermitReceipt companion document (parsed JSON).
    machine_mandate:
        The MachineMandate companion document (parsed JSON).

    Returns
    -------
    dict with keys ``ok`` (bool) and ``gates`` (list of gate result dicts).
    The result is fail-closed: ``ok`` is False if ANY gate fails.
    """
    gates: list[dict] = []

    # ------------------------------------------------------------------
    # Gate 1 — permit_receipt_bound
    # capsule.effect.request_digest must be present and must equal
    # SHA-256(JCS(normalize(permit_receipt))).
    # ------------------------------------------------------------------
    effect = capsule.get("effect") if isinstance(capsule, dict) else None
    request_digest_in_capsule: str | None = (
        effect.get("request_digest") if isinstance(effect, dict) else None
    )

    if not isinstance(request_digest_in_capsule, str) or len(request_digest_in_capsule) != 64:
        gates.append(
            _gate(
                "permit_receipt_bound",
                False,
                "effect.request_digest is missing or not a 64-char hex string",
            )
        )
    else:
        try:
            expected = json_digest(permit_receipt)
        except Exception as exc:  # noqa: BLE001
            gates.append(
                _gate(
                    "permit_receipt_bound",
                    False,
                    f"failed to canonicalize permit_receipt: {exc}",
                )
            )
        else:
            if request_digest_in_capsule == expected:
                gates.append(
                    _gate(
                        "permit_receipt_bound",
                        True,
                        "effect.request_digest matches SHA-256(JCS(permit_receipt))",
                    )
                )
            else:
                gates.append(
                    _gate(
                        "permit_receipt_bound",
                        False,
                        (
                            f"effect.request_digest mismatch: "
                            f"capsule has {request_digest_in_capsule!r}, "
                            f"computed {expected!r}"
                        ),
                    )
                )

    # ------------------------------------------------------------------
    # Gate 2 — machine_mandate_bound
    # capsule.effect.response_digest must be present and must equal
    # SHA-256(JCS(normalize(machine_mandate))).
    # ------------------------------------------------------------------
    response_digest_in_capsule: str | None = (
        effect.get("response_digest") if isinstance(effect, dict) else None
    )

    if not isinstance(response_digest_in_capsule, str) or len(response_digest_in_capsule) != 64:
        gates.append(
            _gate(
                "machine_mandate_bound",
                False,
                "effect.response_digest is missing or not a 64-char hex string",
            )
        )
    else:
        try:
            expected = json_digest(machine_mandate)
        except Exception as exc:  # noqa: BLE001
            gates.append(
                _gate(
                    "machine_mandate_bound",
                    False,
                    f"failed to canonicalize machine_mandate: {exc}",
                )
            )
        else:
            if response_digest_in_capsule == expected:
                gates.append(
                    _gate(
                        "machine_mandate_bound",
                        True,
                        "effect.response_digest matches SHA-256(JCS(machine_mandate))",
                    )
                )
            else:
                gates.append(
                    _gate(
                        "machine_mandate_bound",
                        False,
                        (
                            f"effect.response_digest mismatch: "
                            f"capsule has {response_digest_in_capsule!r}, "
                            f"computed {expected!r}"
                        ),
                    )
                )

    ok = all(g["passed"] for g in gates)
    return {"ok": ok, "gates": gates}
