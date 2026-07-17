# SPDX-License-Identifier: BSD-3-Clause
"""Tests for the PermitReceipt + MachineMandate binding profile.

Binding location (v2): ``effect.authorization`` namespaced payload extension,
NOT ``effect.request_digest`` / ``effect.response_digest`` (those retain -02
semantics: actual protected-action request / actual observed response).

NOTE: this profile is OWNER-PROPOSED — REVIEW PENDING — NOT AGREED — NOT A RESULT.

Illustrative composition paths (subject to revision):
  - PermitReceipt.requested.amount = 425000 (EUR minor units = €4,250.00)
  - MachineMandate.scope.max_spend   = 500000 (EUR minor units = €5,000.00)

Covers:
  - Round-trip: effect.authorization enters capsule_id JCS preimage.
  - Positive case: correct typed references → ok=True, both gates pass.
  - Missing effect.authorization → both gates fail.
  - Missing permit_receipt_digest reference → permit_receipt_bound fails.
  - Missing machine_mandate_digest reference → machine_mandate_bound fails.
  - Wrong companion document → digest mismatch, named gate fails.
  - Malformed reference (missing required field) → named gate fails.
"""
from __future__ import annotations

import copy

from agent_action_capsule.canonical import compute_capsule_id, json_digest
from agent_action_capsule.contracts import EffectRecord
from agent_action_capsule.emit import emit
from agent_action_capsule.verify_composition import verify_permitreceipt_mandate

# ---------------------------------------------------------------------------
# Illustrative companion documents (subject to revision — profile not yet agreed)
# ---------------------------------------------------------------------------

PERMIT_RECEIPT: dict = {
    "type": "PermitReceipt",
    "version": "1",
    "permit_id": "permit-2026-0716-001",
    "issued_at": "2026-07-16T00:00:00Z",
    "issuer": "example-permit-authority",
    "requested": {
        "currency": "EUR",
        "amount": 425000,
        "description": "Payment approved for INV-2026-0716 — server infrastructure renewal",
    },
}

MACHINE_MANDATE: dict = {
    "type": "MachineMandate",
    "version": "1",
    "mandate_id": "mandate-2026-0716-001",
    "issued_at": "2026-07-16T00:00:00Z",
    "issuer": "example-aep-authority",
    "scope": {
        "currency": "EUR",
        "max_spend": 500000,
        "description": "Delegated payment authority for server infrastructure renewal",
    },
}


# ---------------------------------------------------------------------------
# Helper: build a typed authorization reference
# ---------------------------------------------------------------------------

def _typed_ref(artifact: dict, artifact_type: str) -> dict:
    return {
        "type": artifact_type,
        "digest_alg": "SHA-256",
        "digest": json_digest(artifact),
    }


# ---------------------------------------------------------------------------
# Helper: mint a capsule with an effect.authorization extension
# ---------------------------------------------------------------------------

def _mint_capsule(
    permit_receipt: dict | None = None,
    machine_mandate: dict | None = None,
) -> dict:
    """Emit a base capsule and inject effect.authorization typed references.

    The authorization extension is added to the effect sub-object BEFORE
    capsule_id is computed, so both references enter the JCS preimage.
    """
    # Base capsule with a dispatched effect (no -02 request/response digests needed).
    base = emit(
        action_type="decide",
        operator="asg-test",
        developer="test-agent@v1",
        effect=EffectRecord(status="dispatched", type="payment"),
    )

    authorization: dict = {}
    if permit_receipt is not None:
        authorization["permit_receipt_digest"] = _typed_ref(permit_receipt, "PermitReceipt")
    if machine_mandate is not None:
        authorization["machine_mandate_digest"] = _typed_ref(machine_mandate, "MachineMandate")

    if not authorization:
        return base

    # Inject the authorization extension into the effect sub-object.
    effect = dict(base["effect"])
    effect["authorization"] = authorization

    capsule = dict(base)
    capsule["effect"] = effect
    # Recompute capsule_id — effect.authorization is now inside the JCS preimage.
    capsule["capsule_id"] = compute_capsule_id(capsule)
    return capsule


# ---------------------------------------------------------------------------
# Round-trip / preimage test
# ---------------------------------------------------------------------------

def test_authorization_enters_capsule_id_preimage():
    """effect.authorization must be inside the capsule_id JCS preimage.

    Verifies that:
    1. capsule_id == SHA-256(JCS(capsule \\ {capsule_id, chain})) — the
       authorization extension is committed to.
    2. Tampering with the authorization digest produces a different capsule_id.
    """
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)

    # Recompute capsule_id independently and confirm it matches.
    assert compute_capsule_id(capsule) == capsule["capsule_id"], (
        "capsule_id does not match the recomputed digest — authorization may not be in preimage"
    )

    # Tamper with the authorization digest and confirm capsule_id changes.
    tampered = copy.deepcopy(capsule)
    tampered["effect"]["authorization"]["permit_receipt_digest"]["digest"] = "a" * 64
    assert compute_capsule_id(tampered) != capsule["capsule_id"], (
        "tampering with effect.authorization did not change capsule_id — preimage not covered"
    )


# ---------------------------------------------------------------------------
# Positive case
# ---------------------------------------------------------------------------

def test_positive_both_correct():
    """Correct typed references → ok=True, both gates pass."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)
    result = verify_permitreceipt_mandate(capsule, PERMIT_RECEIPT, MACHINE_MANDATE)

    assert result["ok"] is True
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is True
    assert gate_names["machine_mandate_bound"]["passed"] is True


# ---------------------------------------------------------------------------
# Missing effect.authorization
# ---------------------------------------------------------------------------

def test_missing_authorization_block():
    """Missing effect.authorization → both gates fail."""
    base = emit(
        action_type="decide",
        operator="asg-test",
        developer="test-agent@v1",
        effect=EffectRecord(status="dispatched", type="payment"),
    )
    result = verify_permitreceipt_mandate(base, PERMIT_RECEIPT, MACHINE_MANDATE)

    assert result["ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is False
    assert gate_names["machine_mandate_bound"]["passed"] is False


# ---------------------------------------------------------------------------
# Missing permit_receipt_digest reference
# ---------------------------------------------------------------------------

def test_missing_permit_receipt_reference():
    """Missing permit_receipt_digest → permit_receipt_bound fails; machine_mandate_bound passes."""
    capsule = _mint_capsule(machine_mandate=MACHINE_MANDATE)
    # Only machine_mandate_digest is in the authorization block.
    assert "permit_receipt_digest" not in capsule.get("effect", {}).get("authorization", {})

    result = verify_permitreceipt_mandate(capsule, PERMIT_RECEIPT, MACHINE_MANDATE)

    assert result["ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is False
    assert "missing" in gate_names["permit_receipt_bound"]["reason"].lower()
    assert gate_names["machine_mandate_bound"]["passed"] is True


# ---------------------------------------------------------------------------
# Missing machine_mandate_digest reference
# ---------------------------------------------------------------------------

def test_missing_machine_mandate_reference():
    """Missing machine_mandate_digest → machine_mandate_bound fails; permit_receipt_bound passes."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT)
    assert "machine_mandate_digest" not in capsule.get("effect", {}).get("authorization", {})

    result = verify_permitreceipt_mandate(capsule, PERMIT_RECEIPT, MACHINE_MANDATE)

    assert result["ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["machine_mandate_bound"]["passed"] is False
    assert "missing" in gate_names["machine_mandate_bound"]["reason"].lower()
    assert gate_names["permit_receipt_bound"]["passed"] is True


# ---------------------------------------------------------------------------
# Wrong companion document (digest mismatch)
# ---------------------------------------------------------------------------

def test_mismatched_permit_receipt():
    """Wrong PermitReceipt doc → permit_receipt_bound fails; machine_mandate_bound passes."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)

    wrong_permit = copy.deepcopy(PERMIT_RECEIPT)
    wrong_permit["requested"]["amount"] = 999999  # tampered

    result = verify_permitreceipt_mandate(capsule, wrong_permit, MACHINE_MANDATE)

    assert result["ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is False
    assert "mismatch" in gate_names["permit_receipt_bound"]["reason"].lower()
    assert gate_names["machine_mandate_bound"]["passed"] is True


def test_mismatched_machine_mandate():
    """Wrong MachineMandate doc → machine_mandate_bound fails; permit_receipt_bound passes."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)

    wrong_mandate = copy.deepcopy(MACHINE_MANDATE)
    wrong_mandate["scope"]["max_spend"] = 100000  # tampered

    result = verify_permitreceipt_mandate(capsule, PERMIT_RECEIPT, wrong_mandate)

    assert result["ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["machine_mandate_bound"]["passed"] is False
    assert "mismatch" in gate_names["machine_mandate_bound"]["reason"].lower()
    assert gate_names["permit_receipt_bound"]["passed"] is True


# ---------------------------------------------------------------------------
# Malformed reference (missing required field)
# ---------------------------------------------------------------------------

def test_malformed_reference_missing_type():
    """Reference missing 'type' field → named gate fails."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)

    # Strip the 'type' field from the permit reference.
    tampered = copy.deepcopy(capsule)
    del tampered["effect"]["authorization"]["permit_receipt_digest"]["type"]
    tampered["capsule_id"] = compute_capsule_id(tampered)

    result = verify_permitreceipt_mandate(tampered, PERMIT_RECEIPT, MACHINE_MANDATE)

    assert result["ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is False
    assert gate_names["machine_mandate_bound"]["passed"] is True
