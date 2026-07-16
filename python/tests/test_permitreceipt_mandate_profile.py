# SPDX-License-Identifier: BSD-3-Clause
"""Tests for the PermitReceipt + MachineMandate binding profile.

Covers:
  - Positive case: correct companion docs → ok=True, both gates pass.
  - Missing effect.request_digest → permit_receipt_bound gate fails.
  - Mismatched request_digest (wrong PermitReceipt) → permit_receipt_bound gate fails.
  - Missing effect.response_digest → machine_mandate_bound gate fails.
  - Mismatched response_digest (wrong MachineMandate) → machine_mandate_bound gate fails.

Uses the frozen composition paths from Anton's matrix v0.3 (2026-07-16):
  - PermitReceipt.requested.amount = 425000 (EUR minor units = €4,250.00)
  - MachineMandate.scope.max_spend   = 500000 (EUR minor units = €5,000.00)
"""
from __future__ import annotations

import copy

import pytest

from agent_action_capsule.canonical import json_digest
from agent_action_capsule.contracts import EffectRecord
from agent_action_capsule.emit import emit
from agent_action_capsule.verify_composition import verify_permitreceipt_mandate

# ---------------------------------------------------------------------------
# Frozen test documents (Anton matrix v0.3, 2026-07-16)
# ---------------------------------------------------------------------------

PERMIT_RECEIPT: dict = {
    "type": "PermitReceipt",
    "version": "1",
    "permit_id": "permit-2026-0716-001",
    "issued_at": "2026-07-16T00:00:00Z",
    "issuer": "scott-lee-permit-authority",
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
    "issuer": "anton-sokolov-aep-authority",
    "scope": {
        "currency": "EUR",
        "max_spend": 500000,
        "description": "Delegated payment authority for server infrastructure renewal",
    },
}


# ---------------------------------------------------------------------------
# Helper: mint a capsule with given request_digest / response_digest
# ---------------------------------------------------------------------------

def _mint_capsule(
    request_digest: str | None = None,
    response_digest: str | None = None,
) -> dict:
    """Emit a capsule whose effect block carries the given digests.

    When response_digest is absent we use status='dispatched'; when it is
    present we use status='confirmed' (which requires a well-formed response_digest).
    """
    if response_digest is not None:
        effect = EffectRecord(
            status="confirmed",
            type="payment",
            request_digest=request_digest,
            response_digest=response_digest,
        )
    elif request_digest is not None:
        effect = EffectRecord(
            status="dispatched",
            type="payment",
            request_digest=request_digest,
        )
    else:
        effect = EffectRecord(status="dispatched", type="payment")

    return emit(
        action_type="decide",
        operator="asg-test",
        developer="test-agent@v1",
        effect=effect,
    )


# ---------------------------------------------------------------------------
# Positive case
# ---------------------------------------------------------------------------

def test_positive_both_correct():
    """Correct PermitReceipt + MachineMandate → ok=True, both gates pass."""
    req_digest = json_digest(PERMIT_RECEIPT)
    resp_digest = json_digest(MACHINE_MANDATE)

    capsule = _mint_capsule(request_digest=req_digest, response_digest=resp_digest)
    result = verify_permitreceipt_mandate(capsule, PERMIT_RECEIPT, MACHINE_MANDATE)

    assert result["ok"] is True
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is True
    assert gate_names["machine_mandate_bound"]["passed"] is True


# ---------------------------------------------------------------------------
# Missing effect.request_digest
# ---------------------------------------------------------------------------

def test_missing_request_digest():
    """Missing effect.request_digest → permit_receipt_bound gate fails, ok=False."""
    resp_digest = json_digest(MACHINE_MANDATE)
    # Only response_digest is present; request_digest absent (dispatched not valid here;
    # use confirmed with just response_digest by manually patching the capsule).
    capsule = _mint_capsule(response_digest=resp_digest)
    # Confirm request_digest is not in the capsule effect
    assert capsule.get("effect", {}).get("request_digest") is None

    result = verify_permitreceipt_mandate(capsule, PERMIT_RECEIPT, MACHINE_MANDATE)

    assert result["ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is False
    assert "missing" in gate_names["permit_receipt_bound"]["reason"].lower()


# ---------------------------------------------------------------------------
# Mismatched request_digest (wrong PermitReceipt document)
# ---------------------------------------------------------------------------

def test_mismatched_request_digest():
    """Wrong PermitReceipt doc → permit_receipt_bound gate fails, ok=False."""
    wrong_permit = copy.deepcopy(PERMIT_RECEIPT)
    wrong_permit["requested"]["amount"] = 999999  # tampered amount

    # Capsule was minted against the original PERMIT_RECEIPT
    req_digest = json_digest(PERMIT_RECEIPT)
    resp_digest = json_digest(MACHINE_MANDATE)
    capsule = _mint_capsule(request_digest=req_digest, response_digest=resp_digest)

    # Verify against the wrong permit receipt
    result = verify_permitreceipt_mandate(capsule, wrong_permit, MACHINE_MANDATE)

    assert result["ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is False
    assert "mismatch" in gate_names["permit_receipt_bound"]["reason"].lower()
    # Machine mandate gate should still pass since response_digest is correct
    assert gate_names["machine_mandate_bound"]["passed"] is True


# ---------------------------------------------------------------------------
# Missing effect.response_digest
# ---------------------------------------------------------------------------

def test_missing_response_digest():
    """Missing effect.response_digest → machine_mandate_bound gate fails, ok=False."""
    req_digest = json_digest(PERMIT_RECEIPT)
    # Mint with dispatched status so no response_digest is present
    capsule = _mint_capsule(request_digest=req_digest)
    assert capsule.get("effect", {}).get("response_digest") is None

    result = verify_permitreceipt_mandate(capsule, PERMIT_RECEIPT, MACHINE_MANDATE)

    assert result["ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["machine_mandate_bound"]["passed"] is False
    assert "missing" in gate_names["machine_mandate_bound"]["reason"].lower()


# ---------------------------------------------------------------------------
# Mismatched response_digest (wrong MachineMandate document)
# ---------------------------------------------------------------------------

def test_mismatched_response_digest():
    """Wrong MachineMandate doc → machine_mandate_bound gate fails, ok=False."""
    wrong_mandate = copy.deepcopy(MACHINE_MANDATE)
    wrong_mandate["scope"]["max_spend"] = 100000  # tampered limit

    # Capsule was minted against the original MACHINE_MANDATE
    req_digest = json_digest(PERMIT_RECEIPT)
    resp_digest = json_digest(MACHINE_MANDATE)
    capsule = _mint_capsule(request_digest=req_digest, response_digest=resp_digest)

    # Verify against the wrong machine mandate
    result = verify_permitreceipt_mandate(capsule, PERMIT_RECEIPT, wrong_mandate)

    assert result["ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["machine_mandate_bound"]["passed"] is False
    assert "mismatch" in gate_names["machine_mandate_bound"]["reason"].lower()
    # Permit receipt gate should still pass since request_digest is correct
    assert gate_names["permit_receipt_bound"]["passed"] is True
