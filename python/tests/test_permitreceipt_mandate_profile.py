# SPDX-License-Identifier: BSD-3-Clause
"""Tests for the PermitReceipt + MachineMandate profile-defined payload extension.

Binding location: ``effect.authorization`` (profile-defined payload extension),
NOT ``effect.request_digest`` / ``effect.response_digest`` (those retain -02
semantics: actual protected-action request / actual observed response).

NOTE: profile is OWNER-PROPOSED — REVIEW PENDING — NOT AGREED — NOT A RESULT.

Illustrative composition paths (subject to revision):
  - PermitReceipt.requested.amount = 425000 (EUR minor units = €4,250.00)
  - MachineMandate.scope.max_spend   = 500000 (EUR minor units = €5,000.00)

Covers:
  1. parse/round-trip: strict parse preserves effect.authorization through
     EffectRecord → to_dict → seal; capsule_id recomputes correctly.
  2. COSE_Sign1 round-trip: JSON → COSE_Sign1 → payload recovery → capsule_id
     recompute; recovered authorization refs and id match signed payload.
  3. Confirmed-status vector: real unprefixed I/O digests + both authorization
     refs present; response_digest is the outcome weld (≠ mandate digest).
  4. SD-JWT known-answer test: raw issuer-signed JWS bytes preimage.
  5. Positive case: correct typed references + appraisals → bindings_ok=True.
  6–11. Failure cases for each of the four gates.
"""
from __future__ import annotations

import copy
import hashlib
import json

import pytest

from agent_action_capsule.anchor import generate_issuer_keypair
from agent_action_capsule.canonical import compute_capsule_id, json_digest
from agent_action_capsule.contracts import EffectRecord
from agent_action_capsule.emit import emit
from agent_action_capsule.parse import parse_capsule
from agent_action_capsule.verify_composition import (
    PREIMAGE_JWS_ISSUER,
    verify_permitreceipt_mandate,
)

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

# Synthetic observed response (I/O artifact for the confirmed-status vector).
_OBSERVED_RESPONSE: dict = {
    "status": "payment_confirmed",
    "transaction_id": "txn-2026-0716-001",
    "amount_settled": 425000,
    "currency": "EUR",
}

# Synthetic observed request (I/O artifact for the confirmed-status vector).
_PROTECTED_REQUEST: dict = {
    "action": "initiate_payment",
    "amount": 425000,
    "currency": "EUR",
    "recipient": "example-vendor",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _typed_ref(artifact: dict | bytes, artifact_type: str) -> dict:
    if isinstance(artifact, (bytes, bytearray)):
        return {
            "type": artifact_type,
            "digest_alg": "SHA-256",
            "preimage": PREIMAGE_JWS_ISSUER,
            "digest": hashlib.sha256(artifact).hexdigest(),
        }
    return {
        "type": artifact_type,
        "digest_alg": "SHA-256",
        "digest": json_digest(artifact),
    }


def _mint_capsule(
    permit_receipt: dict | None = None,
    machine_mandate: dict | None = None,
    *,
    confirmed: bool = False,
) -> dict:
    """Build a capsule with effect.authorization and optionally confirmed status.

    When ``confirmed=True``, adds real request_digest/response_digest (I/O
    digests per -02 semantics, not the authorization references) so the
    confirmed-effect invariant is satisfied.
    """
    if confirmed:
        effect = EffectRecord(
            status="confirmed",
            type="payment",
            request_digest=json_digest(_PROTECTED_REQUEST),
            response_digest=json_digest(_OBSERVED_RESPONSE),
        )
    else:
        effect = EffectRecord(status="dispatched", type="payment")

    base = emit(
        action_type="decide",
        operator="asg-test",
        developer="test-agent@v1",
        effect=effect,
    )

    authorization: dict = {}
    if permit_receipt is not None:
        authorization["permit_receipt_digest"] = _typed_ref(permit_receipt, "PermitReceipt")
    if machine_mandate is not None:
        authorization["machine_mandate_digest"] = _typed_ref(machine_mandate, "MachineMandate")

    if not authorization:
        return base

    capsule = dict(base)
    capsule["effect"] = dict(base["effect"])
    capsule["effect"]["authorization"] = authorization
    capsule["capsule_id"] = compute_capsule_id(capsule)
    return capsule


def _positive_verify(capsule: dict) -> dict:
    return verify_permitreceipt_mandate(
        capsule,
        PERMIT_RECEIPT,
        MACHINE_MANDATE,
        permit_receipt_appraised=True,
        machine_mandate_appraised=True,
    )


# ---------------------------------------------------------------------------
# 1. Parse / strict-parse round-trip
#    effect.authorization must survive EffectRecord → to_dict → seal
# ---------------------------------------------------------------------------

def test_strict_parse_preserves_authorization():
    """Strict parse must preserve effect.authorization through the typed path."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)
    original_id = capsule["capsule_id"]

    # Parse into typed Capsule object and re-seal.
    typed = parse_capsule(capsule)
    resealed = typed.seal()

    # authorization must survive the round-trip.
    assert resealed["effect"]["authorization"] == capsule["effect"]["authorization"], (
        "effect.authorization was dropped during strict parse → re-seal"
    )
    # capsule_id must match — authorization is in the JCS preimage.
    assert resealed["capsule_id"] == original_id, (
        "capsule_id changed after strict parse → re-seal; authorization may not be in preimage"
    )


def test_authorization_enters_capsule_id_preimage():
    """Tampering with effect.authorization must change capsule_id."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)

    assert compute_capsule_id(capsule) == capsule["capsule_id"]

    tampered = copy.deepcopy(capsule)
    tampered["effect"]["authorization"]["permit_receipt_digest"]["digest"] = "a" * 64
    assert compute_capsule_id(tampered) != capsule["capsule_id"]


# ---------------------------------------------------------------------------
# 2. COSE_Sign1 round-trip (requires scitt-cose)
# ---------------------------------------------------------------------------

def test_cose_sign1_roundtrip_preserves_authorization():
    """COSE_Sign1 round-trip: recovered payload must contain effect.authorization
    and the recovered capsule_id must match the recomputed value."""
    from scitt_cose.statement import build_signed_statement, parse_signed_statement  # type: ignore

    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)
    original_id = capsule["capsule_id"]
    payload_bytes = json.dumps(capsule, separators=(",", ":"), sort_keys=False).encode("utf-8")

    signing_key_pem, issuer_pub_pem = generate_issuer_keypair()
    statement = build_signed_statement(
        payload=payload_bytes,
        alg="EdDSA",
        private_key_pem=signing_key_pem,
        issuer="did:example:test",
        subject="test-subject",
        content_type="application/json",
    )

    # Recover from the signed statement.
    parsed = parse_signed_statement(statement, public_key_pem=issuer_pub_pem)
    assert parsed.get("signature_verified") is True, "COSE signature did not verify"

    recovered_bytes = parsed["payload"]
    recovered = json.loads(recovered_bytes)

    # effect.authorization must survive intact.
    assert "authorization" in recovered.get("effect", {}), (
        "effect.authorization missing from COSE payload recovery"
    )
    assert recovered["effect"]["authorization"] == capsule["effect"]["authorization"]

    # capsule_id must recompute correctly from the recovered payload.
    assert compute_capsule_id(recovered) == original_id, (
        "capsule_id mismatch after COSE round-trip"
    )


# ---------------------------------------------------------------------------
# 3. Confirmed-status vector: real I/O digests + authorization refs + outcome weld
# ---------------------------------------------------------------------------

def test_confirmed_status_with_io_and_authorization():
    """Confirmed vector: effect.request_digest and effect.response_digest carry
    real I/O digests (per -02 semantics); authorization refs carry separate
    PermitReceipt and MachineMandate bindings.

    response_digest == SHA-256(JCS(observed_response)) is the outcome weld for
    Anton's TPM PCR16 measurement.  It is explicitly NOT the MachineMandate
    digest — those are independent bindings in effect.authorization.
    """
    capsule = _mint_capsule(
        permit_receipt=PERMIT_RECEIPT,
        machine_mandate=MACHINE_MANDATE,
        confirmed=True,
    )

    effect = capsule["effect"]

    # -02 I/O digests are present and correct.
    assert effect["request_digest"] == json_digest(_PROTECTED_REQUEST)
    assert effect["response_digest"] == json_digest(_OBSERVED_RESPONSE)

    # The authorization refs are independent of the I/O digests.
    assert effect["authorization"]["permit_receipt_digest"]["digest"] == json_digest(PERMIT_RECEIPT)
    assert effect["authorization"]["machine_mandate_digest"]["digest"] == json_digest(MACHINE_MANDATE)

    # Crucially: response_digest ≠ machine_mandate digest (the outcome weld is the
    # observed response, not the mandate reference).
    assert effect["response_digest"] != effect["authorization"]["machine_mandate_digest"]["digest"]

    # Binding verifier passes.
    result = _positive_verify(capsule)
    assert result["bindings_ok"] is True


# ---------------------------------------------------------------------------
# 4. SD-JWT known-answer test
# ---------------------------------------------------------------------------

def test_sdjwt_jws_preimage_known_answer():
    """Known-answer test: raw issuer-signed JWS bytes → SHA-256 → digest match."""
    # Fake compact-JWS bytes (issuer-signed component only — no holder presentation).
    jws_bytes = (
        b"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"
        b".eyJ0eXBlIjoiUGVybWl0UmVjZWlwdCIsImFtb3VudCI6NDI1MDAwfQ"
        b".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    expected_digest = hashlib.sha256(jws_bytes).hexdigest()

    # Build capsule with SD-JWT typed reference (bytes companion).
    base = emit(
        action_type="decide",
        operator="asg-test",
        developer="test-agent@v1",
        effect=EffectRecord(status="dispatched", type="payment"),
    )
    capsule = dict(base)
    capsule["effect"] = dict(base["effect"])
    capsule["effect"]["authorization"] = {
        "permit_receipt_digest": {
            "type": "PermitReceipt",
            "digest_alg": "SHA-256",
            "preimage": PREIMAGE_JWS_ISSUER,
            "digest": expected_digest,
        },
        "machine_mandate_digest": _typed_ref(MACHINE_MANDATE, "MachineMandate"),
    }
    capsule["capsule_id"] = compute_capsule_id(capsule)

    result = verify_permitreceipt_mandate(
        capsule,
        jws_bytes,          # bytes companion for PermitReceipt
        MACHINE_MANDATE,    # dict companion for MachineMandate
        permit_receipt_appraised=True,
        machine_mandate_appraised=True,
    )
    assert result["bindings_ok"] is True
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is True
    assert PREIMAGE_JWS_ISSUER in gate_names["permit_receipt_bound"]["reason"]


# ---------------------------------------------------------------------------
# 5. Positive case (JSON companions)
# ---------------------------------------------------------------------------

def test_positive_both_correct():
    """Correct typed references + appraisals → bindings_ok=True, all four gates pass."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)
    result = _positive_verify(capsule)

    assert result["bindings_ok"] is True
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is True
    assert gate_names["permit_receipt_appraised"]["passed"] is True
    assert gate_names["machine_mandate_bound"]["passed"] is True
    assert gate_names["machine_mandate_appraised"]["passed"] is True


# ---------------------------------------------------------------------------
# 6. Digest match without appraisal is NOT authorization success
# ---------------------------------------------------------------------------

def test_digest_match_without_appraisal_is_not_success():
    """Binding-only: digest match but appraisal=None → bindings_ok=False."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)
    result = verify_permitreceipt_mandate(
        capsule,
        PERMIT_RECEIPT,
        MACHINE_MANDATE,
        permit_receipt_appraised=None,
        machine_mandate_appraised=None,
    )
    assert result["bindings_ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is True   # digest matched
    assert gate_names["permit_receipt_appraised"]["passed"] is False  # no appraisal
    assert gate_names["machine_mandate_bound"]["passed"] is True
    assert gate_names["machine_mandate_appraised"]["passed"] is False


# ---------------------------------------------------------------------------
# 7. Missing authorization block
# ---------------------------------------------------------------------------

def test_missing_authorization_block():
    """Missing effect.authorization → all four gates fail, bindings_ok=False."""
    base = emit(
        action_type="decide",
        operator="asg-test",
        developer="test-agent@v1",
        effect=EffectRecord(status="dispatched", type="payment"),
    )
    result = _positive_verify(base)
    assert result["bindings_ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is False
    assert gate_names["machine_mandate_bound"]["passed"] is False


# ---------------------------------------------------------------------------
# 8–9. Missing individual references
# ---------------------------------------------------------------------------

def test_missing_permit_receipt_reference():
    """Missing permit_receipt_digest → permit_receipt_bound fails."""
    capsule = _mint_capsule(machine_mandate=MACHINE_MANDATE)
    result = _positive_verify(capsule)

    assert result["bindings_ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is False
    assert "missing" in gate_names["permit_receipt_bound"]["reason"].lower()
    assert gate_names["machine_mandate_bound"]["passed"] is True


def test_missing_machine_mandate_reference():
    """Missing machine_mandate_digest → machine_mandate_bound fails."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT)
    result = _positive_verify(capsule)

    assert result["bindings_ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["machine_mandate_bound"]["passed"] is False
    assert "missing" in gate_names["machine_mandate_bound"]["reason"].lower()
    assert gate_names["permit_receipt_bound"]["passed"] is True


# ---------------------------------------------------------------------------
# 10–11. Digest mismatch (wrong companion document)
# ---------------------------------------------------------------------------

def test_mismatched_permit_receipt():
    """Wrong PermitReceipt doc → permit_receipt_bound fails with 'mismatch'."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)

    wrong_permit = copy.deepcopy(PERMIT_RECEIPT)
    wrong_permit["requested"]["amount"] = 999999

    result = verify_permitreceipt_mandate(
        capsule, wrong_permit, MACHINE_MANDATE,
        permit_receipt_appraised=True,
        machine_mandate_appraised=True,
    )
    assert result["bindings_ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is False
    assert "mismatch" in gate_names["permit_receipt_bound"]["reason"].lower()
    assert gate_names["machine_mandate_bound"]["passed"] is True


def test_mismatched_machine_mandate():
    """Wrong MachineMandate doc → machine_mandate_bound fails with 'mismatch'."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)

    wrong_mandate = copy.deepcopy(MACHINE_MANDATE)
    wrong_mandate["scope"]["max_spend"] = 100000

    result = verify_permitreceipt_mandate(
        capsule, PERMIT_RECEIPT, wrong_mandate,
        permit_receipt_appraised=True,
        machine_mandate_appraised=True,
    )
    assert result["bindings_ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["machine_mandate_bound"]["passed"] is False
    assert "mismatch" in gate_names["machine_mandate_bound"]["reason"].lower()
    assert gate_names["permit_receipt_bound"]["passed"] is True


# ---------------------------------------------------------------------------
# 12. Malformed reference (missing required field)
# ---------------------------------------------------------------------------

def test_malformed_reference_missing_type():
    """Reference missing 'type' → permit_receipt_bound fails."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)

    tampered = copy.deepcopy(capsule)
    del tampered["effect"]["authorization"]["permit_receipt_digest"]["type"]
    tampered["capsule_id"] = compute_capsule_id(tampered)

    result = _positive_verify(tampered)
    assert result["bindings_ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is False
    assert gate_names["machine_mandate_bound"]["passed"] is True


# ---------------------------------------------------------------------------
# 13. Owner appraisal rejected
# ---------------------------------------------------------------------------

def test_owner_appraisal_rejected():
    """Correct digest but owner verifier rejected → bindings_ok=False."""
    capsule = _mint_capsule(permit_receipt=PERMIT_RECEIPT, machine_mandate=MACHINE_MANDATE)
    result = verify_permitreceipt_mandate(
        capsule,
        PERMIT_RECEIPT,
        MACHINE_MANDATE,
        permit_receipt_appraised=False,
        machine_mandate_appraised=True,
    )
    assert result["bindings_ok"] is False
    gate_names = {g["name"]: g for g in result["gates"]}
    assert gate_names["permit_receipt_bound"]["passed"] is True
    assert gate_names["permit_receipt_appraised"]["passed"] is False
    assert gate_names["machine_mandate_bound"]["passed"] is True
    assert gate_names["machine_mandate_appraised"]["passed"] is True
