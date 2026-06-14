# SPDX-License-Identifier: BSD-3-Clause
"""Producer construction-time invariants (MUST-reject at construction)."""
import pytest

from agent_action_capsule import (
    AssuranceBlock,
    Disposition,
    EffectRecord,
    ExpiryPolicy,
    InvariantError,
    derive_effect_mode,
)

HEX = "a" * 64


# ---- §5.4 disposition honesty + closed approver enum ----------------------
def test_human_disposed_requires_human_approver():
    with pytest.raises(InvariantError):
        Disposition(decision="accept", approver="policy", human_disposed=True)


def test_human_disposed_true_with_human_is_fine():
    Disposition(decision="accept", approver="human", human_disposed=True)


def test_approver_is_a_closed_enum():
    with pytest.raises(InvariantError):
        Disposition(decision="accept", approver="vendor_bot", human_disposed=False)
    with pytest.raises(InvariantError):
        Disposition(decision="accept", approver="robot")


def test_policy_disposition_is_human_disposed_false():
    Disposition(decision="reject", approver="policy", human_disposed=False)


# ---- §5.2 confirmed-effect binding + status/digest table ------------------
def test_confirmed_requires_response_digest():
    with pytest.raises(InvariantError):
        EffectRecord(status="confirmed", effect_attestation="gate_executed")


def test_confirmed_with_response_digest_is_fine():
    EffectRecord(status="confirmed", response_digest=HEX, effect_attestation="gate_executed")


def test_planned_forbids_digests():
    with pytest.raises(InvariantError):
        EffectRecord(status="planned", request_digest=HEX)
    with pytest.raises(InvariantError):
        EffectRecord(status="planned", response_digest=HEX)


def test_dispatched_forbids_response_digest():
    with pytest.raises(InvariantError):
        EffectRecord(status="dispatched", response_digest=HEX, effect_attestation="runtime_claimed")


# ---- §5.4 expiry_policy ----------------------------------------------------
def test_expiry_ttl_must_be_integer():
    with pytest.raises(InvariantError):
        ExpiryPolicy(ttl_seconds="3600", on_expiry="expired")
    with pytest.raises(InvariantError):
        ExpiryPolicy(ttl_seconds=True, on_expiry="expired")  # bool is not a count
    ExpiryPolicy(ttl_seconds=3600, on_expiry="escalated")


# ---- §5.3 assurance enums --------------------------------------------------
def test_assurance_enums_validated():
    with pytest.raises(InvariantError):
        AssuranceBlock(attestation_mode="bogus", effect_mode="confirmed", ledger_mode="standalone")
    with pytest.raises(InvariantError):
        AssuranceBlock(attestation_mode="self_attested", effect_mode="confirmed", ledger_mode="bogus")


# ---- §5.2 effect_mode derivation ------------------------------------------
@pytest.mark.parametrize("status,expected", [
    ("planned", "not_applicable"),
    ("dispatched", "dispatched_unconfirmed"),
    ("failed", "dispatched_unconfirmed"),
    ("reverted", "dispatched_unconfirmed"),
    ("unknown_status", "dispatched_unconfirmed"),
])
def test_derive_effect_mode(status, expected):
    assert derive_effect_mode({"status": status}) == expected


def test_derive_effect_mode_confirmed_needs_response():
    assert derive_effect_mode({"status": "confirmed", "response_digest": HEX}) == "confirmed"
    assert derive_effect_mode({"status": "confirmed"}) == "dispatched_unconfirmed"


def test_derive_effect_mode_no_effect():
    assert derive_effect_mode(None) == "not_applicable"
