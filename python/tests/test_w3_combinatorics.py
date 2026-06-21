# SPDX-License-Identifier: BSD-3-Clause
"""Systematic cross-field invariant combinatorics (W-3 hardening pass).

Groups:
 1. NEVER_DISPATCH × effect.status — construction-time InvariantError
 2. NEVER_DISPATCH × effect — verifier MUST-reject over arbitrary bytes
 3. human_disposed × approver — construction-time
 4. disposition honesty on arbitrary bytes — verifier warning (non-gating)
 5. EffectRecord status/digest table — construction-time
 6. effect_mode derivation vs assurance claims — verifier overclaim
 7. derive_effect_mode contract — combinatorial
 8. ExpiryPolicy invariants — construction-time
 9. AssuranceBlock closed enums — construction-time
10. Chain invariants — construction-time
"""
from __future__ import annotations

import pytest
from conftest import HEX_A, base_blocked, base_executed, reseal

from agent_action_capsule import (
    AssuranceBlock,
    Capsule,
    Chain,
    Disposition,
    EffectRecord,
    ExpiryPolicy,
    InvariantError,
    derive_effect_mode,
    verify,
)
from agent_action_capsule.contracts import (
    ATTESTATION_MODES,
    EFFECT_MODES,
    LEDGER_MODES,
    NEVER_DISPATCH_VERDICT_CLASSES,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DISPATCHING_EFFECT_STATUSES = ("dispatched", "confirmed", "failed", "reverted")


def _make_capsule(
    vc: str,
    effect: EffectRecord | None = None,
    approver: str = "policy",
    human_disposed: bool = False,
    decision: str = "reject",
) -> Capsule:
    """Build a minimal Capsule for invariant tests."""
    from agent_action_capsule.contracts import derive_effect_mode as _derive

    eff_dict = None
    if effect is not None:
        eff_dict = {
            "status": effect.status,
            "response_digest": effect.response_digest,
        }
    eff_mode = _derive(eff_dict)
    return Capsule(
        spec_version="draft-mih-scitt-agent-action-capsule-00",
        format_version="2",
        action_id="act-x",
        action_type="decide",
        operator="OP",
        developer="DEV",
        timestamp="2026-06-20T00:00:00Z",
        effect=effect,
        assurance=AssuranceBlock(
            attestation_mode="self_attested",
            effect_mode=eff_mode,
            ledger_mode="standalone",
        ),
        disposition=Disposition(
            decision=decision,
            approver=approver,
            human_disposed=human_disposed,
            verdict_class=vc,
        ),
    )


# ---------------------------------------------------------------------------
# Group 1: NEVER_DISPATCH × effect.status — construction-time InvariantError
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vc", sorted(NEVER_DISPATCH_VERDICT_CLASSES))
def test_never_dispatch_with_dispatched_effect_raises(vc):
    """verdict_class in NEVER_DISPATCH + effect.status='dispatched' → InvariantError."""
    effect = EffectRecord(status="dispatched", request_digest=HEX_A)
    with pytest.raises(InvariantError, match="NEVER_DISPATCH_VERDICT_CLASSES"):
        _make_capsule(vc, effect=effect)


@pytest.mark.parametrize("vc", sorted(NEVER_DISPATCH_VERDICT_CLASSES))
def test_never_dispatch_with_confirmed_effect_raises(vc):
    """verdict_class in NEVER_DISPATCH + effect.status='confirmed' → InvariantError."""
    effect = EffectRecord(status="confirmed", response_digest=HEX_A)
    with pytest.raises(InvariantError, match="NEVER_DISPATCH_VERDICT_CLASSES"):
        _make_capsule(vc, effect=effect)


@pytest.mark.parametrize("vc", sorted(NEVER_DISPATCH_VERDICT_CLASSES))
def test_never_dispatch_with_failed_effect_raises(vc):
    """verdict_class in NEVER_DISPATCH + effect.status='failed' → InvariantError."""
    effect = EffectRecord(status="failed")
    with pytest.raises(InvariantError, match="NEVER_DISPATCH_VERDICT_CLASSES"):
        _make_capsule(vc, effect=effect)


@pytest.mark.parametrize("vc", sorted(NEVER_DISPATCH_VERDICT_CLASSES))
def test_never_dispatch_with_reverted_effect_raises(vc):
    """verdict_class in NEVER_DISPATCH + effect.status='reverted' → InvariantError."""
    effect = EffectRecord(status="reverted")
    with pytest.raises(InvariantError, match="NEVER_DISPATCH_VERDICT_CLASSES"):
        _make_capsule(vc, effect=effect)


@pytest.mark.parametrize("vc", sorted(NEVER_DISPATCH_VERDICT_CLASSES))
def test_never_dispatch_no_effect_ok(vc):
    """verdict_class in NEVER_DISPATCH + no effect → ok (no dispatch claim)."""
    _make_capsule(vc, effect=None)  # must not raise


@pytest.mark.parametrize("vc", sorted(NEVER_DISPATCH_VERDICT_CLASSES))
def test_never_dispatch_planned_effect_ok(vc):
    """verdict_class in NEVER_DISPATCH + effect.status='planned' → ok."""
    effect = EffectRecord(status="planned")
    _make_capsule(vc, effect=effect)  # must not raise


# ---------------------------------------------------------------------------
# Group 2: NEVER_DISPATCH × effect — verifier MUST-reject over arbitrary bytes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vc", sorted(NEVER_DISPATCH_VERDICT_CLASSES))
def test_verifier_rejects_never_dispatch_with_dispatched_effect(vc):
    """Verifier MUST report verdict_effect_conflict when NEVER_DISPATCH vc has a dispatching effect."""
    d = base_blocked()
    # Inject a dispatched effect and change the verdict_class
    d["effect"] = {
        "status": "dispatched",
        "request_digest": HEX_A,
        "effect_attestation": "gate_executed",
    }
    d["assurance"] = {
        "attestation_mode": "self_attested",
        "effect_mode": "dispatched_unconfirmed",
        "ledger_mode": "standalone",
    }
    d["disposition"]["verdict_class"] = vc
    d = reseal(d)
    result = verify(d)
    assert not result.ok
    codes = [f.code for f in result.findings]
    assert "verdict_effect_conflict" in codes


# ---------------------------------------------------------------------------
# Group 3: human_disposed × approver — construction-time
# ---------------------------------------------------------------------------


def test_human_disposed_true_approver_human_ok():
    Disposition(decision="accept", approver="human", human_disposed=True)


def test_human_disposed_true_approver_policy_raises():
    with pytest.raises(InvariantError, match="human_disposed"):
        Disposition(decision="accept", approver="policy", human_disposed=True)


def test_human_disposed_false_approver_human_ok():
    Disposition(decision="accept", approver="human", human_disposed=False)


def test_human_disposed_false_approver_policy_ok():
    Disposition(decision="reject", approver="policy", human_disposed=False)


def test_approver_vendor_bot_raises():
    with pytest.raises(InvariantError, match="approver"):
        Disposition(decision="reject", approver="vendor_bot", human_disposed=False)


def test_approver_empty_string_raises():
    with pytest.raises(InvariantError, match="approver"):
        Disposition(decision="reject", approver="", human_disposed=False)


def test_approver_none_raises():
    with pytest.raises(InvariantError, match="approver"):
        Disposition(decision="reject", approver=None, human_disposed=False)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Group 4: disposition honesty on arbitrary bytes — verifier warning (non-gating)
# ---------------------------------------------------------------------------


def test_verifier_dishonest_human_disposed_is_warning_not_error():
    """human_disposed=True + approver='policy' in raw bytes → ok=True + warning finding."""
    d = base_executed()
    d["disposition"]["human_disposed"] = True
    d["disposition"]["approver"] = "policy"
    d = reseal(d)
    result = verify(d)
    # Non-gating: ok must still be True
    assert result.ok, f"Expected ok=True; findings: {result.findings}"
    codes = {f.code for f in result.findings}
    assert "dishonest_human_disposed" in codes
    # Confirm the finding is a warning, not an error
    dishonest = [f for f in result.findings if f.code == "dishonest_human_disposed"]
    assert all(f.severity == "warning" for f in dishonest)


# ---------------------------------------------------------------------------
# Group 5: EffectRecord status/digest table — construction-time
# ---------------------------------------------------------------------------


def test_effect_confirmed_no_response_digest_raises():
    with pytest.raises(InvariantError, match="confirmed"):
        EffectRecord(status="confirmed")


def test_effect_confirmed_bad_response_digest_raises():
    with pytest.raises(InvariantError, match="confirmed"):
        EffectRecord(status="confirmed", response_digest="not-hex-64")


def test_effect_confirmed_valid_response_digest_ok():
    EffectRecord(status="confirmed", response_digest=HEX_A)


def test_effect_planned_with_request_digest_raises():
    with pytest.raises(InvariantError, match="planned"):
        EffectRecord(status="planned", request_digest=HEX_A)


def test_effect_planned_with_response_digest_raises():
    with pytest.raises(InvariantError, match="planned"):
        EffectRecord(status="planned", response_digest=HEX_A)


def test_effect_planned_no_digests_ok():
    EffectRecord(status="planned")


def test_effect_dispatched_with_response_digest_raises():
    with pytest.raises(InvariantError, match="dispatched"):
        EffectRecord(status="dispatched", response_digest=HEX_A)


def test_effect_dispatched_with_request_digest_ok():
    EffectRecord(status="dispatched", request_digest=HEX_A)


def test_effect_failed_no_digests_ok():
    EffectRecord(status="failed")


def test_effect_reverted_no_digests_ok():
    EffectRecord(status="reverted")


def test_effect_bad_response_digest_non_confirmed_raises():
    """response_digest must be 64-hex even when status != 'confirmed'."""
    # dispatched + bad response_digest: dispatched forbids response_digest entirely
    # so we use 'failed' (which permits response_digest) to test the hex64 check
    with pytest.raises(InvariantError, match="64-hex"):
        EffectRecord(status="failed", response_digest="not-64-hex")


def test_effect_bad_request_digest_raises():
    with pytest.raises(InvariantError, match="64-hex"):
        EffectRecord(status="dispatched", request_digest="bad")


# ---------------------------------------------------------------------------
# Group 6: effect_mode derivation vs assurance claims — verifier overclaim
# ---------------------------------------------------------------------------


def test_assurance_overclaim_confirmed_but_derived_dispatched_unconfirmed():
    """Claiming effect_mode='confirmed' with only a dispatched effect → assurance_overclaim error."""
    d = base_executed()
    # Replace confirmed effect with dispatched (no response_digest)
    d["effect"] = {
        "status": "dispatched",
        "request_digest": HEX_A,
        "effect_attestation": "gate_executed",
    }
    # Keep the assurance claiming 'confirmed'
    d["assurance"]["effect_mode"] = "confirmed"
    d = reseal(d)
    result = verify(d)
    assert not result.ok
    codes = [f.code for f in result.findings]
    assert "assurance_overclaim" in codes


def test_assurance_overclaim_confirmed_but_derived_not_applicable():
    """Claiming effect_mode='confirmed' with no effect at all → assurance_overclaim error."""
    d = base_blocked()
    d["assurance"]["effect_mode"] = "confirmed"
    d = reseal(d)
    result = verify(d)
    assert not result.ok
    codes = [f.code for f in result.findings]
    assert "assurance_overclaim" in codes


def test_assurance_no_overclaim_dispatched_unconfirmed_vs_not_applicable():
    """Claiming 'dispatched_unconfirmed' with no effect: rank tie, NOT an overclaim."""
    d = base_blocked()
    d["assurance"]["effect_mode"] = "dispatched_unconfirmed"
    d = reseal(d)
    result = verify(d)
    # No assurance_overclaim — rank("dispatched_unconfirmed")=0 == rank("not_applicable")=0
    codes = [f.code for f in result.findings]
    assert "assurance_overclaim" not in codes


# ---------------------------------------------------------------------------
# Group 7: derive_effect_mode contract — combinatorial
# ---------------------------------------------------------------------------


def test_derive_effect_mode_none():
    assert derive_effect_mode(None) == "not_applicable"


def test_derive_effect_mode_planned():
    assert derive_effect_mode({"status": "planned"}) == "not_applicable"


def test_derive_effect_mode_confirmed_valid_digest():
    assert derive_effect_mode({"status": "confirmed", "response_digest": HEX_A}) == "confirmed"


def test_derive_effect_mode_confirmed_no_digest():
    assert derive_effect_mode({"status": "confirmed"}) == "dispatched_unconfirmed"


def test_derive_effect_mode_dispatched():
    assert derive_effect_mode({"status": "dispatched"}) == "dispatched_unconfirmed"


def test_derive_effect_mode_failed():
    assert derive_effect_mode({"status": "failed"}) == "dispatched_unconfirmed"


def test_derive_effect_mode_reverted():
    assert derive_effect_mode({"status": "reverted"}) == "dispatched_unconfirmed"


def test_derive_effect_mode_unknown_status():
    assert derive_effect_mode({"status": "unknown_future_status"}) == "dispatched_unconfirmed"


# ---------------------------------------------------------------------------
# Group 8: ExpiryPolicy invariants — construction-time
# ---------------------------------------------------------------------------


def test_expiry_policy_valid_expired():
    ExpiryPolicy(ttl_seconds=3600, on_expiry="expired")


def test_expiry_policy_valid_escalated():
    ExpiryPolicy(ttl_seconds=3600, on_expiry="escalated")


def test_expiry_policy_bool_true_raises():
    """bool is an int subclass but not a count of seconds."""
    with pytest.raises(InvariantError, match="integer"):
        ExpiryPolicy(ttl_seconds=True, on_expiry="expired")  # type: ignore[arg-type]


def test_expiry_policy_bool_false_raises():
    with pytest.raises(InvariantError, match="integer"):
        ExpiryPolicy(ttl_seconds=False, on_expiry="expired")  # type: ignore[arg-type]


def test_expiry_policy_string_raises():
    with pytest.raises(InvariantError, match="integer"):
        ExpiryPolicy(ttl_seconds="3600", on_expiry="expired")  # type: ignore[arg-type]


def test_expiry_policy_zero_ok():
    """Zero is a valid integer count."""
    ExpiryPolicy(ttl_seconds=0, on_expiry="expired")


def test_expiry_policy_negative_ok():
    """Negative is not explicitly rejected by the spec."""
    ExpiryPolicy(ttl_seconds=-1, on_expiry="expired")


def test_expiry_policy_invalid_on_expiry_raises():
    with pytest.raises(InvariantError, match="on_expiry"):
        ExpiryPolicy(ttl_seconds=3600, on_expiry="auto-cancel")


def test_expiry_policy_empty_on_expiry_raises():
    with pytest.raises(InvariantError, match="on_expiry"):
        ExpiryPolicy(ttl_seconds=3600, on_expiry="")


# ---------------------------------------------------------------------------
# Group 9: AssuranceBlock closed enums — construction-time
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("amode", sorted(ATTESTATION_MODES))
@pytest.mark.parametrize("emode", sorted(EFFECT_MODES))
@pytest.mark.parametrize("lmode", sorted(LEDGER_MODES))
def test_assurance_block_all_valid_combos(amode, emode, lmode):
    """All valid enum combinations must construct without error."""
    AssuranceBlock(attestation_mode=amode, effect_mode=emode, ledger_mode=lmode)


def test_assurance_block_invalid_attestation_mode_raises():
    with pytest.raises(InvariantError, match="attestation_mode"):
        AssuranceBlock(attestation_mode="vendor_signed", effect_mode="confirmed", ledger_mode="standalone")


def test_assurance_block_invalid_effect_mode_raises():
    with pytest.raises(InvariantError, match="effect_mode"):
        AssuranceBlock(attestation_mode="self_attested", effect_mode="super_confirmed", ledger_mode="standalone")


def test_assurance_block_invalid_ledger_mode_raises():
    with pytest.raises(InvariantError, match="ledger_mode"):
        AssuranceBlock(attestation_mode="self_attested", effect_mode="confirmed", ledger_mode="distributed")


# ---------------------------------------------------------------------------
# Group 10: Chain invariants — construction-time
# ---------------------------------------------------------------------------


def test_chain_valid():
    Chain(parent_capsule_id=HEX_A, relation="confirms")


def test_chain_short_parent_raises():
    with pytest.raises(InvariantError, match="64-hex"):
        Chain(parent_capsule_id="short", relation="confirms")


def test_chain_none_parent_raises():
    with pytest.raises(InvariantError, match="64-hex"):
        Chain(parent_capsule_id=None, relation="confirms")  # type: ignore[arg-type]


def test_chain_empty_relation_raises():
    with pytest.raises(InvariantError, match="relation"):
        Chain(parent_capsule_id=HEX_A, relation="")


def test_chain_none_relation_raises():
    with pytest.raises(InvariantError, match="relation"):
        Chain(parent_capsule_id=HEX_A, relation=None)  # type: ignore[arg-type]
