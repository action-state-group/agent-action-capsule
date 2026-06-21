# SPDX-License-Identifier: BSD-3-Clause
"""W6 round-trip conformance tests.

Exercises emit() → verify() round-trips for every legal capsule shape, plus
negative conformance tests for tampered capsules. Also exercises verify_store()
at the store level.
"""
import pytest

from agent_action_capsule import verify, verify_store
from agent_action_capsule.emit import emit
from agent_action_capsule.contracts import (
    NEVER_DISPATCH_VERDICT_CLASSES, VALID_APPROVERS, EFFECT_MODES, LEDGER_MODES,
)
from agent_action_capsule import (
    AssuranceBlock, Capsule, Disposition, EffectRecord,
)
from conftest import reseal, HEX_A, HEX_B


# ---------------------------------------------------------------------------
# 1. Round-trip: every emitted capsule verifies
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("action_type,verdict_class,approver,human_disposed", [
    ("fyi", "executed", "policy", False),
    ("decide", "blocked", "policy", False),
    ("decide", "denied", "policy", False),
    ("decide", "deferred", "human", True),
    ("decide", "executed", "human", True),
    ("decide", "errored", "policy", False),
    ("decide", "resolved", "policy", False),
])
def test_round_trip_emit_verifies(action_type, verdict_class, approver, human_disposed):
    """emit() with various shapes → verify() returns ok=True."""
    disp = Disposition(
        decision="accept" if verdict_class not in NEVER_DISPATCH_VERDICT_CLASSES else "reject",
        approver=approver,
        human_disposed=human_disposed,
        verdict_class=verdict_class,
    )
    capsule = emit(
        action_id=f"test/{verdict_class}",
        action_type=action_type,
        operator="test-op",
        developer="test-dev@v1",
        disposition=disp,
    )
    res = verify(capsule)
    assert res.ok, [f.code for f in res.findings]


# ---------------------------------------------------------------------------
# 2. Round-trip: capsule with confirmed effect verifies
# ---------------------------------------------------------------------------

def test_round_trip_with_confirmed_effect():
    """Confirmed effect → verifies correctly and reports effect_mode=confirmed."""
    effect = EffectRecord(status="confirmed", response_digest=HEX_A, effect_attestation="gate_executed")
    disp = Disposition(decision="accept", approver="human", human_disposed=True, verdict_class="executed")
    capsule = emit(
        action_id="test/confirmed",
        action_type="decide",
        operator="OP",
        developer="DEV@v1",
        effect=effect,
        disposition=disp,
    )
    res = verify(capsule)
    assert res.ok
    assert res.assurance["effect_mode"] == "confirmed"


# ---------------------------------------------------------------------------
# 3. Round-trip: chained capsules verify against store
# ---------------------------------------------------------------------------

def test_chained_capsules_verify_in_store():
    """Parent + child chain verifies cleanly in a verify_store() run."""
    parent = emit(action_id="parent", action_type="decide", operator="OP", developer="DEV")
    pid = parent["capsule_id"]
    child = emit(
        action_id="child",
        action_type="decide",
        operator="OP",
        developer="DEV",
        prior_capsule_id=pid,
        chain_relation="confirms",
    )
    results = verify_store([parent, child])
    assert all(r.ok for r in results)


# ---------------------------------------------------------------------------
# 4. Round-trip with model_attestation
# ---------------------------------------------------------------------------

def test_round_trip_with_model_attestation():
    """Model attestation block is included and capsule still verifies."""
    capsule = emit(
        action_id="test/model",
        action_type="fyi",
        operator="OP",
        developer="DEV",
        model_id="claude-sonnet-4-6",
        provider="anthropic",
        compute_attestation={"chip": "A100"},
    )
    res = verify(capsule)
    assert res.ok
    assert "model_attestation" in capsule


# ---------------------------------------------------------------------------
# 5. Positive: all effect status shapes round-trip cleanly
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status,response_digest,attestation", [
    ("planned", None, None),
    ("dispatched", None, "runtime_claimed"),
    ("confirmed", HEX_A, "gate_executed"),
    ("failed", None, "runtime_claimed"),
    ("reverted", None, "runtime_claimed"),
])
def test_effect_status_all_shapes_round_trip(status, response_digest, attestation):
    """Every legal effect.status emits and verifies cleanly."""
    kw: dict = {"status": status}
    if response_digest:
        kw["response_digest"] = response_digest
    if attestation:
        kw["effect_attestation"] = attestation
    effect = EffectRecord(**kw)
    disp = Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="executed")
    capsule = emit(
        action_id=f"test-{status}",
        action_type="decide",
        operator="OP",
        developer="DEV",
        effect=effect,
        disposition=disp,
    )
    res = verify(capsule)
    assert res.ok, [f.code for f in res.findings]


# ---------------------------------------------------------------------------
# 6. Negative: forged confirmed-effect (tamper response_digest after sealing)
# ---------------------------------------------------------------------------

def test_forged_confirmed_effect_fails():
    """Tampering response_digest after sealing causes capsule_id_mismatch."""
    effect = EffectRecord(status="confirmed", response_digest=HEX_A, effect_attestation="gate_executed")
    disp = Disposition(decision="accept", approver="human", human_disposed=True, verdict_class="executed")
    capsule = emit("test/forged", "decide", "OP", "DEV", effect=effect, disposition=disp)
    # Tamper: change the response_digest in-place (capsule_id becomes stale → mismatch)
    capsule["effect"]["response_digest"] = "b" * 64
    res = verify(capsule)
    assert not res.ok
    codes = {f.code for f in res.findings}
    assert "capsule_id_mismatch" in codes  # tamper always causes mismatch


# ---------------------------------------------------------------------------
# 7. Negative: tampered capsule_id (direct assignment, no reseal)
# ---------------------------------------------------------------------------

def test_tampered_capsule_id_fails():
    """Directly setting a wrong capsule_id is detected as a mismatch."""
    effect = EffectRecord(status="confirmed", response_digest=HEX_A, effect_attestation="gate_executed")
    disp = Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="executed")
    capsule = emit("test/tamper", "decide", "OP", "DEV", effect=effect, disposition=disp)
    capsule["capsule_id"] = "c" * 64  # wrong id
    res = verify(capsule)
    assert not res.ok
    assert "capsule_id_mismatch" in {f.code for f in res.findings}


# ---------------------------------------------------------------------------
# 8. Negative: field mutation causes id mismatch
# ---------------------------------------------------------------------------

def test_field_mutation_causes_id_mismatch():
    """Mutating any top-level field without resealing produces capsule_id_mismatch."""
    capsule = emit("test/mutate", "fyi", "OP", "DEV")
    capsule["operator"] = "HACKER"  # mutate without resealing
    res = verify(capsule)
    assert not res.ok
    assert "capsule_id_mismatch" in {f.code for f in res.findings}


# ---------------------------------------------------------------------------
# 9. verify_store: all capsule shapes verify in a store
# ---------------------------------------------------------------------------

def test_store_level_all_shapes_verify():
    """A store with one of each verdict class verifies cleanly end-to-end."""
    capsules = []
    for vc, has_effect in [("executed", True), ("blocked", False), ("denied", False), ("errored", True)]:
        eff = None
        if has_effect:
            eff = EffectRecord(status="dispatched", effect_attestation="runtime_claimed")
        disp = Disposition(
            decision="accept" if has_effect else "reject",
            approver="policy",
            human_disposed=False,
            verdict_class=vc,
        )
        capsules.append(emit(f"test/{vc}", "decide", "OP", "DEV", effect=eff, disposition=disp))
    results = verify_store(capsules)
    assert all(r.ok for r in results), [
        (i, [f.code for f in r.findings]) for i, r in enumerate(results) if not r.ok
    ]
