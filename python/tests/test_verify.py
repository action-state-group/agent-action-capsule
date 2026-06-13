# SPDX-License-Identifier: BSD-3-Clause
"""§6 Class 1 verifier — positive, negative (MUST-reject), store-level, never-throw."""
import pytest
from conftest import HEX_A, HEX_B, base_blocked, base_executed, reseal

from agent_action_capsule import InvariantError, parse_capsule, verify, verify_store


def codes(res):
    return {f.code for f in res.findings}


# ---- Positive --------------------------------------------------------------
def test_valid_executed_ok(executed):
    res = verify(executed)
    assert res.ok and res.errors == []


def test_valid_blocked_ok(blocked):
    res = verify(blocked)
    assert res.ok and res.errors == []


# ---- Check 1: Structural ---------------------------------------------------
def test_missing_required_field(executed):
    d = dict(executed)
    del d["operator"]
    res = verify(reseal(d))
    assert not res.ok and "missing_required_field" in codes(res)


def test_float_in_digest_field_rejected(executed):
    d = dict(executed)
    d["effect"] = dict(d["effect"], amount=12.50)
    res = verify(d)
    assert not res.ok and "float_in_digest_field" in codes(res)


def test_bad_action_type(executed):
    res = verify(reseal({**executed, "action_type": "weird"}))
    assert not res.ok and "action_type_invalid" in codes(res)


def test_invalid_approver_is_structural_not_unknown_registry(executed):
    d = dict(executed)
    d["disposition"] = dict(d["disposition"], approver="vendor_bot")
    res = verify(reseal(d))
    assert not res.ok
    assert "approver_invalid" in codes(res)
    assert "unknown_registry_value" not in codes(res)  # closed enum, not check 8


def test_defensive_dishonest_human_disposed(executed):
    d = dict(executed)
    d["disposition"] = {"decision": "accept", "approver": "policy", "human_disposed": True}
    res = verify(reseal(d))
    assert not res.ok and "dishonest_human_disposed" in codes(res)


# ---- Check 2: Identity -----------------------------------------------------
def test_capsule_id_mismatch(executed):
    d = dict(executed)
    d["operator"] = "TAMPERED"  # mutate without resealing
    res = verify(d)
    assert not res.ok and "capsule_id_mismatch" in codes(res)


# ---- Check 3: Confirmed-effect binding -------------------------------------
def test_confirmed_without_response(executed):
    d = dict(executed)
    d["effect"] = {"status": "confirmed", "type": "write_order", "effect_attestation": "gate_executed"}
    d["assurance"] = dict(d["assurance"], effect_mode="dispatched_unconfirmed")
    res = verify(reseal(d))
    assert not res.ok and "confirmed_without_response" in codes(res)


# ---- Check 4: Orthogonality ------------------------------------------------
def test_never_dispatch_class_with_effect_conflicts():
    d = base_blocked()  # verdict_class blocked
    d["effect"] = {"status": "dispatched", "type": "write_order", "request_digest": HEX_A, "effect_attestation": "runtime_claimed"}
    d["assurance"] = dict(d["assurance"], effect_mode="dispatched_unconfirmed")
    res = verify(reseal(d))
    assert not res.ok and "verdict_effect_conflict" in codes(res)


# ---- Check 5: Effect-attestation matrix ------------------------------------
def test_failed_without_attestation_fails_matrix():
    # The §6 NOTE test vector: failed -> dispatched_unconfirmed -> attestation REQUIRED.
    d = base_executed()
    d["effect"] = {"status": "failed", "type": "write_order"}
    d["assurance"] = dict(d["assurance"], effect_mode="dispatched_unconfirmed")
    d["disposition"] = dict(d["disposition"], verdict_class="errored")
    res = verify(reseal(d))
    assert not res.ok and "effect_attestation_missing" in codes(res)


def test_attestation_present_when_not_applicable_fails():
    d = base_blocked()
    d["effect"] = {"status": "planned", "type": "write_order", "effect_attestation": "gate_executed"}
    res = verify(reseal(d))
    assert not res.ok and "effect_attestation_present" in codes(res)


# ---- Check 6: Chain semantics (store-level) --------------------------------
def test_single_verify_notes_chain_is_store_level(executed):
    d = dict(executed)
    d["chain"] = {"parent_capsule_id": HEX_B, "relation": "supersedes"}
    res = verify(reseal(d))
    assert res.ok  # info only
    assert "chain_check_store_level" in codes(res)


def test_store_missing_parent_fails():
    child = base_executed()
    child["chain"] = {"parent_capsule_id": HEX_B, "relation": "supersedes"}
    child = reseal(child)
    [res] = verify_store([child])
    assert not res.ok and "chain_parent_missing" in codes(res)


def test_store_concurrent_supersedes_is_finding():
    parent = base_blocked()
    pid = parent["capsule_id"]
    c1 = reseal({**base_executed(), "action_id": "c1", "chain": {"parent_capsule_id": pid, "relation": "supersedes"}})
    c2 = reseal({**base_executed(), "action_id": "c2", "chain": {"parent_capsule_id": pid, "relation": "supersedes"}})
    r_parent, r1, r2 = verify_store([parent, c1, c2])
    assert r_parent.ok and r1.ok and r2.ok
    assert "concurrent_supersedes" not in codes(r1)
    assert "concurrent_supersedes" in codes(r2)  # later one flagged


# ---- Check 7: Assurance reconciliation -------------------------------------
def test_effect_mode_overclaim_is_error():
    d = base_executed()
    d["effect"] = {"status": "dispatched", "type": "write_order", "request_digest": HEX_A, "effect_attestation": "gate_executed"}
    # assurance still claims confirmed -> overclaim vs derived dispatched_unconfirmed
    res = verify(reseal(d))
    assert not res.ok and "assurance_overclaim" in codes(res)


def test_anchored_overclaim_is_informational_not_rejection():
    d = base_executed()
    d["assurance"] = dict(d["assurance"], ledger_mode="anchored")
    res = verify(reseal(d))
    assert res.ok  # cannot verify a Receipt at this layer -> info only
    assert "assurance_overclaim" in codes(res)


# ---- Check 8: Unknown registry values (never reject) -----------------------
def test_unknown_verdict_class_is_informational(executed):
    d = dict(executed)
    d["disposition"] = dict(d["disposition"], verdict_class="frobnicate")
    res = verify(reseal(d))
    assert res.ok and "unknown_registry_value" in codes(res)


def test_unknown_effect_type_is_informational(executed):
    d = dict(executed)
    d["effect"] = dict(d["effect"], type="teleport")
    res = verify(reseal(d))
    assert res.ok and "unknown_registry_value" in codes(res)


def test_unknown_effect_attestation_grades_to_floor(executed):
    d = dict(executed)
    d["effect"] = dict(d["effect"], effect_attestation="tee_anchored")
    res = verify(reseal(d))
    assert res.ok
    assert "unknown_registry_value" in codes(res)
    assert "effect_attestation_graded_floor" in codes(res)


def test_unknown_chain_relation_is_informational(executed):
    d = dict(executed)
    d["chain"] = {"parent_capsule_id": HEX_B, "relation": "amends"}
    res = verify(reseal(d))
    assert res.ok and "unknown_registry_value" in codes(res)


# ---- Never throw -----------------------------------------------------------
@pytest.mark.parametrize("garbage", [None, 123, "x", [], {}, {"effect": 5}, {"disposition": "no"}])
def test_verify_never_throws(garbage):
    res = verify(garbage)  # must not raise
    assert res.ok is False


# ---- Round-trip (producer path) -------------------------------------------
def test_parse_and_reseal_roundtrip(executed):
    cap = parse_capsule(executed)
    assert cap.seal()["capsule_id"] == executed["capsule_id"]


def test_parse_rejects_dishonest_capsule(executed):
    d = dict(executed)
    d["disposition"] = {"decision": "accept", "approver": "policy", "human_disposed": True}
    with pytest.raises(InvariantError):
        parse_capsule(reseal(d))
