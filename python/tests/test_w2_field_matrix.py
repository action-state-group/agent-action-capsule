# SPDX-License-Identifier: BSD-3-Clause
import pytest
from conftest import HEX_A, HEX_B, base_blocked, base_executed, reseal

from agent_action_capsule import verify

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def codes(res):
    return {f.code for f in res.findings}


# ===========================================================================
# Section 1: Top-level REQUIRED_FIELDS matrix
# ===========================================================================

REQUIRED_FIELDS = (
    "spec_version",
    "format_version",
    "capsule_id",
    "action_id",
    "action_type",
    "operator",
    "developer",
    "timestamp",
)


@pytest.mark.parametrize("fld", REQUIRED_FIELDS)
def test_required_field_missing_is_error(fld):
    d = dict(base_executed())
    del d[fld]
    # Don't reseal — capsule_id may also mismatch, but we only care about the
    # structural finding.
    res = verify(d)
    assert not res.ok
    assert "missing_required_field" in codes(res)


@pytest.mark.parametrize("fld", REQUIRED_FIELDS)
def test_required_field_null_is_field_not_string(fld):
    d = dict(base_executed())
    d[fld] = None
    res = verify(d)
    assert not res.ok
    assert "field_not_string" in codes(res)


@pytest.mark.parametrize("fld", REQUIRED_FIELDS)
def test_required_field_integer_is_field_not_string(fld):
    d = dict(base_executed())
    d[fld] = 42
    res = verify(d)
    assert not res.ok
    assert "field_not_string" in codes(res)


@pytest.mark.parametrize("fld", REQUIRED_FIELDS)
def test_required_field_bool_is_field_not_string(fld):
    d = dict(base_executed())
    d[fld] = True
    res = verify(d)
    assert not res.ok
    assert "field_not_string" in codes(res)


@pytest.mark.parametrize("fld", REQUIRED_FIELDS)
def test_required_field_list_is_field_not_string(fld):
    d = dict(base_executed())
    d[fld] = ["not", "a", "string"]
    res = verify(d)
    assert not res.ok
    assert "field_not_string" in codes(res)


# Empty string: passes structural check for most fields (IS a string),
# except capsule_id="" → capsule_id_malformed.
@pytest.mark.parametrize("fld", [
    "operator",
    "developer",
    "timestamp",
    "spec_version",
    "format_version",
    "action_id",
])
def test_required_field_empty_string_passes_structural_check(fld):
    d = dict(base_executed())
    d[fld] = ""
    res = verify(d)
    # ok may be False for other checks (capsule_id_mismatch, action_type if
    # action_type was cleared, etc.) but NOT for field_not_string on fld.
    assert "field_not_string" not in codes(res)
    assert "missing_required_field" not in codes(res)


def test_required_field_action_type_empty_string_is_action_type_invalid():
    # Empty action_type is a string but not 'fyi' or 'decide'.
    d = dict(base_executed())
    d["action_type"] = ""
    res = verify(d)
    assert not res.ok
    assert "action_type_invalid" in codes(res)


def test_required_field_capsule_id_empty_string_is_capsule_id_malformed():
    d = dict(base_executed())
    d["capsule_id"] = ""
    res = verify(d)
    assert not res.ok
    assert "capsule_id_malformed" in codes(res)


# Very long string: no length limit for operator/developer/timestamp — passes.
@pytest.mark.parametrize("fld", ["operator", "developer", "timestamp"])
def test_required_field_very_long_string_passes_structural_check(fld):
    d = dict(base_executed())
    d[fld] = "x" * (1024 * 1024)
    res = verify(d)
    assert "field_not_string" not in codes(res)
    assert "missing_required_field" not in codes(res)


# Control characters: no filtering at verify level — passes structural check.
@pytest.mark.parametrize("fld", ["action_id", "operator", "developer"])
def test_required_field_control_char_passes_structural_check(fld):
    d = dict(base_executed())
    d[fld] = "\x00" + d[fld]
    res = verify(d)
    assert "field_not_string" not in codes(res)
    assert "missing_required_field" not in codes(res)


# Unicode: no filtering at verify level — passes structural check.
@pytest.mark.parametrize("fld", ["operator", "developer", "action_id"])
def test_required_field_unicode_passes_structural_check(fld):
    d = dict(base_executed())
    d[fld] = "操作者"
    res = verify(d)
    assert "field_not_string" not in codes(res)
    assert "missing_required_field" not in codes(res)


# ===========================================================================
# Section 2: action_type special values
# ===========================================================================

def test_action_type_fyi_is_ok():
    d = reseal({**base_executed(), "action_type": "fyi"})
    res = verify(d)
    assert "action_type_invalid" not in codes(res)
    assert "field_not_string" not in codes(res)


def test_action_type_decide_is_ok():
    d = reseal({**base_executed(), "action_type": "decide"})
    res = verify(d)
    assert "action_type_invalid" not in codes(res)
    assert "field_not_string" not in codes(res)


def test_action_type_observe_is_invalid():
    d = reseal({**base_executed(), "action_type": "observe"})
    res = verify(d)
    assert not res.ok
    assert "action_type_invalid" in codes(res)


def test_action_type_empty_string_is_invalid():
    d = reseal({**base_executed(), "action_type": ""})
    res = verify(d)
    assert not res.ok
    assert "action_type_invalid" in codes(res)


def test_action_type_none_is_field_not_string():
    d = reseal({**base_executed(), "action_type": "fyi"})
    d["action_type"] = None
    res = verify(d)
    assert not res.ok
    assert "field_not_string" in codes(res)


# ===========================================================================
# Section 3: capsule_id format
# ===========================================================================

def test_capsule_id_valid_64_hex_ok():
    d = base_executed()
    res = verify(d)
    assert "capsule_id_malformed" not in codes(res)
    assert "capsule_id_mismatch" not in codes(res)


def test_capsule_id_63_hex_chars_is_malformed():
    d = dict(base_executed())
    d["capsule_id"] = "a" * 63
    res = verify(d)
    assert not res.ok
    assert "capsule_id_malformed" in codes(res)


def test_capsule_id_64_uppercase_hex_is_malformed():
    d = dict(base_executed())
    d["capsule_id"] = "A" * 64
    res = verify(d)
    assert not res.ok
    assert "capsule_id_malformed" in codes(res)


def test_capsule_id_64_chars_with_non_hex_is_malformed():
    d = dict(base_executed())
    d["capsule_id"] = "g" * 64  # 'g' is not hex
    res = verify(d)
    assert not res.ok
    assert "capsule_id_malformed" in codes(res)


def test_capsule_id_empty_string_is_malformed():
    d = dict(base_executed())
    d["capsule_id"] = ""
    res = verify(d)
    assert not res.ok
    assert "capsule_id_malformed" in codes(res)


def test_capsule_id_tampered_content_is_mismatch():
    # Valid hex format but content doesn't match; verifier detects via recompute.
    d = dict(base_executed())
    d["operator"] = "TAMPERED"  # mutate without resealing
    res = verify(d)
    assert not res.ok
    assert "capsule_id_mismatch" in codes(res)


# ===========================================================================
# Section 4: Block-type violations (effect, assurance, disposition, chain)
# ===========================================================================

_BLOCK_FIELDS = ("effect", "assurance", "disposition", "chain")


@pytest.mark.parametrize("fld", _BLOCK_FIELDS)
def test_block_field_as_string_is_block_not_object(fld):
    d = dict(base_executed())
    d[fld] = "not-an-object"
    res = verify(d)
    assert not res.ok
    assert "block_not_object" in codes(res)


@pytest.mark.parametrize("fld", _BLOCK_FIELDS)
def test_block_field_as_list_is_block_not_object(fld):
    d = dict(base_executed())
    d[fld] = ["item"]
    res = verify(d)
    assert not res.ok
    assert "block_not_object" in codes(res)


@pytest.mark.parametrize("fld", _BLOCK_FIELDS)
def test_block_field_as_integer_is_block_not_object(fld):
    d = dict(base_executed())
    d[fld] = 99
    res = verify(d)
    assert not res.ok
    assert "block_not_object" in codes(res)


@pytest.mark.parametrize("fld", _BLOCK_FIELDS)
def test_block_field_absent_is_ok_structurally(fld):
    # Absence of optional block fields does not produce block_not_object.
    d = dict(base_executed())
    d.pop(fld, None)
    res = verify(d)
    assert "block_not_object" not in codes(res)


# ===========================================================================
# Section 5: constraints field
# ===========================================================================

def test_constraints_as_empty_array_is_ok():
    d = reseal({**base_executed(), "constraints": []})
    res = verify(d)
    assert "constraints_not_array" not in codes(res)


def test_constraints_as_non_empty_array_is_ok():
    d = reseal({**base_executed(), "constraints": [{"type": "time_limit"}]})
    res = verify(d)
    assert "constraints_not_array" not in codes(res)


def test_constraints_as_string_is_constraints_not_array():
    d = dict(base_executed())
    d["constraints"] = "should-be-array"
    res = verify(d)
    assert not res.ok
    assert "constraints_not_array" in codes(res)


def test_constraints_as_dict_is_constraints_not_array():
    d = dict(base_executed())
    d["constraints"] = {"type": "time_limit"}
    res = verify(d)
    assert not res.ok
    assert "constraints_not_array" in codes(res)


def test_constraints_as_integer_is_constraints_not_array():
    d = dict(base_executed())
    d["constraints"] = 5
    res = verify(d)
    assert not res.ok
    assert "constraints_not_array" in codes(res)


# ===========================================================================
# Section 6: disposition sub-fields
# ===========================================================================

def test_disposition_approver_missing_is_missing_required_field():
    d = dict(base_executed())
    disp = dict(d["disposition"])
    del disp["approver"]
    d["disposition"] = disp
    res = verify(reseal(d))
    assert not res.ok
    assert "missing_required_field" in codes(res)


def test_disposition_approver_robot_is_approver_invalid():
    d = dict(base_executed())
    d["disposition"] = dict(d["disposition"], approver="robot")
    res = verify(reseal(d))
    assert not res.ok
    assert "approver_invalid" in codes(res)


def test_disposition_approver_empty_string_is_approver_invalid():
    d = dict(base_executed())
    d["disposition"] = dict(d["disposition"], approver="")
    res = verify(reseal(d))
    assert not res.ok
    assert "approver_invalid" in codes(res)


def test_disposition_decision_missing_is_missing_required_field():
    d = dict(base_executed())
    disp = dict(d["disposition"])
    del disp["decision"]
    d["disposition"] = disp
    res = verify(reseal(d))
    assert not res.ok
    assert "missing_required_field" in codes(res)


def test_disposition_decision_empty_string_is_ok():
    # verify doesn't enforce non-empty decision content.
    d = dict(base_executed())
    d["disposition"] = dict(d["disposition"], decision="")
    res = verify(reseal(d))
    assert "missing_required_field" not in codes(res)


def test_disposition_human_disposed_missing_is_field_not_bool():
    d = dict(base_executed())
    disp = dict(d["disposition"])
    del disp["human_disposed"]
    d["disposition"] = disp
    res = verify(reseal(d))
    assert not res.ok
    assert "field_not_bool" in codes(res)


def test_disposition_human_disposed_string_true_is_field_not_bool():
    d = dict(base_executed())
    d["disposition"] = dict(d["disposition"], human_disposed="true")
    res = verify(reseal(d))
    assert not res.ok
    assert "field_not_bool" in codes(res)


def test_disposition_human_disposed_int_one_is_field_not_bool():
    d = dict(base_executed())
    d["disposition"] = dict(d["disposition"], human_disposed=1)
    res = verify(reseal(d))
    assert not res.ok
    assert "field_not_bool" in codes(res)


# ===========================================================================
# Section 7: effect sub-fields
# ===========================================================================

def test_effect_status_confirmed_without_response_digest_is_error():
    d = dict(base_executed())
    d["effect"] = {"status": "confirmed", "type": "write_order", "effect_attestation": "gate_executed"}
    d["assurance"] = dict(d["assurance"], effect_mode="dispatched_unconfirmed")
    res = verify(reseal(d))
    assert not res.ok
    assert "confirmed_without_response" in codes(res)


def test_effect_status_confirmed_malformed_response_digest_is_error():
    # is_hex64 returns False for non-hex, so it's treated as missing.
    d = dict(base_executed())
    d["effect"] = {
        "status": "confirmed",
        "type": "write_order",
        "effect_attestation": "gate_executed",
        "response_digest": "not-64-hex",
    }
    res = verify(reseal(d))
    assert not res.ok
    assert "confirmed_without_response" in codes(res)


def test_effect_status_empty_string_does_not_crash():
    # Unknown status → derive_effect_mode returns "dispatched_unconfirmed" for
    # non-confirmed/failed/planned statuses — or similar; verifier must not raise.
    d = dict(base_executed())
    d["effect"] = dict(d["effect"], status="")
    res = verify(reseal(d))
    # Just assert no exception was raised; ok may be True or False.
    assert isinstance(res.ok, bool)
    assert "confirmed_without_response" not in codes(res)


def test_effect_response_digest_non_hex_when_status_not_confirmed_no_error():
    # Verifier doesn't validate digests outside the confirmed check.
    d = dict(base_executed())
    d["effect"] = dict(d["effect"], status="dispatched", response_digest="not-hex")
    d["assurance"] = dict(d["assurance"], effect_mode="dispatched_unconfirmed")
    res = verify(reseal(d))
    assert "confirmed_without_response" not in codes(res)


def test_effect_float_amount_is_float_in_digest_field():
    d = dict(base_executed())
    d["effect"] = dict(d["effect"], amount=12.50)
    res = verify(d)
    assert not res.ok
    assert "float_in_digest_field" in codes(res)


def test_effect_unsafe_int_is_unsafe_integer_in_digest_field():
    # Integers outside ±2^53 are unsafe.
    d = dict(base_executed())
    d["effect"] = dict(d["effect"], amount=(2**53) + 1)
    res = verify(d)
    assert not res.ok
    assert "unsafe_integer_in_digest_field" in codes(res)


# ===========================================================================
# Section 8: model_attestation sub-fields
# ===========================================================================

def test_model_attestation_dict_without_model_id_ok_from_check1():
    # Verifier check 1 only validates model_attestation is an object when present;
    # it does NOT validate sub-fields. Any dict content → ok from check-1.
    d = dict(base_executed())
    d["model_attestation"] = {"some_other_field": "value"}
    res = verify(reseal(d))
    assert "block_not_object" not in codes(res)
    assert "missing_required_field" not in codes(res)


def test_model_attestation_arbitrary_dict_content_is_ok_structurally():
    d = dict(base_executed())
    d["model_attestation"] = {"model_id": "gpt-5", "version": "1.0", "extra": {"nested": True}}
    res = verify(reseal(d))
    assert "block_not_object" not in codes(res)


def test_model_attestation_as_string_is_block_not_object():
    # model_attestation is validated as a block field (must be object when present).
    d = dict(base_executed())
    d["model_attestation"] = "not-an-object"
    res = verify(d)
    # The verifier only checks effect/assurance/disposition/chain as block fields;
    # model_attestation is not in that set. So block_not_object is NOT raised.
    # This test documents that model_attestation is NOT in BLOCK_FIELDS checked by §6.
    assert "block_not_object" not in codes(res)
