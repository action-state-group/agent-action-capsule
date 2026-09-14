# SPDX-License-Identifier: BSD-3-Clause
import copy
import hashlib

import pytest
from conftest import base_executed

from agent_action_capsule import (
    FloatInDigestError,
    UnsafeIntegerError,
    compute_capsule_id,
    jcs,
    json_digest,
    verify,
)
from agent_action_capsule.canonical import MAX_SAFE_INTEGER

# ---------------------------------------------------------------------------
# 1. Key-order invariance
# ---------------------------------------------------------------------------


def test_key_order_invariance_same_bytes():
    a = {"z": 1, "a": 2, "m": 3}
    b = {"a": 2, "m": 3, "z": 1}
    assert jcs(a) == jcs(b)


def test_key_order_invariance_nested():
    a = {"outer": {"y": 9, "x": 1}}
    b = {"outer": {"x": 1, "y": 9}}
    assert jcs(a) == jcs(b)


# ---------------------------------------------------------------------------
# 2. Whitespace invariance
# ---------------------------------------------------------------------------


def test_jcs_no_whitespace_simple():
    out = jcs({"key": "val", "n": 1})
    assert b" " not in out
    assert b"\n" not in out
    assert b"\t" not in out


def test_jcs_no_whitespace_nested():
    out = jcs({"a": {"b": [1, 2, 3]}, "c": None})
    assert b" " not in out
    assert b"\n" not in out


# ---------------------------------------------------------------------------
# 3. Unicode string escaping — BMP and control chars
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "char, expected_bytes",
    [
        ("\x00", b'"\\u0000"'),
        ("\x08", b'"\\b"'),
        ("\x09", b'"\\t"'),
        ("\x0A", b'"\\n"'),
        ("\x0C", b'"\\f"'),
        ("\x0D", b'"\\r"'),
        ("\\", b'"\\\\"'),
        ('"', b'"\\""'),
        # A BMP char above the control-char range is passed through as UTF-8.
        ("é", "é".encode().join([b'"', b'"'])),
        ("中", "中".encode().join([b'"', b'"'])),
    ],
)
def test_string_escaping(char, expected_bytes):
    assert jcs(char) == expected_bytes


def test_control_chars_in_string_escaped():
    # All control chars below U+0020 (except the named ones) → \u00XX
    out = jcs("\x01\x02\x1f")
    assert out == b'"\\u0001\\u0002\\u001f"'


# ---------------------------------------------------------------------------
# 4. Non-BMP unicode (emoji / surrogate pairs)
# ---------------------------------------------------------------------------


def test_non_bmp_emoji_round_trips():
    s = "\U0001f600"  # 😀
    encoded = jcs(s)
    # Must be valid UTF-8 and start/end with quotes
    assert encoded[0:1] == b'"' and encoded[-1:] == b'"'
    # The content bytes decode back to the original character
    inner = encoded[1:-1].decode("utf-8")
    assert inner == s


def test_non_bmp_in_dict_key_order():
    # Two keys that differ only by a non-BMP codepoint; JCS still serializes deterministically
    d = {"\U0001f600": 1, "\U0001f601": 2}
    out1 = jcs(d)
    out2 = jcs({"\U0001f601": 2, "\U0001f600": 1})
    assert out1 == out2


# ---------------------------------------------------------------------------
# 6. json_digest is deterministic
# ---------------------------------------------------------------------------


def test_json_digest_same_input_same_output():
    v = {"action_id": "x", "operator": "ACME"}
    assert json_digest(v) == json_digest(v)
    assert json_digest(v) == json_digest(copy.deepcopy(v))


def test_json_digest_matches_manual_sha256():
    v = {"z": 1, "a": "x"}
    # JCS sorts → {"a":"x","z":1}
    expected = hashlib.sha256(b'{"a":"x","z":1}').hexdigest()
    assert json_digest(v) == expected


def test_json_digest_commits_present_null():
    assert json_digest({"a": 1, "b": None}) != json_digest({"a": 1})


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 5. capsule_id stability with extra fields / self-exclusion
# ---------------------------------------------------------------------------


def test_capsule_id_excludes_itself():
    body = {"spec_version": "x", "format_version": "4", "canonicalization_id": "jcs", "action_id": "a3"}
    cid1 = compute_capsule_id(body)
    body_with_cid = dict(body)
    body_with_cid["capsule_id"] = cid1
    assert compute_capsule_id(body_with_cid) == cid1


def test_capsule_id_changes_when_content_changes():
    body1 = {"spec_version": "x", "format_version": "4", "canonicalization_id": "jcs", "action_id": "a4"}
    body2 = {"spec_version": "x", "format_version": "4", "canonicalization_id": "jcs", "action_id": "a5"}
    assert compute_capsule_id(body1) != compute_capsule_id(body2)


def test_capsule_id_is_64_lowercase_hex():
    cid = compute_capsule_id({"format_version": "4", "canonicalization_id": "jcs", "action_id": "x"})
    assert len(cid) == 64
    assert cid == cid.lower()
    assert all(c in "0123456789abcdef" for c in cid)


# ---------------------------------------------------------------------------
# 9. Byte-flip → id mismatch → verify INVALID
# ---------------------------------------------------------------------------

_KEY_FIELDS = [
    "spec_version",
    "action_id",
    "action_type",
    "operator",
    "developer",
    "timestamp",
]


def test_flip_format_version_fails_closed():
    cap = base_executed()
    cap["format_version"] = "3"
    result = verify(cap)
    assert not result.ok
    assert "unsupported_format_version" in {f.code for f in result.findings}


@pytest.mark.parametrize("field", _KEY_FIELDS)
def test_flip_field_invalidates_capsule(field):
    cap = base_executed()
    mutated = dict(cap)
    original = cap[field]
    # Flip the field to something different
    mutated[field] = original + "_tampered"
    # capsule_id is now stale — verify must catch the mismatch
    result = verify(mutated)
    assert not result.ok
    codes = {f.code for f in result.findings}
    assert "capsule_id_mismatch" in codes


def test_flip_capsule_id_directly_invalidates():
    cap = base_executed()
    mutated = dict(cap)
    # Replace the last hex nibble
    mutated["capsule_id"] = cap["capsule_id"][:-1] + ("0" if cap["capsule_id"][-1] != "0" else "1")
    result = verify(mutated)
    assert not result.ok
    codes = {f.code for f in result.findings}
    assert "capsule_id_mismatch" in codes


# ---------------------------------------------------------------------------
# 10. MAX_SAFE_INTEGER boundary
# ---------------------------------------------------------------------------


def test_max_safe_integer_accepted():
    assert MAX_SAFE_INTEGER == 9007199254740991
    # Both bounds accepted
    assert json_digest({"n": MAX_SAFE_INTEGER}) == json_digest({"n": MAX_SAFE_INTEGER})
    assert json_digest({"n": -MAX_SAFE_INTEGER})


def test_max_safe_integer_plus_one_rejected():
    with pytest.raises(UnsafeIntegerError):
        json_digest({"n": MAX_SAFE_INTEGER + 1})


def test_max_safe_integer_minus_minus_one_rejected():
    with pytest.raises(UnsafeIntegerError):
        json_digest({"n": -(MAX_SAFE_INTEGER + 1)})


def test_zero_and_one_accepted():
    assert json_digest({"n": 0}) is not None
    assert json_digest({"n": 1}) is not None
    assert json_digest({"n": -1}) is not None


# ---------------------------------------------------------------------------
# 11. Nested floats raise FloatInDigestError
# ---------------------------------------------------------------------------


def test_float_at_top_level_rejected():
    with pytest.raises(FloatInDigestError):
        jcs(1.5)


def test_float_in_dict_value_rejected():
    with pytest.raises(FloatInDigestError):
        json_digest({"amount": 12.5})


def test_float_in_nested_dict_rejected():
    with pytest.raises(FloatInDigestError):
        json_digest({"a": {"b": {"c": 0.1}}})


def test_float_in_list_rejected():
    with pytest.raises(FloatInDigestError):
        json_digest([1, 2, 3.0])


def test_float_in_nested_list_rejected():
    with pytest.raises(FloatInDigestError):
        json_digest({"items": [1, [2, 3.14]]})


# ---------------------------------------------------------------------------
# 12. Nested unsafe ints
# ---------------------------------------------------------------------------


def test_unsafe_int_in_nested_dict_rejected():
    with pytest.raises(UnsafeIntegerError):
        json_digest({"a": {"b": MAX_SAFE_INTEGER + 1}})


def test_unsafe_int_in_array_rejected():
    with pytest.raises(UnsafeIntegerError):
        json_digest({"a": [1, 2, MAX_SAFE_INTEGER + 1]})


def test_unsafe_int_deeply_nested_rejected():
    with pytest.raises(UnsafeIntegerError):
        json_digest({"a": {"b": {"c": [0, -(MAX_SAFE_INTEGER + 1)]}}})


# ---------------------------------------------------------------------------
