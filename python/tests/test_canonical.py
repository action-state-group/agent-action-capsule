# SPDX-License-Identifier: BSD-3-Clause
"""§2 JSON-DIGEST + §5.1 capsule_id."""
import hashlib

import pytest

from agent_action_capsule import compute_capsule_id, jcs, json_digest
from agent_action_capsule.canonical import (
    MAX_SAFE_INTEGER,
    FloatInDigestError,
    UnsafeIntegerError,
)


def test_jcs_sorts_keys_and_has_no_whitespace():
    assert jcs({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert jcs([1, "x", True, None]) == b'[1,"x",true,null]'


def test_jcs_string_escaping():
    assert jcs("a\"b\\c\n\t") == b'"a\\"b\\\\c\\n\\t"'


def test_json_digest_matches_manual():
    v = {"z": 1, "a": "x"}
    expected = hashlib.sha256(b'{"a":"x","z":1}').hexdigest()
    assert json_digest(v) == expected


def test_json_digest_commits_null_and_empty_values():
    assert json_digest({"a": 1, "b": None}) != json_digest({"a": 1})
    assert json_digest({"a": 1, "b": []}) != json_digest({"a": 1})


def test_float_is_rejected():
    with pytest.raises(FloatInDigestError):
        json_digest({"amount": 12.50})


def test_max_safe_integer_is_accepted():
    # 2^53 - 1 round-trips through an ECMAScript Number, so it is digest-safe.
    assert MAX_SAFE_INTEGER == 9007199254740991
    assert json_digest({"n": MAX_SAFE_INTEGER}) == json_digest({"n": MAX_SAFE_INTEGER})
    assert json_digest({"n": -MAX_SAFE_INTEGER})  # negative bound accepted too


def test_unsafe_integer_is_rejected_both_signs():
    # Just over the JS-safe range in a digest-bearing position -> rejected, rather
    # than emit a digest an ECMAScript-Number-based reader could not reproduce.
    with pytest.raises(UnsafeIntegerError):
        json_digest({"n": MAX_SAFE_INTEGER + 1})
    with pytest.raises(UnsafeIntegerError):
        json_digest({"n": -(MAX_SAFE_INTEGER + 1)})


def test_unsafe_integer_nested_is_rejected():
    with pytest.raises(UnsafeIntegerError):
        json_digest({"a": {"b": [1, 2, MAX_SAFE_INTEGER + 1]}})


def test_declared_jcs_capsule_id_commits_chain_and_absent_fields():
    body = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-04",
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": "a",
        "chain": {"parent_capsule_id": "b" * 64, "relation": "sequence"},
        "optional": None,
    }
    cid = compute_capsule_id(body)

    changed_chain = dict(body)
    changed_chain["chain"] = dict(body["chain"], relation="supersedes")
    assert compute_capsule_id(changed_chain) != cid

    absent_optional = dict(body)
    absent_optional.pop("optional")
    assert compute_capsule_id(absent_optional) != cid


@pytest.mark.parametrize("declaration", ["jcs-n", "future-algorithm", "", None, 7])
def test_capsule_id_rejects_invalid_declaration(declaration):
    with pytest.raises((TypeError, ValueError)):
        compute_capsule_id({"format_version": "4", "canonicalization_id": declaration})


@pytest.mark.parametrize("capsule", [
    {},
    {"format_version": "2"},
    {"format_version": "4"},
])
def test_capsule_id_rejects_non_format_4_profiles(capsule):
    with pytest.raises(ValueError):
        compute_capsule_id(capsule)


def test_capsule_id_is_64_lowercase_hex():
    cid = compute_capsule_id({"format_version": "4", "canonicalization_id": "jcs", "action_id": "a"})
    assert len(cid) == 64 and cid == cid.lower() and all(c in "0123456789abcdef" for c in cid)
