# SPDX-License-Identifier: BSD-3-Clause
"""§2 JSON-DIGEST + §5.1 capsule_id."""
import hashlib

import pytest

from agent_action_capsule import compute_capsule_id, jcs, json_digest, normalize
from agent_action_capsule.canonical import (
    MAX_SAFE_INTEGER,
    FloatInDigestError,
    UnsafeIntegerError,
)


def test_normalize_removes_null_empty_bottom_up():
    v = {"a": 1, "b": None, "c": [], "d": {}, "e": {"x": None}, "f": {"y": 2}}
    # b(null), c([]), d({}) removed; e becomes {} after x removed -> e removed.
    assert normalize(v) == {"a": 1, "f": {"y": 2}}


def test_jcs_sorts_keys_and_has_no_whitespace():
    assert jcs({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert jcs([1, "x", True, None]) == b'[1,"x",true,null]'


def test_jcs_string_escaping():
    assert jcs("a\"b\\c\n\t") == b'"a\\"b\\\\c\\n\\t"'


def test_json_digest_matches_manual():
    v = {"z": 1, "a": "x"}
    expected = hashlib.sha256(b'{"a":"x","z":1}').hexdigest()
    assert json_digest(v) == expected


def test_json_digest_normalizes_before_hashing():
    assert json_digest({"a": 1, "b": None}) == json_digest({"a": 1})


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


def test_capsule_id_excludes_capsule_id_and_chain():
    body = {"spec_version": "x", "format_version": "2", "action_id": "a"}
    cid = compute_capsule_id(body)
    # Adding capsule_id and a chain block must NOT change the content-address.
    with_extras = dict(body)
    with_extras["capsule_id"] = cid
    with_extras["chain"] = {"parent_capsule_id": "b" * 64, "relation": "supersedes"}
    assert compute_capsule_id(with_extras) == cid


def test_capsule_id_is_64_lowercase_hex():
    cid = compute_capsule_id({"action_id": "a"})
    assert len(cid) == 64 and cid == cid.lower() and all(c in "0123456789abcdef" for c in cid)
