# SPDX-License-Identifier: BSD-3-Clause
"""verify() does bounded work on hostile numbers (#383, the #381 shape).

A wide array under a long key used to make the walk build a full path for
every member and keep a finding per failing number: about 125 GB for a 1 MB
record. Now a path is written only for a failing number, at most 64 findings
of each number kind are kept, and each quotes at most 256 characters of its
path. The shared fixture pins the same findings for every implementation.
"""
import json
import time
import tracemalloc
from pathlib import Path

import pytest

from agent_action_capsule import FloatInDigestError, UnsafeIntegerError, compute_capsule_id, verify

FIXTURE = Path(__file__).resolve().parents[2] / "vectors" / "cross-language" / "verify-number-findings.json"
NUMBER_CODES = ("float_in_digest_field", "unsafe_integer_in_digest_field")


def number_findings(res):
    return [f for f in res.findings if f.code in NUMBER_CODES]


def test_number_findings_match_the_shared_fixture():
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    found = number_findings(verify(fixture["record"]))
    assert [f.code for f in found] == [e["code"] for e in fixture["expected"]]
    for f, e in zip(found, fixture["expected"]):
        assert _quotes(f.detail, e["path"]), (f.detail, e["path"])


def _quotes(detail, path):
    """``detail`` quotes exactly ``path``: the path ends the detail or a ';' follows it."""
    return detail.endswith(f" at {path}") or f" at {path};" in detail


def _peak_during(fn):
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def _wide_record(value):
    """A well-formed record with 250,000 copies of ``value`` in one array under
    a 500 KB key: a little over 1 MB of JSON. The same shape as Rust's
    ``tests/verify_bounds.rs``."""
    record = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-05",
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": "wide",
        "action_type": "fyi",
        "operator": "op",
        "developer": "dev@v1",
        "timestamp": "2026-09-29T00:00:00Z",
        "model_attestation": {"k" * 500_000: [value] * 250_000},
    }
    try:
        record["capsule_id"] = compute_capsule_id(record)
    except (FloatInDigestError, UnsafeIntegerError):
        record["capsule_id"] = ""
    return record


@pytest.mark.parametrize("value", [0, {}, 0.5, 9007199254740993], ids=["zeros", "objects", "floats", "unsafe"])
def test_wide_array_under_a_long_key_is_bounded(value):
    record = _wide_record(value)
    res = None

    def run():
        nonlocal res
        res = verify(record)

    start = time.monotonic()
    peak = _peak_during(run)
    assert time.monotonic() - start < 30
    # The identity check re-canonicalizes the record (a few MB); the walk adds
    # one entry per level of nesting. Before #383 the floats shape needed
    # about 125 GB.
    assert peak < 32 * 1024 * 1024, peak
    found = number_findings(res)
    if value in (0, {}):
        assert res.ok, res.findings
        assert found == []
        return
    assert not res.ok
    assert len(found) == 64
    assert f" at model_attestation.{'k' * (256 - len('model_attestation.'))}..." in found[0].detail
    assert all(len(f.detail) < 600 for f in found)
