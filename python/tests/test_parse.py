# SPDX-License-Identifier: BSD-3-Clause
"""Strict producer/round-trip path (parse.py).

`parse_capsule` is the strict counterpart to `verify()`: it RAISES InvariantError
on a non-conforming Capsule rather than reporting findings. These tests lock the
three parse hardenings:

  (a) a present-but-wrong-typed sub-block is REJECTED, never silently dropped;
  (b) a disposition missing REQUIRED decision / human_disposed is REJECTED;
  (c) a malformed input that previously leaked a bare TypeError now surfaces as a
      structured InvariantError.

The verifier (test_verify.py) reports these same conditions as findings over
arbitrary bytes; here we assert the strict path refuses to build.
"""
import pytest

from agent_action_capsule import parse_capsule
from agent_action_capsule.contracts import InvariantError

BASE = {
    "spec_version": "draft-mih-scitt-agent-action-capsule-00",
    "format_version": "2",
    "action_id": "a",
    "action_type": "decide",
    "operator": "o",
    "developer": "d",
    "timestamp": "2026-01-01T00:00:00Z",
}


def _parse(**extra):
    return parse_capsule({**BASE, **extra})


# (a) present-but-wrong-typed blocks -> rejected, not silently dropped ---------
@pytest.mark.parametrize("block,bad", [
    ("effect", "garbage"),
    ("effect", ["not", "an", "object"]),
    ("disposition", ["x"]),
    ("disposition", "nope"),
    ("assurance", 7),
    ("chain", "nope"),
])
def test_wrong_typed_block_is_rejected_not_dropped(block, bad):
    with pytest.raises(InvariantError):
        _parse(**{block: bad})


def test_constraints_must_be_array_and_objects():
    with pytest.raises(InvariantError):
        _parse(constraints="x")
    with pytest.raises(InvariantError):
        _parse(constraints=[{"id": "c1", "result": "pass"}, "not-an-object"])


# (b) missing REQUIRED disposition members -> rejected -------------------------
def test_disposition_requires_decision():
    with pytest.raises(InvariantError):
        _parse(disposition={"approver": "human", "human_disposed": False})


def test_disposition_requires_human_disposed():
    with pytest.raises(InvariantError):
        _parse(disposition={"approver": "human", "decision": "accept"})


# (c) missing effect.status -> structured InvariantError, never a bare TypeError
def test_effect_missing_status_is_invariant_error_not_typeerror():
    with pytest.raises(InvariantError):
        _parse(effect={"type": "write_order"})


# sanity: a conforming Capsule still parses cleanly ---------------------------
def test_valid_capsule_round_trips():
    cap = _parse(
        disposition={"approver": "human", "decision": "accept", "human_disposed": True},
        effect={
            "status": "confirmed",
            "type": "write_order",
            "response_digest": "1" * 64,
            "effect_attestation": "runtime_claimed",
        },
    )
    assert cap.disposition.decision == "accept"
    assert cap.effect.status == "confirmed"
