# SPDX-License-Identifier: BSD-3-Clause
"""A list or an object where the verifier looks a value up in a closed set.

Those lookups use a ``frozenset`` or a ``dict``, and a list or an object is
unhashable, so the lookup used to raise and ``verify()`` reported only
``verifier_internal_error``. Now each value is looked up as a string only:

- a closed enum refuses it with its own finding (``approver_invalid``,
  ``provenance_mode_invalid``);
- a registry field treats it as any unseeded value: informational, never a
  rejection (§4, §12);
- ``verdict_class`` and the stated assurance modes are simply not members of
  their sets.

In no case is the result ``verifier_internal_error``.
"""
import copy
import json
from pathlib import Path

import pytest

from agent_action_capsule import verify
from agent_action_capsule.canonical import compute_capsule_id

VECTORS = Path(__file__).resolve().parents[2] / "vectors" / "capsule"


def _record(path: tuple[str, ...], value) -> dict:
    """A verifying record with ``value`` placed at ``path``, id recomputed."""
    capsule = json.loads((VECTORS / "pos-executed-confirmed" / "input.json").read_text())
    capsule = copy.deepcopy(capsule)
    target = capsule
    for key in path[:-1]:
        target = target.setdefault(key, {})
    target[path[-1]] = value
    capsule.pop("capsule_id", None)
    capsule["capsule_id"] = compute_capsule_id(capsule)
    return capsule


def _codes(result, severity: str) -> list[str]:
    return [f.code for f in result.findings if f.severity == severity]


def test_the_base_record_verifies():
    assert verify(_record(("action_id",), "closed-set-base")).ok


@pytest.mark.parametrize("value", [[], {}, ["human"], {"human": 1}], ids=["list", "object", "list-of-member", "object-keyed-by-member"])
@pytest.mark.parametrize(
    ("path", "refused_with"),
    [
        (("disposition", "approver"), "approver_invalid"),
        (("provenance_mode", "mode"), "provenance_mode_invalid"),
    ],
)
def test_a_closed_enum_refuses_a_container_with_its_own_finding(path, refused_with, value):
    result = verify(_record(path, value))
    assert not result.ok
    assert refused_with in _codes(result, "error")
    assert "verifier_internal_error" not in _codes(result, "error")


@pytest.mark.parametrize("value", [[], {}])
@pytest.mark.parametrize(
    "path",
    [
        ("disposition", "verdict_class"),
        ("disposition", "decision"),
        ("effect", "type"),
        ("effect", "irreversibility_class"),
        ("effect", "effect_attestation"),
        ("assurance", "effect_mode"),
        ("assurance", "attestation_mode"),
        ("assurance", "ledger_mode"),
        ("assurance", "cross_party_rung"),
    ],
)
def test_a_container_elsewhere_is_judged_like_any_unseeded_value(path, value):
    result = verify(_record(path, value))
    assert "verifier_internal_error" not in _codes(result, "error")
    assert result.ok, result.findings


@pytest.mark.parametrize("value", [[], {}])
def test_a_container_as_chain_relation_is_unseeded_not_a_crash(value):
    capsule = _record(("chain",), {"parent_capsule_id": "a" * 64, "relation": value})
    result = verify(capsule)
    assert "verifier_internal_error" not in _codes(result, "error")
    assert "unknown_registry_value" in _codes(result, "info")


@pytest.mark.parametrize("value", [[], {}])
def test_a_container_as_time_rung_is_invalid_not_a_crash(value):
    capsule = _record(
        ("provenance_mode",),
        {
            "mode": "backfilled",
            "source_ref": {"type": "t", "digest_alg": "SHA-256", "digest": "d"},
            "source_asserted_at": "2026-01-01T00:00:00Z",
            "import_batch": "b",
            "imported_at": "2026-01-02T00:00:00Z",
            "time_rung": value,
        },
    )
    result = verify(capsule)
    assert "verifier_internal_error" not in _codes(result, "error")
    assert "provenance_mode_invalid" in _codes(result, "error")


def test_a_registry_value_that_is_a_number_is_still_unseeded():
    """Unchanged behaviour: a hashable non-string was always unseeded."""
    result = verify(_record(("effect", "type"), 7))
    assert result.ok
    assert "unknown_registry_value" in _codes(result, "info")
