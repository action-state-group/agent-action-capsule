# SPDX-License-Identifier: BSD-3-Clause
"""A non-string where the verifier expects a string.

The closed-set lookups use a ``frozenset`` or a ``dict``, and a list or an
object is unhashable, so the lookup used to raise and ``verify()`` reported
only ``verifier_internal_error``. Now:

- a string-typed member of disposition, effect, chain or assurance that holds
  any other JSON type fails check 1 with ``field_not_string`` ("REQUIRED
  fields present and typed", §6). The never-reject rule for unregistered
  values (§4, §12) covers well-typed strings only;
- the provenance_mode enums refuse it with ``provenance_mode_invalid``.

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


CONTAINERS = pytest.mark.parametrize(
    "value", [[], {}, ["human"], {"human": 1}, 7, True, None],
    ids=["list", "object", "list-of-member", "object-keyed-by-member", "number", "boolean", "null"],
)


@CONTAINERS
@pytest.mark.parametrize(
    "path",
    [
        ("disposition", "approver"),
        ("disposition", "decision"),
        ("disposition", "verdict_class"),
        ("effect", "status"),
        ("effect", "type"),
        ("effect", "irreversibility_class"),
        ("effect", "effect_attestation"),
        ("effect", "external_ref"),
        ("assurance", "effect_mode"),
        ("assurance", "attestation_mode"),
        ("assurance", "ledger_mode"),
        ("assurance", "cross_party_rung"),
    ],
)
def test_a_non_string_in_a_string_field_fails_check_1(path, value):
    result = verify(_record(path, value))
    assert not result.ok
    if path == ("disposition", "approver") and value is None:
        # A null approver is absent, as it always was.
        assert "missing_required_field" in _codes(result, "error")
        return
    typed = [f for f in result.findings if f.code == "field_not_string"]
    assert [(f.check, f.severity) for f in typed] == [(1, "error")]
    assert ".".join(path) in typed[0].detail
    assert "verifier_internal_error" not in _codes(result, "error")
    # A type error is not an unknown value: check 8 stays silent on it.
    assert "unknown_registry_value" not in _codes(result, "info")


@CONTAINERS
def test_a_non_string_chain_relation_fails_check_1(value):
    capsule = _record(("chain",), {"parent_capsule_id": "a" * 64, "relation": value})
    result = verify(capsule)
    assert not result.ok
    assert "field_not_string" in _codes(result, "error")
    assert "verifier_internal_error" not in _codes(result, "error")


@CONTAINERS
def test_a_non_string_epoch_id_fails_check_1(value):
    result = verify(_record(("epoch_id",), value))
    assert not result.ok
    assert [f.detail for f in result.findings if f.code == "field_not_string"] == [
        "epoch_id MUST be a string when present (§5.1)"
    ]


@CONTAINERS
def test_a_non_string_correlator_fails_check_1_and_derives_no_bilateral_rung(value):
    capsule = _record(
        ("cross_party",),
        {"initiator_ref": "1" * 64, "counterparty_ref": "2" * 64, "correlator": value, "substantive": True},
    )
    result = verify(capsule)
    assert not result.ok
    assert "field_not_string" in _codes(result, "error")
    # Only a non-empty string correlates the two halves, as in Go, TS and Rust.
    assert result.assurance["cross_party_rung"] == "unilateral_fallback"


def test_disposition_authority_is_not_string_typed():
    """§5.4 types authority only as "an opaque reference", not as a string."""
    result = verify(_record(("disposition", "authority"), {"ref": "policy-7"}))
    assert "field_not_string" not in _codes(result, "error")


@pytest.mark.parametrize("value", [[], {}, ["backfilled"]])
def test_a_container_as_provenance_mode_is_invalid_not_a_crash(value):
    result = verify(_record(("provenance_mode", "mode"), value))
    assert not result.ok
    assert "provenance_mode_invalid" in _codes(result, "error")
    assert "verifier_internal_error" not in _codes(result, "error")


def test_an_unregistered_string_is_still_informational():
    """The never-reject rule is unchanged for a well-typed unregistered value."""
    result = verify(_record(("effect", "type"), "x-unregistered"))
    assert result.ok
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
