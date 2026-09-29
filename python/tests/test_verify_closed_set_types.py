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


@CONTAINERS
@pytest.mark.parametrize("member", ["source_asserted_at", "import_batch", "imported_at"])
def test_a_non_string_provenance_field_fails_check_1(member, value):
    provenance_mode = {
        "mode": "backfilled",
        "source_ref": {"type": "t", "digest_alg": "SHA-256", "digest": "d"},
        "source_asserted_at": "2026-01-01T00:00:00Z",
        "import_batch": "b",
        "imported_at": "2026-01-02T00:00:00Z",
        member: value,
    }
    result = verify(_record(("provenance_mode",), provenance_mode))
    assert not result.ok
    typed = [f for f in result.findings if f.code == "field_not_string"]
    assert [(f.check, f.detail) for f in typed] == [
        (1, f"provenance_mode.{member} MUST be a string when present (§6 check 1)")
    ]


@CONTAINERS
@pytest.mark.parametrize("member", ["declarant", "retained_until", "not_retained_after"])
def test_a_non_string_retention_field_fails_check_1(member, value):
    if member == "declarant" and value is None:
        pytest.skip("a null declarant is missing: test_an_absent_or_null_declarant_is_missing")
    retention = {"declarant": "ACME-CO", "retained_until": "2027-01-01T00:00:00Z", member: value}
    reference = {"type": "x-artifact", "digest_alg": "SHA-256", "digest": "3" * 64}
    result = verify(_record(("references",), [reference, {**reference, "retention": retention}]))
    assert not result.ok
    typed = [f for f in result.findings if f.code == "field_not_string"]
    assert [(f.check, f.detail) for f in typed] == [
        (1, f"references[1].retention.{member} MUST be a string when present (§5.5.5)")
    ]


def _retention(retention):
    reference = {"type": "x-artifact", "digest_alg": "SHA-256", "digest": "3" * 64}
    return verify(_record(("references",), [reference, {**reference, "retention": retention}]))


def _check_1(result):
    return [(f.code, f.detail) for f in result.findings if f.check == 1 and f.severity == "error"]


@pytest.mark.parametrize("value", [[], "2027", 7, True, None], ids=["list", "string", "number", "boolean", "null"])
def test_a_non_object_retention_fails_check_1(value):
    result = _retention(value)
    assert not result.ok
    assert _check_1(result) == [("field_not_object", "references[1].retention MUST be a JSON object when present (§5.5.5)")]


@pytest.mark.parametrize("retention", [{"retained_until": "2027"}, {"declarant": None, "not_retained_after": "2027"}],
                         ids=["absent", "null"])
def test_an_absent_or_null_declarant_is_missing(retention):
    result = _retention(retention)
    assert not result.ok
    assert _check_1(result) == [("missing_required_field", "references[1].retention.declarant is REQUIRED (§5.5.5)")]


def test_a_retention_with_no_bound_is_empty():
    result = _retention({"declarant": "ACME-CO"})
    assert not result.ok
    assert _check_1(result) == [
        ("retention_empty", "references[1].retention MUST carry retained_until or not_retained_after (§5.5.5)")
    ]


def test_retention_findings_come_in_a_fixed_order():
    result = _retention({"declarant": None})
    assert [code for code, _ in _check_1(result)] == ["missing_required_field", "retention_empty"]


@pytest.mark.parametrize(
    "retention",
    [
        {"declarant": "ACME-CO", "retained_until": "2027-01-01T00:00:00Z"},
        {"declarant": "ACME-CO", "not_retained_after": "2030-01-01T00:00:00Z"},
        {"declarant": "ACME-CO", "retained_until": "2027-01-01T00:00:00Z", "not_retained_after": "2030-01-01T00:00:00Z"},
    ],
    ids=["floor", "ceiling", "window"],
)
def test_a_well_formed_retention_passes(retention):
    assert _retention(retention).ok

