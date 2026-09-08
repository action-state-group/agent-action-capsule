# SPDX-License-Identifier: BSD-3-Clause
"""draft-04 §5.5.5 ``references[]`` — cross-record references.

Two surfaces:
  - the CONSUMER path (verify.py): the 25 shared vectors in
    ``go/verify/testdata/references.json`` are the cross-language oracle for
    ``ok``/finding-codes, replayed here exactly as the Go suite replays them
    (same store, same check-order assertion) so Python and Go agree
    byte-for-byte on every case.
  - the PRODUCER path (contracts.py/parse.py/emit.py): the typed builder,
    Capsule.to_dict()/seal(), and the strict parse_capsule round-trip, with
    absent vs. empty vs. populated ``references`` kept as three DISTINCT wire
    forms (and therefore three distinct capsule_id digests).
"""
import json
from pathlib import Path

import pytest
from conftest import HEX_A, HEX_B, base_executed

from agent_action_capsule import (
    AssuranceBlock,
    Capsule,
    Chain,
    InvariantError,
    LogCoordinates,
    ReferenceEntry,
    emit,
    jcs,
    load_registries,
    parse_capsule,
    verify,
)

# python/tests -> python -> repo root
_REPO_ROOT = Path(__file__).resolve().parents[2]
_VECTORS_PATH = _REPO_ROOT / "go" / "verify" / "testdata" / "references.json"

with _VECTORS_PATH.open(encoding="utf-8") as f:
    _VECTORS = json.load(f)

CASES = _VECTORS["cases"]
assert len(CASES) == 25, f"expected the 25 shared reference vectors, found {len(CASES)}"


def _codes(res):
    return [f.code for f in res.findings]


# ---- The 25 shared cross-language vectors -----------------------------------
@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_reference_vectors(case):
    # The chain parent (HEX_A) exists in the store; external references
    # deliberately do not — mirrors go/verify/references_test.go exactly.
    result = verify(case["capsule"], store=[HEX_A])
    assert result.ok == case["ok"], result.findings
    assert _codes(result) == case["codes"]
    assert jcs(case["capsule"]).decode() == case["canonical"]


def test_future_purpose_resolves_with_a_caller_supplied_registry():
    case = next(c for c in CASES if c["name"] == "future-purpose")
    regs = dict(load_registries())
    regs["citation_purpose"] = frozenset(regs["citation_purpose"] | {"example-purpose"})
    result = verify(case["capsule"], store=[HEX_A], registries=regs)
    assert result.ok
    assert result.findings == []


def test_reference_findings_follow_check_order():
    """References must not move check 6/8 diagnostics ahead of structural
    errors (mirrors go/verify/references_test.go
    TestReferenceFindingsFollowCheckOrder)."""
    capsule = dict(base_executed())
    capsule["format_version"] = "4"
    capsule["canonicalization_id"] = "jcs"
    del capsule["operator"]
    capsule["chain"] = {"parent_capsule_id": HEX_A, "relation": "confirms"}
    capsule["references"] = [
        {"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": HEX_A, "citation_purpose": "future-purpose"},
    ]
    result = verify(capsule)
    last = 0
    for finding in result.findings:
        if finding.check is not None:
            assert finding.check >= last
            last = finding.check
    codes = _codes(result)
    assert "missing_required_field" in codes
    assert "reference_duplicates_chain_parent" in codes
    assert "unknown_registry_value" in codes


# ---- Producer path: absent vs. empty vs. populated --------------------------
def _sealed(**kwargs) -> dict:
    return Capsule(
        spec_version="draft-mih-scitt-agent-action-capsule-04",
        format_version="4",
        canonicalization_id="jcs",
        action_id="ref-1",
        action_type="fyi",
        operator="ACME-CO",
        developer="agent@v1",
        timestamp="2026-09-08T00:00:00Z",
        assurance=AssuranceBlock(
            attestation_mode="self_attested", effect_mode="not_applicable", ledger_mode="standalone"
        ),
        **kwargs,
    ).seal()


def test_absent_references_key_omitted():
    sealed = _sealed()
    assert "references" not in sealed


def test_empty_references_emits_empty_array():
    sealed = _sealed(references=())
    assert sealed["references"] == []


def test_absent_and_empty_are_distinct_capsule_ids():
    absent = _sealed()
    empty = _sealed(references=())
    assert absent["capsule_id"] != empty["capsule_id"]


def test_populated_references_round_trip_through_to_dict_and_parse():
    entry = ReferenceEntry(type="agent-action-capsule", digest_alg="SHA-256", digest=HEX_B, citation_purpose="acted_on")
    sealed = _sealed(references=(entry,))
    assert sealed["references"] == [
        {"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": HEX_B, "citation_purpose": "acted_on"}
    ]

    parsed = parse_capsule(sealed)
    assert parsed.references == (entry,)
    assert parsed.to_dict()["references"] == sealed["references"]


def test_log_coordinates_round_trip():
    entry = ReferenceEntry(
        type="foreign-artifact", digest_alg="opaque", digest="opaque-digest",
        log_coordinates=LogCoordinates(log_id="example-log", leaf_index=3, inclusion_proof={"future-format": "unverified"}),
    )
    sealed = _sealed(references=(entry,))
    assert sealed["references"][0]["log_coordinates"] == {
        "log_id": "example-log", "leaf_index": 3, "inclusion_proof": {"future-format": "unverified"}
    }
    parsed = parse_capsule(sealed)
    assert parsed.references[0].log_coordinates == entry.log_coordinates
    res = verify(sealed)
    assert res.ok


def test_parse_capsule_preserves_absent_vs_empty():
    absent = parse_capsule(_sealed())
    empty = parse_capsule(_sealed(references=()))
    assert absent.references is None
    assert empty.references == ()
    assert "references" not in absent.to_dict()
    assert empty.to_dict()["references"] == []


# ---- Producer-side invariants (mirror the verifier's structural checks) ----
def test_reference_entry_rejects_empty_type():
    with pytest.raises(InvariantError):
        ReferenceEntry(type="", digest_alg="SHA-256", digest=HEX_A)


def test_reference_entry_requires_hex64_for_aac_self_identity():
    with pytest.raises(InvariantError):
        ReferenceEntry(type="agent-action-capsule", digest_alg="SHA-256", digest="not-hex")


def test_reference_entry_foreign_type_digest_stays_open():
    # A foreign type/algorithm combination is never constrained to hex64 —
    # CPB owns digest representation and comparison context for it.
    ReferenceEntry(type="foreign-artifact", digest_alg="future-hash", digest="opaque-digest")


def test_reference_entry_rejects_empty_citation_purpose():
    with pytest.raises(InvariantError):
        ReferenceEntry(type="agent-action-capsule", digest_alg="SHA-256", digest=HEX_A, citation_purpose="")


def test_reference_entry_does_not_enum_check_citation_purpose():
    # Registry-governed and open: an unseeded value builds fine (verify()
    # reports it as informational, never a producer-side rejection).
    ReferenceEntry(type="agent-action-capsule", digest_alg="SHA-256", digest=HEX_A, citation_purpose="a-future-purpose")


def test_log_coordinates_requires_all_three_members():
    with pytest.raises(InvariantError):
        LogCoordinates(log_id="l", leaf_index=0, inclusion_proof=None)


def test_capsule_rejects_reference_duplicating_chain_parent():
    with pytest.raises(InvariantError):
        _sealed(
            chain=Chain(parent_capsule_id=HEX_A, relation="confirms"),
            references=(ReferenceEntry(type="agent-action-capsule", digest_alg="SHA-256", digest=HEX_A),),
        )


def test_capsule_allows_reference_matching_parent_digest_under_a_different_type():
    # The boundary rule is scoped to the agent-action-capsule/SHA-256 self-
    # identity context only — a same-hex value under a foreign type/alg is not
    # a chain-parent duplicate.
    sealed = _sealed(
        chain=Chain(parent_capsule_id=HEX_A, relation="confirms"),
        references=(ReferenceEntry(type="foreign-artifact", digest_alg="SHA-256", digest=HEX_A),),
    )
    assert sealed["references"][0]["digest"] == HEX_A


# ---- emit() convenience builder ---------------------------------------------
def test_emit_omits_references_by_default():
    cap = emit(action_id="emit-ref-1", operator="op", developer="dev@v1")
    assert "references" not in cap
    assert verify(cap).ok


def test_emit_with_references():
    cap = emit(
        action_id="emit-ref-2", operator="op", developer="dev@v1",
        references=(ReferenceEntry(type="agent-action-capsule", digest_alg="SHA-256", digest=HEX_B, citation_purpose="responds_to"),),
    )
    assert cap["references"] == [
        {"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": HEX_B, "citation_purpose": "responds_to"}
    ]
    result = verify(cap)
    assert result.ok
