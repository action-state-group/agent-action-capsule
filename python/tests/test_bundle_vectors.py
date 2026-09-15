# SPDX-License-Identifier: BSD-3-Clause
"""Exercise the shared Evidence Bundle outcome matrix with real CLL proofs."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_action_capsule.bundle import decode_fragment, encode_fragment, verify_bundle
from agent_action_capsule.canonical import compute_capsule_id, json_digest

cll = pytest.importorskip("cll.checkpoint")
from cll.checkpoint import core  # noqa: E402  (imported after importorskip guard)
from cll.checkpoint.store import MemoryNodeStore  # noqa: E402

VECTORS = Path(__file__).resolve().parents[2] / "vectors/bundle"
MANIFEST = json.loads((VECTORS / "vectors.json").read_text())


def _capsule(number, *, output=None, input_=None, chain=None):
    capsule = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-04", "format_version": "4",
        "canonicalization_id": "jcs", "action_id": f"bundle-{number}", "action_type": "decide",
        "operator": "ACME-CO", "developer": "agent@v1", "timestamp": f"2026-09-14T00:00:0{number}Z",
        "assurance": {"effect_mode": "not_applicable", "attestation_mode": "self_attested", "ledger_mode": "standalone"},
        "disposition": {"verdict_class": "blocked", "decision": "reject", "approver": "policy", "human_disposed": False},
    }
    if output is not None:
        capsule["model_attestation"] = {"compute_attestation": {"agent_output_digest": json_digest(output)}}
    if input_ is not None:
        capsule.setdefault("model_attestation", {"compute_attestation": {}})["compute_attestation"]["agent_input_digest"] = json_digest(input_)
    if chain is not None:
        capsule["chain"] = chain
    capsule["capsule_id"] = compute_capsule_id(capsule)
    return capsule


def _proof(p):
    return {"v": p.v, "kind": p.kind, "size": p.size, "leaf_index": p.leaf_index, "witness": list(p.witness), "peaks_left": list(p.peaks_left), "peaks_right": list(p.peaks_right)}


def _bundle(records, root, disclosures=None, missing=None):
    nodes = MemoryNodeStore()
    for record in records:
        core.add_leaf(nodes, core.leaf_hash(bytes.fromhex(record["capsule_id"])))
    size = nodes.size()
    root_hash = core.root_from_peaks([nodes.node(pos) for pos in core.peaks(size)])
    proofs = [core.inclusion_proof(nodes, index, size) for index in range(len(records))]
    certificate = {
        "log_id": "bundle-log", "range_root": root_hash.hex(), "first_seq": 1, "last_seq": len(records),
        "first_digest": records[0]["capsule_id"], "last_digest": records[-1]["capsule_id"],
        "range_proof": {"from_seq": 1, "to_seq": len(records), "size": size, "inclusion_from": _proof(proofs[0]), "inclusion_to": _proof(proofs[-1])},
        "memberships": {record["capsule_id"]: {"log_coordinates": {"log_id": "bundle-log", "seq": index + 1, "leaf_index": index}, "inclusion_proof": _proof(proofs[index])} for index, record in enumerate(records)},
    }
    return {"bundle_version": "2", "bundle_kind": "evidence-bundle/v2", "root": root["capsule_id"], "records": records,
            "completeness": {"closure_depth": 2, "records_mode": "declared_incomplete" if missing else "complete", "payloads_mode": "selected", "suppressed_fields": ["agent_input"], "missing": missing or []},
            "disclosures": disclosures or {}, "completeness_certificate": certificate, "checkpoint": {"root": root_hash.hex(), "mmr_size": size},
            "extensions": {"example/unimplemented": {"note": "digest-covered only"}}}


def _case(name):
    output = {"answer": {"steps": ["check", "approve"], "total": "42"}}
    input_ = {"request": {"account": "A-17", "amount": "42.00"}}
    first, middle, root = _capsule(1, output=output), _capsule(2, input_=input_), _capsule(3)
    bundle = _bundle([first, middle, root], root, {first["capsule_id"]: {"agent_output": output}})
    if name == "neg-deleted-interior-record":
        bundle["records"] = [first, root]
        bundle["completeness_certificate"]["memberships"].pop(middle["capsule_id"])
    elif name == "neg-replaced-interior-record":
        replacement = _capsule(9, input_=input_)
        proof = bundle["completeness_certificate"]["memberships"].pop(middle["capsule_id"])
        bundle["records"] = [first, replacement, root]
        bundle["completeness_certificate"]["memberships"][replacement["capsule_id"]] = proof
    elif name in {"neg-dangling-citation", "pos-declared-missing-citation"}:
        absent = "f" * 64
        cited_root = _capsule(4, chain={"parent_capsule_id": absent, "relation": "derived_from"})
        bundle = _bundle([first, middle, cited_root], cited_root, missing=[absent] if name.startswith("pos-") else None)
    elif name == "neg-disclosure-mismatch-nested-match":
        bundle["disclosures"][middle["capsule_id"]] = {"agent_input": {"request": {"account": "A-17", "amount": "99.00"}}}
    elif name == "neg-supplied-record-unbound":
        bundle["records"].append(_capsule(9))
    elif name == "neg-membership-proof-coordinate-mismatch":
        bundle["completeness_certificate"]["memberships"][middle["capsule_id"]]["inclusion_proof"]["leaf_index"] = 0
    elif name == "pos-default-completeness-values":
        bundle["completeness"].pop("closure_depth")
        bundle["completeness"].pop("missing")
    elif name == "neg-portable-proof-version-kind":
        proof = bundle["completeness_certificate"]["memberships"][middle["capsule_id"]]["inclusion_proof"]
        proof["v"] = 2
        proof["kind"] = "not-inclusion"
    elif name == "neg-boolean-proof-integer":
        bundle["completeness_certificate"]["memberships"][middle["capsule_id"]]["inclusion_proof"]["v"] = True
    return bundle


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda c: c["name"])
def test_bundle_vector(case):
    bundle = _case(case["name"])
    assert decode_fragment(encode_fragment(bundle)) == bundle
    result = verify_bundle(bundle)
    expected = case["expected"]
    assert result.graph_closure.status == expected["graph_closure"]
    assert result.interval_coverage.status == expected["interval_coverage"]
    assert result.per_record_membership.status == expected["per_record_membership"]
    if "interval_findings" in expected:
        assert sorted(result.interval_coverage.findings) == sorted(expected["interval_findings"])
    if "membership_findings" in expected:
        assert sorted(result.per_record_membership.findings) == sorted(expected["membership_findings"])
    if "disclosures" in expected:
        assert sorted(item.status for item in result.disclosures) == sorted(expected["disclosures"])


def test_malformed_missing_does_not_crash():
    # Non-string completeness.missing entries (e.g. an object) must not raise
    # while binding memberships; they simply do not count as declared-missing ids.
    bundle = _case("pos-declared-missing-citation")
    for junk in ([{}, 7, None], None, "not-a-list", 5):
        bundle["completeness"]["missing"] = junk
        result = verify_bundle(bundle)  # must not raise for non-list or non-string entries
        assert result.per_record_membership.status in {"pass", "fail"}


def test_transport_only_decode_and_reserved_reporting():
    assert decode_fragment(encode_fragment(None)) is None
    result = verify_bundle({"countersignatures": ["reserved"], "verification": {"producer": "claimed"}})
    assert result.countersignatures[0].status == "unverified"
    assert result.countersignatures[0].value == "reserved"
    assert result.verification is not None
    assert result.verification.status == "producer_self_report"
