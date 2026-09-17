# SPDX-License-Identifier: BSD-3-Clause
"""Exercise the shared Evidence Bundle outcome matrix with real CLL proofs.

``agent_action_capsule.bundle`` is now a deprecated shim over
``capsule_emit.evidence_bundle`` ([evidence-bundle-codec-to-capsule-emit]);
this file exercises that shim end-to-end (real CLL proof data, not the
codec's own unit tests, which now live in capsule-emit's
``tests/test_evidence_bundle.py``). ``capsule-emit`` is intentionally not in
this package's own dependencies (kept stdlib-only), so this file is skipped
rather than failing in a plain aac dev environment that doesn't have it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("capsule_emit.evidence_bundle")

from agent_action_capsule.bundle import decode_fragment, encode_fragment, verify_bundle  # noqa: E402
from agent_action_capsule.canonical import compute_capsule_id, json_digest  # noqa: E402

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
    # CLL #13 flat range proof over the whole interval — every leaf participates.
    range_p = core.range_proof(nodes, 0, len(records) - 1, size)
    certificate = {
        "log_id": "bundle-log", "range_root": root_hash.hex(), "first_seq": 1, "last_seq": len(records),
        "body_digests": [record["capsule_id"] for record in records],
        "range_proof": {"from_seq": 1, "to_seq": len(records), "size": size, "from_index": range_p.from_index, "to_index": range_p.to_index, "witness": list(range_p.witness)},
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
    elif name == "neg-interval-body-digest-altered":
        # A well-formed (32-byte) but wrong interior body digest: it passes the
        # length/hex guards yet cannot rebuild the range root, so the every-leaf
        # binding (not just the two endpoints) must reject it.
        bundle["completeness_certificate"]["body_digests"][1] = "aa" * 32
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


def test_interval_coverage_rejects_altered_interior_body_digest():
    # CLL #13 every-leaf binding, Python-only for now: a well-formed but wrong
    # interior body digest must fail interval coverage. This stays out of the
    # shared cross-language manifest because Go/TS still verify the endpoint-
    # boundary shape and would report interval_coverage: pass here — so it would
    # break their conformance rather than guard anything. Pinned here so a
    # _verify_range that ignored body_digests could not pass silently.
    bundle = _case("neg-interval-body-digest-altered")
    result = verify_bundle(bundle)
    assert result.interval_coverage.status == "fail"
    assert "range_proof_invalid" in result.interval_coverage.findings


def test_malformed_missing_does_not_crash():
    # Non-string completeness.missing entries (e.g. an object) must not raise
    # while binding memberships; they simply do not count as declared-missing ids.
    bundle = _case("pos-declared-missing-citation")
    for junk in ([{}, 7, None], None, "not-a-list", 5):
        bundle["completeness"]["missing"] = junk
        result = verify_bundle(bundle)  # must not raise for non-list or non-string entries
        assert result.per_record_membership.status in {"pass", "fail"}


def test_interval_rejects_sub_tip_range():
    # F1 regression: the interval must end at the checkpoint tip
    # (leaf_count(size) == last_seq). A sub-tip range — here [1,3] proved against
    # a 4-leaf tree (size 7) — has a valid core range proof and root, so without
    # the tip bind it verifies; records after last_seq could then be silently
    # omitted. All languages must reject it with range_proof_invalid.
    caps = [_capsule(i) for i in range(1, 5)]
    nodes = MemoryNodeStore()
    for capsule in caps:
        core.add_leaf(nodes, core.leaf_hash(bytes.fromhex(capsule["capsule_id"])))
    size = nodes.size()
    root_hash = core.root_from_peaks([nodes.node(pos) for pos in core.peaks(size)])
    proofs = [core.inclusion_proof(nodes, index, size) for index in range(3)]
    rp = core.range_proof(nodes, 0, 2, size)
    records = caps[:3]
    bundle = {
        "bundle_version": "2", "bundle_kind": "evidence-bundle/v2", "root": records[-1]["capsule_id"],
        "records": records, "completeness": {"records_mode": "complete", "missing": []},
        "completeness_certificate": {
            "log_id": "bundle-log", "range_root": root_hash.hex(), "first_seq": 1, "last_seq": 3,
            "body_digests": [r["capsule_id"] for r in records],
            "range_proof": {"from_seq": 1, "to_seq": 3, "size": size, "from_index": rp.from_index, "to_index": rp.to_index, "witness": list(rp.witness)},
            "memberships": {r["capsule_id"]: {"log_coordinates": {"log_id": "bundle-log", "seq": i + 1, "leaf_index": i}, "inclusion_proof": _proof(proofs[i])} for i, r in enumerate(records)},
        },
        "checkpoint": {"root": root_hash.hex(), "mmr_size": size},
    }
    result = verify_bundle(bundle)
    assert result.interval_coverage.status == "fail", result.interval_coverage
    assert "range_proof_invalid" in result.interval_coverage.findings


def test_transport_only_decode_and_reserved_reporting():
    assert decode_fragment(encode_fragment(None)) is None
    result = verify_bundle({"countersignatures": ["reserved"], "verification": {"producer": "claimed"}})
    assert result.countersignatures[0].status == "unverified"
    assert result.countersignatures[0].value == "reserved"
    assert result.verification is not None
    assert result.verification.status == "producer_self_report"
