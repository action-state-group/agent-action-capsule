# SPDX-License-Identifier: BSD-3-Clause
"""Tests for agent_action_capsule.history — ledger-grade list/verify/export."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from agent_action_capsule.emit import emit
from agent_action_capsule.history import (
    RUNGS,
    ChainReport,
    export_verifiable_bundle,
    list_capsules,
    verify_chain_completeness,
)

_RUNG_VECTORS_PATH = Path(__file__).resolve().parent / "vectors" / "rung" / "vectors.json"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_ledger(capsules: list[dict]) -> str:
    """Write a list of capsule dicts to a temp JSONL file; return the path."""
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for cap in capsules:
            fh.write(json.dumps(cap) + "\n")
    return path


def _make_chain(operator: str = "op1", n: int = 3, **extra) -> list[dict]:
    """Emit a chain of *n* capsules for *operator* with sequential linkage."""
    caps: list[dict] = []
    prior: str | None = None
    for _ in range(n):
        cap = emit(
            operator=operator,
            developer="dev/1.0",
            prior_capsule_id=prior,
            chain_relation="follows" if prior is not None else None,
            **extra,
        )
        caps.append(cap)
        prior = cap["capsule_id"]
    return caps


# ---------------------------------------------------------------------------
# list_capsules
# ---------------------------------------------------------------------------

def test_list_capsules_filters_by_operator():
    """Two operators in ledger; list_capsules returns only the target one."""
    cap_a = emit(operator="alice", developer="dev/1.0")
    cap_b = emit(operator="bob", developer="dev/1.0")
    path = _write_ledger([cap_a, cap_b])
    try:
        results = list_capsules(
            operator="alice",
            window_start="2000-01-01T00:00:00Z",
            window_end="2099-12-31T23:59:59Z",
            ledger_path=path,
        )
        assert len(results) == 1
        assert results[0]["operator"] == "alice"
    finally:
        os.unlink(path)


def test_list_capsules_timestamp_window():
    """Capsules with created_at outside the window are excluded."""
    # Use explicit timestamp to control placement.
    inside = emit(operator="op1", developer="dev/1.0", timestamp="2024-06-15T12:00:00Z")
    outside = emit(operator="op1", developer="dev/1.0", timestamp="2023-01-01T00:00:00Z")
    path = _write_ledger([inside, outside])
    try:
        results = list_capsules(
            operator="op1",
            window_start="2024-01-01T00:00:00Z",
            window_end="2024-12-31T23:59:59Z",
            ledger_path=path,
        )
        assert len(results) == 1
        assert results[0]["timestamp"] == "2024-06-15T12:00:00Z"
    finally:
        os.unlink(path)


def test_list_capsules_no_timestamp_includes_all():
    """Capsules that lack a timestamp field are included conservatively."""
    cap = emit(operator="op1", developer="dev/1.0")
    # Strip the timestamp field to simulate a capsule without one.
    cap_no_ts = {k: v for k, v in cap.items() if k != "timestamp"}
    path = _write_ledger([cap_no_ts])
    try:
        results = list_capsules(
            operator="op1",
            window_start="2000-01-01T00:00:00Z",
            window_end="2001-01-01T00:00:00Z",   # narrow window that would exclude a dated capsule
            ledger_path=path,
        )
        # Must be included because there is no timestamp to filter on.
        assert len(results) == 1
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# verify_chain_completeness
# ---------------------------------------------------------------------------

def test_verify_chain_complete():
    """Three capsules forming A → B → C; chain_report.complete is True, gaps is []."""
    caps = _make_chain(operator="op1", n=3)
    report = verify_chain_completeness(caps)
    assert report.complete is True
    assert report.gaps == []


def test_verify_chain_gap():
    """Remove the middle capsule; chain_report.complete is False and the gap is identified.

    DELIBERATE-GAP NEGATIVE CASE — this test MUST pass.
    Chain: A → B → C.  Remove B.  C's parent (B) is not in the window → gap.
    """
    caps = _make_chain(operator="op1", n=3)
    # caps[0] = A (no parent), caps[1] = B (parent=A), caps[2] = C (parent=B)
    window_without_b = [caps[0], caps[2]]   # deliberately drop the middle capsule

    report = verify_chain_completeness(window_without_b)

    assert report.complete is False, "Expected complete=False when middle capsule is missing"
    assert len(report.gaps) == 1, f"Expected exactly one gap; got {report.gaps}"
    # The gap should be capsule C (the one whose parent is missing).
    assert report.gaps[0] == caps[2]["capsule_id"], (
        f"Expected gap at C ({caps[2]['capsule_id']!r}); got {report.gaps[0]!r}"
    )


def test_verify_chain_epoch_opens_not_a_gap():
    """A capsule with chain.relation == 'epoch_opens' is a legal chain-start, not a gap."""
    # Craft a capsule that claims to open an epoch (its parent won't be in the window).
    cap_a = emit(operator="op1", developer="dev/1.0")
    # Build a second capsule that follows from some external parent (not in window)
    # and marks itself as epoch_opens.
    external_parent = "a" * 64   # a valid-looking hex64 not in the window
    cap_epoch = emit(
        operator="op1",
        developer="dev/1.0",
        prior_capsule_id=external_parent,
        chain_relation="epoch_opens",
    )

    report = verify_chain_completeness([cap_a, cap_epoch])

    assert report.complete is True, f"epoch_opens capsule should not be a gap; report={report}"
    assert cap_epoch["capsule_id"] in report.epoch_opens


def test_verify_chain_epoch_scoped():
    """Two epoch_ids in one ledger; filtering to one epoch returns only those capsules."""
    # Caps for epoch "e1" with compute_attestation carrying epoch_id.
    def _emit_with_epoch(epoch: str, prior: str | None = None) -> dict:
        return emit(
            operator="op1",
            developer="dev/1.0",
            compute_attestation={"epoch_id": epoch},
            prior_capsule_id=prior,
            chain_relation="follows" if prior else None,
        )

    e1_a = _emit_with_epoch("e1")
    e1_b = _emit_with_epoch("e1", prior=e1_a["capsule_id"])
    e2_a = _emit_with_epoch("e2")

    all_caps = [e1_a, e1_b, e2_a]

    report_e1 = verify_chain_completeness(all_caps, epoch_id="e1")
    assert report_e1.complete is True
    assert len(report_e1.gaps) == 0
    # e2_a should not appear in e1's scope.
    ids_seen = {c["capsule_id"] for c in all_caps if c.get("model_attestation", {}).get("compute_attestation", {}).get("epoch_id") == "e1"}
    assert e2_a["capsule_id"] not in ids_seen


# ---------------------------------------------------------------------------
# export_verifiable_bundle
# ---------------------------------------------------------------------------

def test_export_bundle_re_verifies():
    """export_verifiable_bundle, then re-verify bundle["capsules"] → same ChainReport."""
    caps = _make_chain(operator="op1", n=3)
    bundle = export_verifiable_bundle(caps)

    assert bundle["version"] == "1"
    assert bundle["capsules"] is caps
    assert isinstance(bundle["inclusion_proofs"], list)

    # Re-verify the bundle's capsules independently.
    re_report = verify_chain_completeness(bundle["capsules"])
    original_report = ChainReport(**bundle["chain_report"])

    assert re_report.complete == original_report.complete
    assert re_report.gaps == original_report.gaps
    assert re_report.epoch_opens == original_report.epoch_opens


def test_export_bundle_with_inclusion_proofs():
    """Inclusion proofs are preserved in the bundle when supplied."""
    caps = _make_chain(operator="op1", n=2)
    proofs = [{"capsule_id": caps[0]["capsule_id"], "receipt": "dummy"}]
    bundle = export_verifiable_bundle(caps, inclusion_proofs=proofs)
    assert bundle["inclusion_proofs"] == proofs


def test_export_bundle_no_proofs_is_empty_list():
    """When no inclusion proofs are supplied, the field is an empty list."""
    caps = _make_chain(operator="op1", n=1)
    bundle = export_verifiable_bundle(caps)
    assert bundle["inclusion_proofs"] == []


# ---------------------------------------------------------------------------
# Anchoring-evidence rung (docs/ledger-grade.md §4)
# ---------------------------------------------------------------------------

def test_rung_default_is_standalone():
    """No inclusion proofs, no countersignatures -> the floor rung."""
    caps = _make_chain(operator="op1", n=2)
    report = verify_chain_completeness(caps)
    assert report.rung == "standalone"


def test_rung_never_higher_than_evidence_supports_missing_capsule_id():
    """A capsule with no capsule_id can never earn credit from evidence."""
    cap = emit(operator="op1", developer="dev/1.0")
    cap_no_id = {k: v for k, v in cap.items() if k != "capsule_id"}
    proofs = [{"capsule_id": "anything", "visibility": "public"}]
    report = verify_chain_completeness([cap_no_id], inclusion_proofs=proofs)
    assert report.rung == "standalone"


def test_export_bundle_carries_rung_alongside_chain_report():
    """export_verifiable_bundle()'s output carries rung at the top level AND
    inside chain_report, and both agree."""
    caps = _make_chain(operator="op1", n=1)
    proofs = [{"capsule_id": caps[0]["capsule_id"], "visibility": "public"}]
    bundle = export_verifiable_bundle(caps, inclusion_proofs=proofs)
    assert bundle["rung"] == "publicly-anchored"
    assert bundle["chain_report"]["rung"] == "publicly-anchored"
    assert bundle["countersignatures"] == []


def test_export_bundle_countersignatures_preserved_and_drive_rung():
    caps = _make_chain(operator="op1", n=1)
    cs = [{"capsule_id": caps[0]["capsule_id"], "signer": "counterparty:acme"}]
    bundle = export_verifiable_bundle(caps, countersignatures=cs)
    assert bundle["countersignatures"] == cs
    assert bundle["rung"] == "countersigned"


def test_rung_bundle_is_minimum_across_capsules():
    """Never-grades-up at the bundle level: one capsule's strong evidence must
    not inflate a sibling capsule's absence of evidence."""
    caps = _make_chain(operator="op1", n=2)
    proofs = [{"capsule_id": caps[0]["capsule_id"], "visibility": "public"}]
    report = verify_chain_completeness(caps, inclusion_proofs=proofs)
    assert report.rung == "standalone"


def _load_rung_vectors() -> list[dict]:
    with open(_RUNG_VECTORS_PATH, encoding="utf-8") as fh:
        return json.load(fh)["cases"]


def test_rung_vectors_cover_all_five_rungs():
    """Sanity: the frozen vector file exercises every rung at least once."""
    cases = _load_rung_vectors()
    covered = {c["expected_rung"] for c in cases}
    assert covered == set(RUNGS)


def test_rung_vectors():
    """Each frozen vector's evidence justifies exactly its expected_rung and no higher."""
    for case in _load_rung_vectors():
        report = verify_chain_completeness(
            case["capsules"],
            inclusion_proofs=case["inclusion_proofs"],
            countersignatures=case["countersignatures"],
        )
        assert report.rung == case["expected_rung"], (
            f"vector {case['name']!r}: expected rung {case['expected_rung']!r}, "
            f"got {report.rung!r}"
        )
