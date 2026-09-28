# SPDX-License-Identifier: BSD-3-Clause
"""Pin the single-record report bundle (the /demos shape) and the difference
between a certificate that is wrong and one this installation cannot check.

agent-action-capsule 0.5.0 installed from PyPI without the CLL reference
reported the clean /demos bundles as ``completeness_certificate_invalid`` on
interval coverage and per-record membership, while the in-report verifier
passed them. The bundles are conforming; the missing substrate was misreported
as a producer fault.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_action_capsule.bundle import (
    COMPLETENESS_VERIFIER_UNAVAILABLE,
    decode_fragment,
    encode_fragment,
    verify_bundle,
)

VECTOR = json.loads((Path(__file__).resolve().parents[2] / "vectors/bundle/report-single-record.json").read_text())
CASES = VECTOR["cases"]


def _outcome(result):
    return {
        "graph_closure": result.graph_closure.status,
        "interval_coverage": result.interval_coverage.status,
        "interval_findings": sorted(result.interval_coverage.findings),
        "per_record_membership": result.per_record_membership.status,
        "membership_findings": sorted(result.per_record_membership.findings),
    }


def _sorted(expected):
    return {key: sorted(value) if isinstance(value, list) else value for key, value in expected.items()}


def _block_cll(monkeypatch):
    # A None entry in sys.modules makes the import raise ImportError, exactly
    # as on a plain `pip install agent-action-capsule` without the extra.
    for name in ("cll", "cll.checkpoint", "cll.checkpoint.index"):
        monkeypatch.setitem(__import__("sys").modules, name, None)


def test_vector_manifest_shape():
    assert VECTOR["count"] == len(CASES) == 3
    assert {case["kind"] for case in CASES} == {"positive", "negative"}


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_report_vector_with_cll(case):
    pytest.importorskip("cll.checkpoint")
    bundle = case["bundle"]
    assert decode_fragment(encode_fragment(bundle)) == bundle
    assert _outcome(verify_bundle(bundle)) == _sorted(case["expected"])


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_report_vector_without_cll(case, monkeypatch):
    _block_cll(monkeypatch)
    assert _outcome(verify_bundle(case["bundle"])) == _sorted(case["expected_without_cll"])


def test_unavailable_substrate_is_never_reported_as_invalid_certificate(monkeypatch):
    # The distinguishing pair: the same well-formed certificate must never be
    # called invalid just because the proofs cannot be checked here, and it must
    # never pass either. A certificate that is wrong on its face stays invalid.
    positive = next(case for case in CASES if case["name"] == "pos-single-record-report")
    negative = next(case for case in CASES if case["name"] == "neg-checkpoint-root-mismatch")
    _block_cll(monkeypatch)
    result = verify_bundle(positive["bundle"])
    for claim in (result.interval_coverage, result.per_record_membership):
        assert claim.status == "fail"
        assert claim.findings == (COMPLETENESS_VERIFIER_UNAVAILABLE,)
    assert result.graph_closure.status == "pass"
    result = verify_bundle(negative["bundle"])
    assert result.interval_coverage.findings == ("completeness_certificate_invalid",)
    assert result.per_record_membership.findings == ("completeness_certificate_invalid",)
