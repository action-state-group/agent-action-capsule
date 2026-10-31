# SPDX-License-Identifier: BSD-3-Clause
"""Evidence Bundle -02 "Empty-History Bundles" in ``verify_bundle``.

The Bundles are the empty-history members of
``vectors/bundle/composed-controller-binding/``: one with its stream's first
checkpoint, one with none (a stream never started).
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from agent_action_capsule.bundle import is_empty_history, verify_bundle

VECTORS = Path(__file__).resolve().parents[2] / "vectors" / "bundle" / "composed-controller-binding" / "vectors.json"
CASES = {c["id"]: c for c in json.loads(VECTORS.read_text(encoding="utf-8"))["cases"]}


def _member_bundle(case_id: str) -> dict:
    block = CASES[case_id]["container"]["extensions"]["composed/v1"]
    return copy.deepcopy(next(m for m in block["members"] if m["id"] == "responder-b")["bundle"])


CHECKPOINTED = _member_bundle("controller-binding-empty-member-linked")
UNSTARTED = _member_bundle("controller-binding-empty-member-no-checkpoint")


def _claims(result) -> tuple:
    return tuple((c.status, c.findings) for c in (result.graph_closure, result.interval_coverage,
                                                  result.per_record_membership))


NO_HISTORY = (("pass", ()), ("withheld", ("no_records",)), ("withheld", ("no_records",)))


def test_an_empty_history_bundle_shows_no_history_since_its_checkpoint():
    result = verify_bundle(CHECKPOINTED)
    assert _claims(result) == NO_HISTORY
    assert result.history == {"state": "none", "since": CHECKPOINTED["checkpoint"]["timestamp"]}


def test_a_stream_never_started_shows_no_history_with_no_date():
    assert "checkpoint" not in UNSTARTED
    result = verify_bundle(UNSTARTED)
    assert _claims(result) == NO_HISTORY
    assert result.history == {"state": "none", "since": None}


def test_a_checkpoint_that_does_not_verify_gives_no_date():
    bundle = copy.deepcopy(CHECKPOINTED)
    bundle["checkpoint"]["cose"] = bundle["checkpoint"]["cose"][:-4] + "AAAA"
    result = verify_bundle(bundle)
    assert _claims(result) == NO_HISTORY
    assert result.history == {"state": "none", "since": None}


@pytest.mark.parametrize(
    ("change", "finding"),
    [
        (lambda b: b["completeness"].update(payloads_mode="all"), "empty_history_completeness_invalid"),
        (lambda b: b["completeness"].update(records_mode="declared_incomplete"), "empty_history_completeness_invalid"),
        (lambda b: b["completeness"].update(missing=["0" * 64]), "empty_history_completeness_invalid"),
        (lambda b: b.update(completeness_certificate={}), "empty_history_carries:completeness_certificate"),
        (lambda b: b.update(disclosures={}), "empty_history_carries:disclosures"),
        (lambda b: b.update(disclosure_record="0" * 64), "empty_history_carries:disclosure_record"),
        (lambda b: b.update(bundle_kind="evidence-bundle/v1"), "bundle_version_or_kind_invalid"),
    ],
)
def test_a_malformed_empty_history_bundle_fails_and_shows_nothing(change, finding):
    bundle = copy.deepcopy(CHECKPOINTED)
    change(bundle)
    result = verify_bundle(bundle)
    assert result.graph_closure.status == "fail" and finding in result.graph_closure.findings
    assert result.history is None


def test_an_empty_missing_list_is_allowed():
    bundle = copy.deepcopy(UNSTARTED)
    bundle["completeness"]["missing"] = []
    assert verify_bundle(bundle).history == {"state": "none", "since": None}


def test_root_with_no_records_is_not_empty_history():
    bundle = copy.deepcopy(UNSTARTED)
    bundle["root"] = "0" * 64
    assert not is_empty_history(bundle)
    result = verify_bundle(bundle)
    assert result.graph_closure.findings == ("root_not_supplied_with_matching_identity",)
    assert result.history is None


def test_a_bundle_with_records_never_reports_history():
    assert not is_empty_history({"records": [{}], "completeness": {}})
