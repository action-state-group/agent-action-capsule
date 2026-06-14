# SPDX-License-Identifier: BSD-3-Clause
"""Run every frozen vector in ../../test-vectors/ through the verifier and assert
its expected.json. This is what makes the vectors CI-checked, not just static."""
import json
from pathlib import Path

import pytest

from agent_action_capsule import verify, verify_store

VECTORS = Path(__file__).resolve().parents[2] / "test-vectors"
MANIFEST = json.loads((VECTORS / "vectors.json").read_text())
CASES = [c["name"] for c in MANIFEST["cases"]]


def _findings(res):
    # spec-anchored projection + the impl code, in fixed emission order
    return [(f.check, f.severity, f.code) for f in res.findings]


def _expected_findings(exp):
    return [(f["check"], f["severity"], f["code"]) for f in exp["findings"]]


def _assert_single(res, exp):
    assert res.ok == exp["ok"]
    assert res.assurance == exp["derived"]
    assert res.capsule_id == exp["capsule_id_recomputed"]
    assert _findings(res) == _expected_findings(exp)


@pytest.mark.parametrize("name", CASES)
def test_vector(name):
    case = VECTORS / name
    inp = json.loads((case / "input.json").read_text())
    exp = json.loads((case / "expected.json").read_text())

    if isinstance(inp, dict) and "ledger" in inp:
        results = verify_store(inp["ledger"])
        assert len(results) == len(exp["results"])
        for res, e in zip(results, exp["results"]):
            _assert_single(res, e)
    else:
        _assert_single(verify(inp), exp)


def test_manifest_count_matches_dirs():
    dirs = {p.name for p in VECTORS.iterdir() if p.is_dir()}
    assert dirs == set(CASES)
    assert MANIFEST["count"] == len(CASES)
