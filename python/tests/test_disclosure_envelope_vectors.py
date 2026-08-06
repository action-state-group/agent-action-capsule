# SPDX-License-Identifier: BSD-3-Clause
"""Run every frozen vector in ../../disclosure-envelope-vectors/ through
verify_disclosure_envelope() and assert its expected.json."""
import json
from pathlib import Path

import pytest

from agent_action_capsule import verify_disclosure_envelope

VECTORS = Path(__file__).resolve().parents[2] / "disclosure-envelope-vectors"
MANIFEST = json.loads((VECTORS / "vectors.json").read_text())
CASES = [c["name"] for c in MANIFEST["cases"]]


@pytest.mark.parametrize("name", CASES)
def test_vector(name):
    case = VECTORS / name
    inp = json.loads((case / "input.json").read_text())
    exp = json.loads((case / "expected.json").read_text())

    res = verify_disclosure_envelope(inp["envelope"])

    assert res.ok == exp["ok"]
    assert res.capsule_result.ok == exp["capsule"]["ok"]
    assert res.capsule_result.assurance == exp["capsule"]["derived"]
    assert res.capsule_result.capsule_id == exp["capsule"]["capsule_id_recomputed"]
    assert res.disclosures_checked == exp["disclosures_checked"]
    assert res.disclosures_matched == exp["disclosures_matched"]
    assert [(f.member, f.code) for f in res.disclosure_findings] == [
        (f["member"], f["code"]) for f in exp["disclosure_findings"]
    ]


def test_manifest_count_matches_dirs():
    dirs = {p.name for p in VECTORS.iterdir() if p.is_dir()}
    assert dirs == set(CASES)
    assert MANIFEST["count"] == len(CASES)
