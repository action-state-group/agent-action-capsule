# SPDX-License-Identifier: BSD-3-Clause
"""Run every frozen vector in ../../vectors/capsule/ through the verifier and assert
its expected.json. This is what makes the vectors CI-checked, not just static."""
import json
from pathlib import Path

import pytest

from agent_action_capsule import canonical, verify, verify_store

VECTORS = Path(__file__).resolve().parents[2] / "vectors/capsule"
MANIFEST = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
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


def _assert_canonical(inp, exp):
    """Assert a kind=canonical vector: test compute_capsule_id directly."""
    exc = None
    cap_id = None
    try:
        cap_id = canonical.compute_capsule_id(inp)
    except Exception as e:
        exc = type(e).__name__
    assert cap_id == exp["capsule_id_recomputed"], (
        f"capsule_id mismatch: got {cap_id!r}, expected {exp['capsule_id_recomputed']!r}"
    )
    assert exc == exp["exception"], (
        f"exception mismatch: got {exc!r}, expected {exp['exception']!r}"
    )


def _assert_preimage(inp, exp):
    """A spec-derived capsule_id preimage is the literal RFC 8785 text: JCS must produce it."""
    preimage = exp.get("canonical_preimages", {}).get("capsule_id")
    if preimage is None or "ledger" in inp:
        return
    excluded = {"capsule_id", *canonical.LOCAL_ONLY_FIELDS}
    body = {k: v for k, v in inp.items() if k not in excluded}
    assert canonical.jcs(body).decode("utf-8") == preimage


def _assert_same_capsule_id(exp):
    """A twin case (e.g. -0 written 0) must pin the same capsule_id as the case it names."""
    other = exp.get("same_capsule_id_as")
    if other is None:
        return
    twin = json.loads((VECTORS / other / "expected.json").read_text(encoding="utf-8"))
    assert exp["capsule_id_recomputed"] == twin["capsule_id_recomputed"]


@pytest.mark.parametrize("name", CASES)
def test_vector(name):
    case = VECTORS / name
    inp = json.loads((case / "input.json").read_text(encoding="utf-8"))
    exp = json.loads((case / "expected.json").read_text(encoding="utf-8"))

    _assert_preimage(inp, exp)
    _assert_same_capsule_id(exp)
    if exp.get("kind") == "canonical":
        _assert_canonical(inp, exp)
    elif isinstance(inp, dict) and "ledger" in inp:
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
