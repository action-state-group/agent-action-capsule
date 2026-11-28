# SPDX-License-Identifier: BSD-3-Clause
"""The ``inference-service-history/1`` vectors (``vectors/inference-service-history-v1/``), checked
from their inputs alone.

Each case runs through the evaluator of ``test_inference_service_history_v0_vectors.py`` (loaded
here as a separate instance under ``evidence-interop/1``): the reference verifier for the request
and reply, and the History properties of §8.3, whose ``period_floor`` applies §6.2 items 3 and 5 under the
definition's revision. A case that carries the verdict counts member also has each result's table
checked under the same rule. The result must equal the case's whole ``expected`` block, and the
generator must regenerate the directory byte for byte.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / "vectors" / "inference-service-history-v1"
DATA = json.loads((DIR / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
GENERATOR = ROOT / "python" / "scripts" / "generate_inference_service_history_v1_vectors.py"
RESULTS = ["corroborated", "contradicted", "inconclusive", "not_comparable"]

_spec = importlib.util.spec_from_file_location(
    "inference_service_history_vectors_for_v1", Path(__file__).with_name("test_inference_service_history_v0_vectors.py"))
assert _spec is not None and _spec.loader is not None
base = importlib.util.module_from_spec(_spec)
base._PROFILE_VERSION = 1  # evidence-interop/1, as this set's requests and envelopes name
_spec.loader.exec_module(base)


def verdicts_ok(d: dict, env: dict) -> bool:
    """§5.3, §6.2: each result's table of the verdict counts member, under the definition's
    revision, as ``period_floor`` reads it."""
    member = env["artifact"].get("verdict_counts")
    if member is None:
        return True
    floor = d["period_policy"]["floor"]
    revision1 = d["profile"] == base.PROFILES[1]
    for period in member["periods"]:
        for c in period["cells"]:
            if ("suppressed" in c) != (c["value"] is None) or c.get("suppressed", "below_floor") not in (
                    "below_floor", "complementary"):
                return False
            if c["value"] is not None and c["value"] < floor:
                return False
        for result in RESULTS:
            table = [c for c in period["cells"] if c["dimension"]["result"] == result]
            parts = [c for c in table if "model_hash" in c["dimension"]]
            totals = [c for c in table if "model_hash" not in c["dimension"]]
            if not base.table_ok(parts, totals[0] if totals else None, floor, revision1):
                return False
    return True


def evaluate(case: dict, d: dict, env: dict) -> dict:
    props = base.history_properties(case, d, env)
    if props.get("period_floor") == "PASS" and not verdicts_ok(d, env):
        props["period_floor"] = "FAIL"
    return props


def test_corpus_shape():
    assert DATA["count"] == len(CASES) == 13
    assert DATA["profile"] == "evidence-interop/1" and DATA["history_profile"] == "inference-service-history/1"
    assert all(c["kind"] == "history" and c["inputs"]["definition"]["profile"] == DATA["history_profile"]
               for c in CASES)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(case):
    assert base.run_history(case, evaluate) == base.comparable(case["expected"])
    assert sorted(base.failing(base.run_history(case, evaluate))) == sorted(case["expected"]["fails"])


def test_the_withheld_totals_are_complementary():
    by_id = {c["id"]: c for c in CASES}
    for cid in ("v1-total-withheld-two-under-floor", "v1-total-withheld-five-ones",
                "v1-total-under-floor-withheld-complementary"):
        _, env = base.run_reply(by_id[cid], by_id[cid]["inputs"])
        total = env["artifact"]["period_counts"]["periods"][1]["cells"][-1]
        assert (total["value"], total.get("suppressed")) == (None, "complementary"), cid
    _, env = base.run_reply(by_id["v1-total-pins-nothing-published"], by_id["v1-total-pins-nothing-published"]["inputs"])
    assert env["artifact"]["period_counts"]["periods"][1]["cells"][-1]["value"] == 7


def test_the_rule_is_the_revisions():
    """The same published total of 8 over 4 and 4 fails under /1 and passes /0's minimum check."""
    case = next(c for c in CASES if c["id"] == "mutant-v1-total-pins-two-under-floor")
    _, env = base.run_reply(case, case["inputs"])
    d = dict(case["inputs"]["definition"])
    assert not base.floor_ok(d, env)
    d["profile"] = base.PROFILES[0]
    assert base.floor_ok(d, env)


def test_every_case_is_listed_in_the_spec():
    spec = (ROOT / DATA["spec"]).read_text(encoding="utf-8")
    section = spec.split("### 9.5", 1)[1].split("\n## ", 1)[0]
    assert set(re.findall(r"^\| `([a-z0-9-]+)` \|", section, re.M)) == {c["id"] for c in CASES}


def test_the_directory_is_regenerated_byte_for_byte():
    # In a process of its own: the generator switches the base generator to evidence-interop/1.
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "README.md").write_bytes((DIR / "README.md").read_bytes())
        subprocess.run([sys.executable, str(GENERATOR), "--out", tmp], check=True, cwd=GENERATOR.parent)
        for name in ("vectors.json", "manifest.json", "SHA256SUMS"):
            assert (Path(tmp) / name).read_bytes() == (DIR / name).read_bytes(), name


def _part(value, why=None):
    c = {"dimension": {"model": "m"}, "value": value}
    if why:
        c["suppressed"] = why
    return c


@pytest.mark.parametrize("name,parts,total,floor,rev0,rev1", [
    ("4+4 beside a published 8", [_part(None, "below_floor")] * 2, _part(8), 5, True, False),
    ("3+4 beside a published 7", [_part(None, "below_floor")] * 2, _part(7), 5, True, True),
    ("10 and 4+4 beside 18", [_part(10)] + [_part(None, "below_floor")] * 2, _part(18), 5, True, False),
    ("total withheld beside two", [_part(None, "below_floor")] * 2, _part(None, "complementary"), 5, True, True),
    ("total withheld complementary beside one", [_part(None, "complementary"), _part(None, "below_floor")],
     _part(None, "complementary"), 5, True, False),
    ("three withheld, a rest of 2", [_part(10)] + [_part(None, "below_floor")] * 3, _part(12), 5, True, False),
    ("published over the total", [_part(10), _part(9)], _part(12), 5, True, False),
    ("floor 1: nothing withheld", [_part(1), _part(1)], _part(2), 1, True, True),
    ("floor 2: two 1s beside 7 and 9", [_part(None, "below_floor")] * 2 + [_part(7)], _part(9), 2, True, False),
    ("floor 1: two withheld beside a withheld total", [_part(None, "below_floor")] * 2,
     _part(None, "complementary"), 1, True, False),
    ("floor 1: two withheld beside a total withheld below it", [_part(None, "below_floor")] * 2,
     _part(None, "below_floor"), 1, True, False),
    ("floor 2: two under the floor, total 3", [_part(None, "below_floor")] * 2, _part(3), 2, True, False),
    ("floor 5: two under the floor beside 10, total 19", [_part(10)] + [_part(None, "below_floor")] * 2, _part(19),
     5, True, False),
])

def test_table_rule_by_revision(name, parts, total, floor, rev0, rev1):
    assert base.table_ok(parts, total, floor, False) is rev0, name
    assert base.table_ok(parts, total, floor, True) is rev1, name


def test_a_verdict_cell_withheld_with_a_value_fails():
    case = next(c for c in CASES if c["id"] == "v1-verdict-total-withheld")
    _, env = base.run_reply(case, case["inputs"])
    d = case["inputs"]["definition"]
    assert verdicts_ok(d, env)
    cell = next(c for c in env["artifact"]["verdict_counts"]["periods"][1]["cells"] if "suppressed" in c)
    cell["value"] = 5
    assert not verdicts_ok(d, env)


def test_the_generator_withholds_by_hand_as_the_rule_says():
    """The generator's own §6.2 under /1, on the tables the vectors and the Rust tests use."""
    out = subprocess.run([sys.executable, "-c", (
        "import generate_inference_service_history_v1_vectors as v; "
        "print([v.withheld(t)[2] for t in ({'a': 4, 'b': 4}, {'a': 1, 'b': 1}, {'a': 3, 'b': 4}, "
        "{'a': 10, 'b': 4, 'c': 4}, {'a': 9, 'b': 3}, {'a': 3}, {'a': 1, 'b': 1, 'c': 1, 'd': 1, 'e': 1})])")],
        check=True, capture_output=True, text=True, cwd=GENERATOR.parent).stdout.strip()
    assert out == ("['complementary', 'complementary', None, 'complementary', None, 'below_floor', "
                   "'complementary']")
