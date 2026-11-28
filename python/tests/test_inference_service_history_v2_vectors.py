# SPDX-License-Identifier: BSD-3-Clause
"""The ``inference-service-history/2`` vectors, checked from their inputs alone.

- ``vectors/inference-service-history-v2/``: each case runs through the evaluator of
  ``test_inference_service_history_v0_vectors.py`` (loaded here as a separate instance under
  ``evidence-interop/1``), whose ``period_floor`` applies §6.2 items 3, 5 and 6 under the
  definition's revision. A case that carries the verdict counts member also has each result's
  table checked under the same rule. The result must equal the case's whole ``expected`` block,
  and the generator must regenerate the directory byte for byte.
- ``vectors/inference-service-history-v2-base/``: every test of
  ``test_inference_service_history_v0_vectors.py`` runs again over the evidence-interop/1 cases with
  ``/2`` definitions, and each expected status equals the ``/0`` set's for the same case id.
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
DIR = ROOT / "vectors" / "inference-service-history-v2"
DATA = json.loads((DIR / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
GENERATOR = ROOT / "python" / "scripts" / "generate_inference_service_history_v2_vectors.py"
RESULTS = ["corroborated", "contradicted", "inconclusive", "not_comparable"]
BASE_FILE = Path(__file__).with_name("test_inference_service_history_v0_vectors.py")


def _load(name: str, **flags: object):
    spec = importlib.util.spec_from_file_location(name, BASE_FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    for k, v in flags.items():
        setattr(module, k, v)  # read by the module before anything else
    spec.loader.exec_module(module)
    return module


base = _load("inference_service_history_vectors_for_v2", _PROFILE_VERSION=1)
_rerun = _load("inference_service_history_vectors_v2_base", _PROFILE_VERSION=1, _BASE_V2=True)
# The base set's tests, collected here under a prefix of their own.
globals().update({f"test_base_{name[5:]}": value for name, value in vars(_rerun).items()
                  if name.startswith("test_")})


def verdicts_ok(d: dict, env: dict) -> bool:
    """§5.3, §6.2: each result's table of the verdict counts member, under the definition's
    revision, as ``period_floor`` reads it."""
    member = env["artifact"].get("verdict_counts")
    if member is None:
        return True
    floor = d["period_policy"]["floor"]
    revision = base.PROFILES.index(d["profile"])
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
            if not base.table_ok(parts, totals[0] if totals else None, floor, revision):
                return False
    return True


def evaluate(case: dict, d: dict, env: dict) -> dict:
    props = base.history_properties(case, d, env)
    if props.get("period_floor") == "PASS" and not verdicts_ok(d, env):
        props["period_floor"] = "FAIL"
    return props


def test_corpus_shape():
    assert DATA["count"] == len(CASES) == 28
    assert sum(c["expected"]["accepted"] for c in CASES) == 14
    assert DATA["profile"] == "evidence-interop/1" and DATA["history_profile"] == "inference-service-history/2"
    assert all(c["kind"] == "history" and c["inputs"]["definition"]["profile"] == DATA["history_profile"]
               for c in CASES)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(case):
    assert base.run_history(case, evaluate) == base.comparable(case["expected"])
    assert sorted(base.failing(base.run_history(case, evaluate))) == sorted(case["expected"]["fails"])


def test_item_6_withholds_where_one_value_is_left():
    by_id = {c["id"]: c for c in CASES}
    for cid, want in (("v2-one-value-least", None), ("v2-one-value-most", None),
                      ("v2-one-value-partner-at-floor", None), ("v2-one-value-nothing-published", None),
                      ("v2-two-values-published", 15), ("v2-two-values-nothing-published", 10),
                      ("v2-standard-served", 12)):
        _, env = base.run_reply(by_id[cid], by_id[cid]["inputs"])
        total = env["artifact"]["period_counts"]["periods"][1]["cells"][-1]
        assert total["value"] == want, cid
        assert total.get("suppressed") == (None if want else "complementary"), cid


def test_the_rule_is_the_revisions():
    """A published total of 15 over 1, 5 and 9 fails under /2 and passes under /1 and /0."""
    case = next(c for c in CASES if c["id"] == "mutant-v2-one-value-least")
    _, env = base.run_reply(case, case["inputs"])
    d = dict(case["inputs"]["definition"])
    assert not base.floor_ok(d, env)
    for p in base.PROFILES[:2]:
        d["profile"] = p
        assert base.floor_ok(d, env), p


def test_every_case_is_listed_in_the_spec():
    spec = (ROOT / DATA["spec"]).read_text(encoding="utf-8")
    section = spec.split("### 9.6", 1)[1].split("\n## ", 1)[0]
    assert set(re.findall(r"^\| `([a-z0-9-]+)` \|", section, re.M)) == {c["id"] for c in CASES}


def test_the_base_set_expects_what_the_v0_set_expects():
    v0 = json.loads((ROOT / "vectors" / "inference-service-history-v0-interop-v1" / "vectors.json").read_text())
    keys = ("accepted", "fails", "history_properties", "reason", "coverage", "shows")
    assert [c["id"] for c in _rerun.CASES] == [c["id"] for c in v0["cases"]]
    for a, b in zip(v0["cases"], _rerun.CASES):
        assert {k: a["expected"].get(k) for k in keys} == {k: b["expected"].get(k) for k in keys}, a["id"]
    assert _rerun.DATA["history_profile"] == "inference-service-history/2"
    for c in _rerun.HISTORY_CASES:
        assert c["inputs"]["definition"]["profile"] == "inference-service-history/2", c["id"]


def test_the_directory_is_regenerated_byte_for_byte():
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


BELOW, COMP = _part(None, "below_floor"), _part(None, "complementary")


@pytest.mark.parametrize("name,parts,total,floor,rev1,rev2", [
    ("1, 5 and 9 beside 15", [BELOW, COMP, _part(9)], _part(15), 5, True, False),
    ("4, 6 and 6 beside 16", [BELOW, COMP, _part(6)], _part(16), 5, True, False),
    ("3, 5 and 5 beside 13", [BELOW, COMP, _part(5)], _part(13), 5, True, False),
    ("3, 6 and 6 beside 15", [BELOW, COMP, _part(6)], _part(15), 5, True, True),
    ("1 and 5 beside 6", [BELOW, COMP], _part(6), 5, True, False),
    ("3 and 7 beside 10", [BELOW, COMP], _part(10), 5, True, True),
    ("1, 5 and 9 beside 14", [BELOW, COMP, _part(9)], _part(14), 5, True, False),
    ("1, 5 and 9 beside 23", [BELOW, COMP, _part(9)], _part(23), 5, True, False),
    ("one and its partner beside a withheld total", [BELOW, COMP, _part(9)], COMP, 5, False, True),
    ("one, no partner, beside a withheld total", [BELOW, _part(9)], COMP, 5, False, False),
    ("one and two partners beside a withheld total", [BELOW, COMP, COMP], COMP, 5, False, False),
    ("one and two partners beside 20", [BELOW, COMP, COMP, _part(6)], _part(20), 5, True, True),
    ("floor 2: one and its partner beside 5", [BELOW, COMP], _part(5), 2, True, False),
    ("a total alone", [], _part(23), 5, False, True),
])
def test_table_rule_by_revision(name, parts, total, floor, rev1, rev2):
    assert base.table_ok(parts, total, floor, 1) is rev1, name
    assert base.table_ok(parts, total, floor, 2) is rev2, name


def test_the_generator_withholds_by_hand_as_the_rule_says():
    """The generator's own §6.2 under /2, on the tables the vectors and the Rust tests use."""
    out = subprocess.run([sys.executable, "-c", (
        "import generate_inference_service_history_v2_vectors as v; "
        "print([v.withheld(t)[2] for t in ({'a': 1, 'b': 5, 'c': 9}, {'a': 4, 'b': 6, 'c': 6}, "
        "{'a': 3, 'b': 5, 'c': 5}, {'a': 3, 'b': 6, 'c': 6}, {'a': 1, 'b': 5}, {'a': 3, 'b': 7}, "
        "{'a': 9, 'b': 3}, {'a': 4, 'b': 4}, {'a': 4, 'b': 5, 'c': 6, 'd': 6})])")],
        check=True, capture_output=True, text=True, cwd=GENERATOR.parent).stdout.strip()
    assert out == ("['complementary', 'complementary', 'complementary', None, 'complementary', None, None, "
                   "'complementary', None]")
