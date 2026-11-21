# SPDX-License-Identifier: BSD-3-Clause
"""``witness.check_card_registered`` (standard-history-v0 §13) against ``vectors/card-registration-v0``.

Every expected report is written by the generator from §13; Go, TypeScript and Rust run the same
file.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from agent_action_capsule import witness as aw  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "card-registration-v0"
GENERATOR = ROOT / "python" / "scripts" / "generate_card_registration_v0_vectors.py"
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))


def _inputs(case):
    policy = DATA["policies"][case["policy"]] if isinstance(case["policy"], str) else case["policy"]
    return (bytes.fromhex(case["card"]), case["holder"], case["anchor"],
            [bytes.fromhex(s) for s in case["statements"]], policy)


def test_corpus_regenerates_byte_for_byte(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(tmp_path)], check=True)
    for name in ("vectors.json", "manifest.json"):
        assert (tmp_path / name).read_bytes() == (VECTORS / name).read_bytes(), name


def test_corpus_covers_every_status():
    assert {c["expected"]["status"] for c in DATA["cases"]} == {"PASS", "FAIL", "NOT_CHECKED", "NOT_PRESENT"}


@pytest.mark.parametrize("case", DATA["cases"], ids=lambda c: c["name"])
def test_case(case):
    out = aw.check_card_registered(*_inputs(case)).to_dict()
    assert out.pop("property") == aw.CARD_REGISTERED_PROPERTY
    assert out == case["expected"]


def test_statement_status_is_independent_of_order():
    case = next(c for c in DATA["cases"] if c["name"] == "pass-beside-fail")
    card, holder, anchor, statements, policy = _inputs(case)
    assert aw.check_card_registered(card, holder, anchor, list(reversed(statements)), policy).status == "PASS"


def test_another_holder_fails():
    case = next(c for c in DATA["cases"] if c["name"] == "pass-eddsa-time")
    card, _, anchor, statements, policy = _inputs(case)
    assert aw.check_card_registered(card, "00" * 32, anchor, statements, policy).status == "FAIL"
    card, holder, _, statements, policy = _inputs(case)
    assert aw.check_card_registered(card, holder, "00" * 32, statements, policy).status == "FAIL"


def test_non_bytes_inputs_fail_without_raising():
    case = next(c for c in DATA["cases"] if c["name"] == "pass-eddsa-time")
    card, holder, anchor, statements, policy = _inputs(case)
    assert aw.check_card_registered(card, holder, anchor, ["not bytes"], policy).status == "FAIL"
    assert aw.check_card_registered(b"other octets", holder, anchor, statements, policy).status == "FAIL"
    assert aw.check_card_registered(card, holder, anchor, None, policy).status == "NOT_PRESENT"
