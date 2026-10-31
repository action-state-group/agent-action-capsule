# SPDX-License-Identifier: BSD-3-Clause
"""``witness.check_anchor_witnessed`` (profile v1 §6.2.2) against ``vectors/anchor-witness-v1``.

Every expected report is written by the generator from §6.2.2, with its own tree, CBOR and P-256
code; Go and TypeScript run the same file.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

pytest.importorskip("scitt_cose")

from agent_action_capsule import witness as aw  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "anchor-witness-v1"
GENERATOR = ROOT / "python" / "scripts" / "generate_anchor_witness_v1_vectors.py"
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))


def _inputs(case):
    policy = DATA["policies"][case["policy"]] if isinstance(case["policy"], str) else case["policy"]
    return case["anchor"], [bytes.fromhex(r) for r in case["receipts"]], policy


def _report(case):
    out = aw.check_anchor_witnessed(*_inputs(case)).to_dict()
    assert out.pop("property") == aw.ANCHOR_WITNESS_PROPERTY
    return out


def test_corpus_regenerates_byte_for_byte(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(tmp_path)], check=True)
    for name in ("vectors.json", "manifest.json"):
        assert (tmp_path / name).read_bytes() == (VECTORS / name).read_bytes(), name


def test_corpus_covers_every_status():
    seen = {c["expected"]["status"] for c in DATA["cases"]}
    assert seen == {"PASS", "FAIL", "NOT_CHECKED", "NOT_PRESENT"}


@pytest.mark.parametrize("case", DATA["cases"], ids=lambda c: c["name"])
def test_case(case):
    assert _report(case) == case["expected"]


def test_time_and_witness_come_from_one_receipt():
    # A defective reader that takes the earliest time but the first passing witness must disagree.
    case = next(c for c in DATA["cases"] if c["name"] == "earliest-time-and-its-witness")
    report = aw.check_anchor_witnessed(*_inputs(case))
    first = next(r for r in report.receipts if r.status == "PASS")
    mixed = replace(report, witness=first.witness)
    assert mixed.to_dict() != {"property": aw.ANCHOR_WITNESS_PROPERTY, **case["expected"]}
    assert report.witness == "witness-c" and report.witnessed_time == min(
        r.registration_time for r in report.receipts if r.registration_time is not None)


def test_receipts_are_independent_of_order_for_status():
    case = next(c for c in DATA["cases"] if c["name"] == "pass-beside-fail")
    anchor, receipts, policy = _inputs(case)
    assert aw.check_anchor_witnessed(anchor, list(reversed(receipts)), policy).status == "PASS"


def test_malformed_policy_lists_no_key():
    case = next(c for c in DATA["cases"] if c["name"] == "pass-eddsa-time")
    anchor, receipts, _ = _inputs(case)
    for policy in (None, [], {"witnesses": "x"}, {"witnesses": [{"name": 1, "keys": []}]},
                   {"witnesses": [{"name": "w", "keys": ["not hex"]}]}):
        assert aw.check_anchor_witnessed(anchor, receipts, policy).status == "NOT_CHECKED"


def test_non_bytes_receipt_fails_without_raising():
    anchor = DATA["cases"][0]["anchor"]
    report = aw.check_anchor_witnessed(anchor, ["text", None, b""], DATA["policies"]["default"])
    assert [r.status for r in report.receipts] == ["FAIL"] * 3


def test_receipt_size_limit():
    # Valid, signed Receipts padded by a private-use label to the limit and one octet over it:
    # too large for a vector file, so built here with the generator's own code.
    import importlib.util

    spec = importlib.util.spec_from_file_location("generator", GENERATOR)
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    policy = DATA["policies"]["default"]

    def build(pad):
        return gen.receipt(gen.KEY_A, protected={1: -8, 395: 1, -65537: b"\x00" * pad})

    def padded(size):
        # Every head width is fixed above 65,536 octets, so the length grows one for one.
        base = 1 << 20
        return build(base + size - len(build(base)))

    limit = 10 * 1024 * 1024
    at_limit, over = padded(limit), padded(limit + 1)
    assert len(at_limit) == limit and len(over) == limit + 1
    anchor = gen.ANCHOR.hex()
    assert aw.check_anchor_receipt(anchor, at_limit, policy).status == "PASS"
    assert aw.check_anchor_receipt(anchor, over, policy).status == "FAIL"
