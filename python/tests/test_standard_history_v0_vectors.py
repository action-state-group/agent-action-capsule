# SPDX-License-Identifier: BSD-3-Clause
"""The standard history vectors (``vectors/standard-history-v0/``).

Every case runs from its inputs alone through ``agent_action_capsule.standard_history``:

- ``check_card`` reports the six card properties of ``spec/standard-history-v0.md`` (SH) §6,
  compared with the case's whole ``expected`` block, which the generator states by hand;
- for every standard card checked with the policy, the anchor and the deal entries,
  ``derive_card`` rebuilds exactly the case's card from them.

``go/standardhistory`` runs the same cases. The test regenerates the corpus twice and requires
both runs to be byte-identical to the committed files, and runs defective evaluators, each of
which must disagree with at least one case.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from agent_action_capsule import standard_history as sh

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "standard-history-v0"
GENERATOR = ROOT / "python" / "scripts" / "generate_standard_history_v0_vectors.py"
HAND_WRITTEN = ("README.md",)
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]


def _check(c: dict) -> dict:
    i = c["inputs"]
    return sh.check_card(i["card"], policy=i.get("policy"), as_of=i.get("as_of"), deals=i.get("deals"))


def _derivable(c: dict) -> bool:
    return c["expected"]["standard"] and all(k in c["inputs"] for k in ("policy", "as_of", "deals"))


def _derive(c: dict) -> dict:
    i, card = c["inputs"], c["inputs"]["card"]
    return sh.derive_card(holder_kind=card["holder_kind"], controller_class=card["controller_class"],
                          anchor=i["as_of"]["anchor"], anchor_time=i["as_of"]["anchor_time"],
                          first_checkpoint_time=i["as_of"]["first_checkpoint_time"], policy=i["policy"],
                          deals=i["deals"])


def test_corpus_header() -> None:
    assert DATA["spec"] == "spec/standard-history-v0.md"
    assert tuple(DATA["properties"]) == sh.PROPERTIES
    assert DATA["count"] == len(CASES)
    spec = (ROOT / DATA["spec"]).read_text(encoding="utf-8")
    for prop in sh.PROPERTIES:
        assert f"| `{prop}` |" in spec, prop


@pytest.mark.parametrize("c", CASES, ids=[c["id"] for c in CASES])
def test_case(c: dict) -> None:
    props = _check(c)
    assert props == c["expected"]["properties"]
    assert list(props) == list(sh.PROPERTIES)
    assert sh.is_standard(props) is c["expected"]["standard"]
    assert [k for k, v in props.items() if v == "FAIL"] == c["expected"]["fails"]
    if _derivable(c):
        assert _derive(c) == c["inputs"]["card"]


def test_every_negative_named_in_sh_6_is_present() -> None:
    ids = {c["id"] for c in CASES}
    for cid in ("percentage-fraction", "percentage-member", "count-without-denominator", "tallies-disagree",
                "counted-shop-purchase", "window-not-in-policy", "counterparty-member", "since-day",
                "other-anchor"):
        assert cid in ids
        assert next(c for c in CASES if c["id"] == cid)["expected"]["fails"], cid


def test_counts_integral_reads_the_value() -> None:
    """SH §4 "Counts": JCS writes 75.0 as 75, so an integral float is a count and 0.5 is not."""
    card = json.loads(json.dumps(CASES[0]["inputs"]["card"]))
    card["outcomes"]["held"] = 3.0
    assert sh.check_card(card)["counts_integral"] == "PASS"
    card["outcomes"]["held"] = 2 ** 53
    assert sh.check_card(card)["counts_integral"] == "FAIL"
    card["outcomes"]["held"] = -1
    assert sh.check_card(card)["counts_integral"] == "FAIL"


def test_card_form_rejects_a_boolean_count() -> None:
    card = json.loads(json.dumps(CASES[0]["inputs"]["card"]))
    card["roles"]["bought"] = True
    assert sh.check_card(card)["card_form"] == "FAIL"


def test_malformed_input_raises() -> None:
    c = CASES[0]
    deals = json.loads(json.dumps(c["inputs"]["deals"]))
    deals[0]["counterparty_class"] = "a_shop"
    with pytest.raises(ValueError):
        sh.check_card(c["inputs"]["card"], policy=c["inputs"]["policy"], as_of=c["inputs"]["as_of"], deals=deals)


@pytest.mark.parametrize("change", [
    {"amount": {"value": "500", "assetCode": "USD", "assetScale": "2"}},   # SR "Amounts" rule 2
    {"amount": {"value": "500", "assetCode": "Example Bakery", "assetScale": 2}},
    {"agreed_at": "\u0662\u0660\u0662\u0666-09-02T10:00:00Z"},   # Python's strptime reads these digits
    {"counterparty_class": None},
])
def test_malformed_deal_entry_raises(change: dict) -> None:
    c = CASES[0]
    deals = json.loads(json.dumps(c["inputs"]["deals"]))
    deals[0].update(change)
    with pytest.raises(ValueError):
        sh.check_card(c["inputs"]["card"], policy=c["inputs"]["policy"], as_of=c["inputs"]["as_of"], deals=deals)


def test_integral_float_months_is_a_whole_number_of_months() -> None:
    """SH §4 "Counts": a policy window of 3.0 months is 3 months, as in Go."""
    c = CASES[0]
    policy = {**c["inputs"]["policy"], "window": {"months": 3.0}}
    assert sh.check_card(c["inputs"]["card"], policy=policy, as_of=c["inputs"]["as_of"],
                         deals=c["inputs"]["deals"]) == c["expected"]["properties"]


def test_is_standard_needs_every_property() -> None:
    props = dict(CASES[0]["expected"]["properties"])
    props["counts_recompute"] = "INCONCLUSIVE"
    assert not sh.is_standard(props)
    del props["counts_recompute"]
    assert not sh.is_standard(props)


def test_card_of_null_has_no_numbers() -> None:
    """As in Go: JSON null is a card with no numbers, so counts_integral is PASS and card_form FAIL."""
    props = sh.check_card(None)
    assert props["card_form"] == "FAIL" and props["counts_integral"] == "PASS"


def _mutant_disagrees(monkeypatch: pytest.MonkeyPatch, name: str, replacement) -> bool:
    with monkeypatch.context() as m:
        m.setattr(sh, name, replacement)
        return any(_check(c) != c["expected"]["properties"] or (_derivable(c) and _derive(c) != c["inputs"]["card"])
                   for c in CASES)


def _partitions_only(card: dict) -> bool:
    """A denominator check that skips the cross-tally totals of SH §4."""
    return all("of" in card[name] and (name == "class_missing" or sh._partitions(card[name], parts))
               for name, parts in sh.TALLIES.items())


def test_defective_evaluators_disagree(monkeypatch: pytest.MonkeyPatch) -> None:
    real_in_window, real_window_start, real_decade = sh._in_window, sh._window_start, sh._decade
    mutants = {
        "counts every shop purchase": ("NOT_COUNTED", "no_such_class"),
        "ignores the window": ("_in_window", lambda d, w, t: d <= t),
        "drops the deal at the window start": ("_in_window", lambda d, w, t: real_in_window(d, w, t) and (
            w.get("all") is True or d > real_window_start(t, w["months"]))),
        "overflows the month end instead of clamping": ("_window_start", lambda t, n: real_window_start(
            t.replace(day=1), n) + timedelta(days=t.day - 1)),
        "decade off by one": ("_decade", lambda a: real_decade(a) + 1),
        "accepts any number": ("_counts_integral", lambda card: True),
        "checks no cross-tally total": ("_denominator", _partitions_only),
        "lets a node card carry the person class": ("CONTROLLER_CLASSES", {"person": "person_declared",
                                                                            "node": "person_declared"}),
    }
    agreeing = [desc for desc, (name, value) in mutants.items()
                if not _mutant_disagrees(monkeypatch, name, value)]
    assert agreeing == []


def _regenerate(out: Path) -> None:
    out.mkdir()
    for name in HAND_WRITTEN:
        shutil.copy(VECTORS / name, out / name)
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(out)], check=True)


def test_regenerates_byte_identical(tmp_path: Path) -> None:
    for run in ("a", "b"):
        out = tmp_path / run
        _regenerate(out)
        committed = sorted(p.relative_to(VECTORS).as_posix() for p in VECTORS.rglob("*") if p.is_file())
        produced = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
        assert produced == committed
        for rel in committed:
            assert (out / rel).read_bytes() == (VECTORS / rel).read_bytes(), rel


def test_sha256sums() -> None:
    lines = (VECTORS / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    listed = {}
    for line in lines:
        digest, rel = line.split("  ", 1)
        listed[rel] = digest
    files = {p.relative_to(VECTORS).as_posix() for p in VECTORS.rglob("*") if p.is_file()} - {"SHA256SUMS"}
    assert set(listed) == files
    for rel, digest in listed.items():
        assert hashlib.sha256((VECTORS / rel).read_bytes()).hexdigest() == digest, rel
