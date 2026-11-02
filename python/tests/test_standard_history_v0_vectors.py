# SPDX-License-Identifier: BSD-3-Clause
"""The standard history vectors (``vectors/standard-history-v0/``).

Every case runs from its inputs alone through ``agent_action_capsule.standard_history``:

- ``check_card`` reports the six card properties of ``spec/standard-history-v0.md`` (SH) §6,
  compared with the case's whole ``expected`` block, which the generator states by hand;
- for every standard card checked with the policy, the anchor and the deal entries,
  ``derive_card`` rebuilds exactly the case's card from them.

``vectors.json`` holds the ``standard_history/1`` cases and ``vectors-2.json`` the
``standard_history/2`` ones; a case's ``inputs.derivation`` names the token it is checked under,
``/1`` when absent.

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
DATA_2 = json.loads((VECTORS / "vectors-2.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
CASES_2 = DATA_2["cases"]
ALL_CASES = CASES + CASES_2


def _check(c: dict) -> dict:
    i = c["inputs"]
    return sh.check_card(i["card"], policy=i.get("policy"), as_of=i.get("as_of"), deals=i.get("deals"),
                         derivation=i.get("derivation", sh.DERIVATION))


def _derivable(c: dict) -> bool:
    return c["expected"]["standard"] and all(k in c["inputs"] for k in ("policy", "as_of", "deals"))


def _derive(c: dict) -> dict:
    i, card = c["inputs"], c["inputs"]["card"]
    return sh.derive_card(holder_kind=card["holder_kind"], controller_class=card["controller_class"],
                          anchor=i["as_of"]["anchor"], anchor_time=i["as_of"]["anchor_time"],
                          first_checkpoint_time=i["as_of"]["first_checkpoint_time"], policy=i["policy"],
                          deals=i["deals"], derivation=i.get("derivation", sh.DERIVATION))


def test_corpus_header() -> None:
    for data in (DATA, DATA_2):
        assert data["spec"] == "spec/standard-history-v0.md"
        assert tuple(data["properties"]) == sh.PROPERTIES
        assert data["count"] == len(data["cases"])
    assert DATA_2["derivation"] == sh.DERIVATION_2
    assert all(c["inputs"]["derivation"] in sh.DERIVATIONS for c in CASES_2)
    assert not any("derivation" in c["inputs"] for c in CASES)
    spec = (ROOT / DATA["spec"]).read_text(encoding="utf-8")
    for prop in sh.PROPERTIES:
        assert f"| `{prop}` |" in spec, prop


@pytest.mark.parametrize("c", ALL_CASES, ids=[c["id"] for c in ALL_CASES])
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


def test_every_negative_named_for_v2_is_present() -> None:
    """SH §6 "Vectors": the /2 negatives, each failing the property named."""
    fails = {c["id"]: c["expected"]["fails"] for c in CASES_2}
    assert fails["unpriced-left-out"] == ["counts_recompute"]
    assert fails["unpriced-in-band"] == ["counts_recompute"]
    assert fails["unpriced-outside-outcomes"] == ["denominator"]
    for cid in ("v2-without-unpriced", "v1-card-with-unpriced", "unpriced-with-currency",
                "v1-card-for-v2-request", "v2-card-for-v1-request"):
        assert fails[cid] == ["card_form"], cid
    assert next(c for c in CASES_2 if c["id"] == "unpriced-counted")["expected"]["standard"]


def test_v1_cannot_count_an_unpriced_deal() -> None:
    """SH §3, §5.2: a /1 deal entry needs an amount, so a /1 card over an unpriced deal cannot be built;
    the same entries build a /2 card."""
    c = next(c for c in CASES_2 if c["id"] == "unpriced-counted")
    i = c["inputs"]
    with pytest.raises(ValueError):
        sh.derive_card(holder_kind="person", controller_class="person_declared", anchor=i["as_of"]["anchor"],
                       anchor_time=i["as_of"]["anchor_time"],
                       first_checkpoint_time=i["as_of"]["first_checkpoint_time"], policy=i["policy"],
                       deals=i["deals"])
    with pytest.raises(ValueError):
        sh.check_card(CASES[0]["inputs"]["card"], policy=i["policy"], as_of=i["as_of"], deals=i["deals"])
    assert _derive(c) == i["card"]


@pytest.mark.parametrize("amount", [None, {}, {"value": "500", "assetScale": 2}])
def test_v2_amount_present_must_be_an_amount(amount) -> None:
    """SH §5.2: under /2 an amount is absent or an SR amount triple; null is neither."""
    c = next(c for c in CASES_2 if c["id"] == "unpriced-counted")
    deals = json.loads(json.dumps(c["inputs"]["deals"]))
    deals[-2]["amount"] = amount
    with pytest.raises(ValueError):
        _check({**c, "inputs": {**c["inputs"], "deals": deals}})


def test_unknown_token_raises() -> None:
    with pytest.raises(ValueError):
        sh.check_card(CASES[0]["inputs"]["card"], derivation="standard_history/3")


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
    {"amount": {"value": "500", "assetCode": "USD", "assetScale": 2.0}},
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
                   for c in ALL_CASES)


def _partitions_only(card: dict) -> bool:
    """A denominator check that skips the cross-tally totals of SH §4."""
    return all("of" in card[name] and (name == "class_missing" or sh._partitions(card[name], parts))
               for name, parts in sh.TALLIES.items())


_REAL_DENOMINATOR = sh._denominator


def _bands_only(card: dict) -> bool:
    """A denominator check that reads a /2 card as a /1 one: the bands alone partition the outcomes."""
    return _REAL_DENOMINATOR({k: v for k, v in card.items() if k != "unpriced"})


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
        "lets a /2 card leave out unpriced": ("MEMBERS", {**sh.MEMBERS, sh.DERIVATION_2: sh.CARD_MEMBERS}),
        "lets a /1 card carry unpriced": ("MEMBERS", {**sh.MEMBERS, sh.DERIVATION: sh.MEMBERS[sh.DERIVATION_2]}),
        "leaves unpriced out of the outcome totals": ("_denominator", _bands_only),
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
