# SPDX-License-Identifier: BSD-3-Clause
"""The standard history vectors (``vectors/standard-history-v0/``).

Every case runs from its inputs alone through ``agent_action_capsule.standard_history``:

- ``check_card`` reports the six card properties of ``spec/standard-history-v0.md`` (SH) §6,
  compared with the case's whole ``expected`` block, which the generator states by hand;
- for every standard card checked with the policy, the anchor and the deal entries,
  ``derive_card`` rebuilds exactly the case's card from them.

``vectors.json`` holds the ``standard_history/1`` cases, ``vectors-2.json`` the
``standard_history/2`` ones, ``vectors-3.json`` the ``standard_history/3`` ones (SH §11),
``vectors-4.json`` the ``standard_history/4`` ones (SH §12) and ``vectors-5.json`` the
``standard_history/5`` ones (SH §14); a case's ``inputs.derivation`` names the token it is checked under,
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
DATA_3 = json.loads((VECTORS / "vectors-3.json").read_text(encoding="utf-8"))
DATA_4 = json.loads((VECTORS / "vectors-4.json").read_text(encoding="utf-8"))
DATA_5 = json.loads((VECTORS / "vectors-5.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
CASES_2 = DATA_2["cases"]
CASES_3 = DATA_3["cases"]
CASES_4 = DATA_4["cases"]
CASES_5 = DATA_5["cases"]
ALL_CASES = CASES + CASES_2 + CASES_3 + CASES_4 + CASES_5


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
                          deals=i["deals"], derivation=i.get("derivation", sh.DERIVATION),
                          coverage_start_time=i["as_of"].get("coverage_start_time"))


def test_corpus_header() -> None:
    for data in (DATA, DATA_2, DATA_3, DATA_4, DATA_5):
        assert data["spec"] == "spec/standard-history-v0.md"
        assert tuple(data["properties"]) == sh.PROPERTIES
        assert data["count"] == len(data["cases"])
    assert DATA_2["derivation"] == sh.DERIVATION_2
    assert DATA_3["derivation"] == sh.DERIVATION_3
    assert DATA_4["derivation"] == sh.DERIVATION_4
    assert DATA_5["derivation"] == sh.DERIVATION_5
    assert all(c["inputs"]["derivation"] in sh.DERIVATIONS for c in CASES_2 + CASES_3 + CASES_4 + CASES_5)
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


def test_every_negative_named_for_v3_is_present() -> None:
    """SH §11.10: the /3 cases, each negative failing the property named."""
    fails = {c["id"]: c["expected"]["fails"] for c in CASES_3}
    for cid in ("outcome-not-first", "dispute-hides-unmet", "ruling-not-honoured-undecided", "other-side-did-not-hold",
                "not-reached-left-out", "not-reached-hides-unmet", "not-honoured-uncounted",
                "left-out-counted", "local-times-dropped", "refund-not-remedied",
                "not-counted-wrong-reason"):
        assert fails[cid] == ["counts_recompute"], cid
    for cid in ("remedied-not-did-not-hold", "not-honoured-not-did-not-hold", "remedied-and-not-honoured",
                "not-counted-not-the-window"):
        assert fails[cid] == ["denominator"], cid
    assert fails["coverage-start-other-month"] == ["as_of"]
    for cid in ("outcomes-five-lines", "band-five-lines", "v3-card-for-v2-request"):
        assert fails[cid] == ["card_form"], cid
    for cid in ("no-coverage-start", "coverage-start-before-since", "v2-card-for-v3-request"):
        assert fails[cid][0] == "card_form", cid
    for cid in ("outcomes-from-rows", "quiet-deals-later-anchor"):
        c = next(c for c in CASES_3 if c["id"] == cid)
        assert c["expected"]["standard"] and _derivable(c), cid


def test_every_case_named_for_v4_is_present() -> None:
    """SH §12 "Vectors": the /4 cases, each negative failing the property named."""
    fails = {c["id"]: c["expected"]["fails"] for c in CASES_4}
    for cid in ("no-witness-time-left-out", "silent-deal-not-local"):
        assert fails[cid] == ["counts_recompute"], cid
    for cid in ("not-counted-member", "v3-card-for-v4-request", "v4-card-for-v3-request"):
        assert fails[cid] == ["card_form"], cid
    c = next(c for c in CASES_4 if c["id"] == "no-witness-time-counted")
    assert c["expected"]["standard"] and _derivable(c)
    # SH §12: every deal without a witness time carries no_witness_time; the silent one has no local row.
    flagged = {d["deal"]: d for d in c["inputs"]["deals"] if d.get("no_witness_time")}
    assert set(flagged) == {"deal-311", "deal-315", "deal-316"}
    assert not any(r.get("local") for r in flagged["deal-316"]["rows"])
    assert not any("left_out" in d for d in c["inputs"]["deals"])


@pytest.mark.parametrize("change", [{"left_out": "no_witness_time"}, {"no_witness_time": False},
                                    {"no_witness_time": "true"}])
def test_malformed_v4_deal_entry_raises(change: dict) -> None:
    """SH §12: a /4 deal entry has no left_out, and no_witness_time only as true."""
    c = next(c for c in CASES_4 if c["id"] == "no-witness-time-counted")
    deals = json.loads(json.dumps(c["inputs"]["deals"]))
    deals[0].update(change)
    with pytest.raises(ValueError):
        _check({**c, "inputs": {**c["inputs"], "deals": deals}})


def test_every_case_named_for_v5_is_present() -> None:
    """SH §14 "Vectors": the /5 cases, each negative failing the property named."""
    fails = {c["id"]: c["expected"]["fails"] for c in CASES_5}
    for cid in ("shop-purchases-dropped", "shop-dispute-dropped", "shop-preauth-uncounted"):
        assert fails[cid] == ["counts_recompute"], cid
    for cid in ("shop-purchases-not-counted", "shop-preauth-not-the-counted", "shop-preauth-and-class-missing"):
        assert fails[cid] == ["denominator"], cid
    for cid in ("v4-card-for-v5-request", "v5-card-for-v4-request"):
        assert fails[cid] == ["card_form"], cid
    c = next(c for c in CASES_5 if c["id"] == "shop-purchases-counted")
    assert c["expected"]["standard"] and _derivable(c)
    # SH §14 (AAC#682 acceptance 5): a shop purchase with a dispute the holder raised, counted.
    shops = [d for d in c["inputs"]["deals"] if d.get("counterparty_class") == "shop_preauth"]
    assert any(x["side"] == "raised" for d in shops for x in d["disputes"])
    assert c["inputs"]["card"]["shop_preauth"] == {"of": 16, "count": len(shops)}
    assert c["inputs"]["card"]["in_window"]["not_counted"] == 0


def test_v5_counts_what_v4_leaves_out() -> None:
    """SH §14: the same shelf under /4 leaves the shop purchases and their disputes out; /5 counts them."""
    c = next(c for c in CASES_5 if c["id"] == "shop-purchases-counted")
    v4 = _derive({**c, "inputs": {**c["inputs"], "derivation": sh.DERIVATION_4}})
    v5 = _derive(c)
    assert v4["in_window"] == {"of": 16, "counted": 14, "not_counted": 2} and "shop_preauth" not in v4
    assert v5["in_window"] == {"of": 16, "counted": 16, "not_counted": 0}
    assert v5["disputes"]["raised"]["of"] == v4["disputes"]["raised"]["of"] + 1
    assert v5["disputes"]["received"]["of"] == v4["disputes"]["received"]["of"] + 1


@pytest.mark.parametrize("change", [{"left_out": "no_witness_time"}, {"no_witness_time": False}])
def test_malformed_v5_deal_entry_raises(change: dict) -> None:
    """SH §14: a /5 deal entry is a /4 one: no left_out, and no_witness_time only as true."""
    c = next(c for c in CASES_5 if c["id"] == "shop-purchases-counted")
    deals = json.loads(json.dumps(c["inputs"]["deals"]))
    deals[0].update(change)
    with pytest.raises(ValueError):
        _check({**c, "inputs": {**c["inputs"], "deals": deals}})


def test_v3_refuses_no_witness_time() -> None:
    """SH §11.2: no_witness_time is a /4 member only."""
    c = next(c for c in CASES_3 if c["id"] == "outcomes-from-rows")
    deals = json.loads(json.dumps(c["inputs"]["deals"]))
    deals[0]["no_witness_time"] = True
    with pytest.raises(ValueError):
        _check({**c, "inputs": {**c["inputs"], "deals": deals}})


def test_v3_outcomes_cover_every_row_result() -> None:
    """SH §11.3: every combination of row results has exactly one outcome, and only a
    did_not_hold deal has a detail (§11.4)."""
    results = [{"status": s} for s in ("not_reached", "not_due", "no_statement", "in_disagreement",
                                       "in_dispute")]
    results += [{"status": "waiting", "value": v} for v in sh.ROW_VALUES]
    results += [{"status": s, "value": "met"} for s in sh.UNMET_STATUSES]
    results += [{"status": s, "value": "not_met", "remedy": r} for s in sh.UNMET_STATUSES
                for r in sh.UNRULED_REMEDIES]
    results += [{"status": "ruled", "value": v, "remedy": r} for v in sh.ROW_VALUES for r in sh.REMEDIES]
    rows = [{"owed_by": o, **r} for o in sh.OWED_BY for r in results]
    for r in rows:
        sh._check_row("x", r)
    for a in rows:
        for b in rows:
            outcome, detail = sh.outcome([a, b])
            assert outcome in sh.OUTCOMES
            assert detail in ((None, "remedied", "not_honoured") if outcome == "did_not_hold" else (None,))


def _row(owed_by: str, status: str, value: str | None = None, remedy: str | None = None) -> dict:
    r = {"owed_by": owed_by, "status": status}
    if value is not None:
        r["value"] = value
    if remedy is not None:
        r["remedy"] = remedy
    return r


@pytest.mark.parametrize("rows, outcome", [
    ([_row("counterparty", "uncontested", "not_met", "none")], "held"),
    ([_row("counterparty", "ruled", "not_met", "not_honoured"), _row("holder", "agreed", "met")], "held"),
    ([_row("counterparty", "agreed_so_far", "not_met", "none")], "undecided"),
    ([_row("counterparty", "waiting", "not_met")], "undecided"),
    ([_row("holder", "agreed", "met"), _row("counterparty", "not_reached")], "undecided"),
    ([_row("holder", "agreed", "not_met", "none"), _row("counterparty", "not_reached")], "did_not_hold"),
    ([_row("holder", "ruled", "not_met", "not_honoured"), _row("counterparty", "in_dispute")], "did_not_hold"),
    ([_row("holder", "agreed", "not_met", "none"), _row("counterparty", "in_dispute")], "did_not_hold"),
    ([_row("holder", "agreed_so_far", "not_met", "none"), _row("counterparty", "in_dispute")], "undecided"),
    ([_row("holder", "agreed_so_far", "not_met", "none"), _row("counterparty", "not_due")], "did_not_hold"),
    ([_row("holder", "agreed", "not_met", "none"), _row("counterparty", "not_due")], "did_not_hold"),
    ([_row("holder", "agreed_so_far", "met"), _row("counterparty", "agreed", "met")], "undecided"),
])
def test_v3_outcome_rules(rows: list, outcome: str) -> None:
    """SH §11.3: only rows the holder owed make a deal did_not_hold, a ruling the holder did not
    honour comes first, and a not_reached row makes the deal undecided unless did_not_hold applies,
    as does a row not final."""
    assert sh.outcome(rows)[0] == outcome


@pytest.mark.parametrize("remedies, detail", [
    (("none", "made"), None),
    (("due", "made"), None),
    (("made", "made"), "remedied"),
    (("made", "not_honoured"), "not_honoured"),
    (("none", "not_honoured"), "not_honoured"),
    (("due", "not_honoured"), "not_honoured"),
])
def test_v3_remedied(remedies: tuple, detail: str | None) -> None:
    """SH §11.4: a did_not_hold deal is remedied only when every unmet row the holder owed has its
    remedy made, by a ruling or without one, and a ruling not honoured comes first, whatever the
    order of the rows."""
    rows = [_row("holder", "ruled", "not_met", r) for r in remedies]
    unruled = [_row("holder", "agreed", "not_met", "made")]
    for rs in (rows, rows[::-1], unruled + rows):
        assert sh.outcome(rs) == ("did_not_hold", detail)


def test_v3_as_of_without_anchor_time_raises() -> None:
    """A /3 as_of input without its anchor time is malformed input, never an as_of FAIL."""
    c = next(c for c in CASES_3 if c["id"] == "outcomes-without-shelf")
    as_of = {k: v for k, v in c["inputs"]["as_of"].items() if k != "anchor_time"}
    with pytest.raises(ValueError):
        sh.check_card(c["inputs"]["card"], as_of=as_of, derivation=sh.DERIVATION_3)


def test_v3_quiet_deal_moves_outcome_with_the_anchor() -> None:
    """SH §11.1: the same deal, with no new fact, has another outcome at a later anchor."""
    a = next(c for c in CASES_3 if c["id"] == "outcomes-from-rows")["inputs"]["deals"]
    b = next(c for c in CASES_3 if c["id"] == "quiet-deals-later-anchor")["inputs"]["deals"]
    moved = {x["deal"]: (sh.outcome(x["rows"])[0], sh.outcome(y["rows"])[0])
             for x, y in zip(a, b) if sh.outcome(x["rows"]) != sh.outcome(y["rows"])}
    assert moved == {"deal-314": ("undecided", "held")}


@pytest.mark.parametrize("change", [
    {"outcome": "held"},                                              # /3 reads no outcome claim
    {"rows": []},
    {"rows": [{"owed_by": "holder", "status": "agreed"}]},            # agreed carries a value
    {"rows": [{"owed_by": "holder", "status": "not_due", "value": "met"}]},
    {"rows": [{"owed_by": "holder", "status": "ruled", "value": "met"}]},   # ruled carries a remedy
    {"rows": [{"owed_by": "seller", "status": "not_due"}]},
    {"left_out": "late"},
    {"rows": [{"owed_by": "holder", "status": "agreed", "value": "not_met"}]},   # unmet: remedy required
    {"rows": [{"owed_by": "holder", "status": "agreed", "value": "not_met", "remedy": "due"}]},
    {"rows": [{"owed_by": "holder", "status": "not_due", "local": False}]},
    {"rows": [{"owed_by": "holder", "status": "not_due", "value": ""}]},
])
def test_malformed_v3_deal_entry_raises(change: dict) -> None:
    c = next(c for c in CASES_3 if c["id"] == "outcomes-from-rows")
    deals = json.loads(json.dumps(c["inputs"]["deals"]))
    deals[0].update(change)
    with pytest.raises(ValueError):
        _check({**c, "inputs": {**c["inputs"], "deals": deals}})


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
    deals[-4]["amount"] = amount   # deal-09, counted and unpriced
    with pytest.raises(ValueError):
        _check({**c, "inputs": {**c["inputs"], "deals": deals}})


def test_unknown_token_raises() -> None:
    with pytest.raises(ValueError):
        sh.check_card(CASES[0]["inputs"]["card"], derivation="standard_history/6")


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


def _partitions_only(card: dict, derivation: str) -> bool:
    """A denominator check that skips the cross-tally totals of SH §4."""
    return all("of" in card[name] and (name == "class_missing" or sh._partitions(card[name], parts))
               for name, parts in sh._tallies(derivation).items())


_REAL_DENOMINATOR = sh._denominator


def _bands_only(card: dict, derivation: str) -> bool:
    """A denominator check that reads a /2 card as a /1 one: the bands alone partition the outcomes."""
    return _REAL_DENOMINATOR({k: v for k, v in card.items() if k != "unpriced"}, derivation)


def _remedied_unchecked(card: dict, derivation: str) -> bool:
    """A denominator check that does not tie remedied to did_not_hold (SH §11.6)."""
    return _REAL_DENOMINATOR(card, sh.DERIVATION_2 if derivation == sh.DERIVATION_3 else derivation)


_REAL_OUTCOME = sh.outcome


def _open_unmet_first(rows):
    """An outcome function that reads an unmet row still in its contest window before the rows
    in dispute (SH §11.3)."""
    if any(r["owed_by"] == "holder" and r["status"] == "agreed_so_far" and r.get("value") == "not_met"
           for r in rows):
        return "did_not_hold", None
    return _REAL_OUTCOME(rows)


def _dispute_first(rows):
    """An outcome function where a row in dispute hides a final unmet row (SH §11.3)."""
    if _REAL_OUTCOME(rows)[1] != "not_honoured" and any(
            r["status"] in ("in_disagreement", "in_dispute", "no_statement")
            or (r["status"] == "waiting" and r.get("value") == "not_met") for r in rows):
        return "undecided", None
    return _REAL_OUTCOME(rows)


def _counterparty_blamed(rows):
    """An outcome function that blames the holder for the counterparty's rows too (SH §11.3)."""
    return _REAL_OUTCOME([{**r, "owed_by": "holder"} for r in rows])


def _not_reached_left_out(rows):
    """An outcome function that leaves a not_reached row out, as the design's text did."""
    kept = [r for r in rows if r["status"] != "not_reached"]
    return _REAL_OUTCOME(kept) if kept else ("undecided", None)


def _not_reached_first(rows):
    """An outcome function where a not_reached row hides an unmet row (SH §11.3)."""
    if any(r["status"] == "not_reached" for r in rows) and _REAL_OUTCOME(rows)[1] != "not_honoured":
        return "undecided", None
    return _REAL_OUTCOME(rows)


_REAL_COUNTS = sh._counts


def _counting_left_out(deals, window, anchor_time, derivation=sh.DERIVATION):
    """Counts as if no deal carried left_out (SH §11.2)."""
    return _REAL_COUNTS([{k: v for k, v in d.items() if k != "left_out"} for d in deals], window, anchor_time,
                        derivation)


def _counting_left_out_first(deals, window, anchor_time, derivation=sh.DERIVATION):
    """Counts a deal not counted under no_witness_time whenever it carries left_out, before
    shop_preauth (SH §11.6 takes shop_preauth first)."""
    t = _REAL_COUNTS(deals, window, anchor_time, derivation)
    if "not_counted" in t:
        both = sum(1 for d in deals if d.get("counterparty_class") == sh.NOT_COUNTED and "left_out" in d
                   and sh._in_window(sh._time(d["agreed_at"]), window, anchor_time))
        t["not_counted"]["shop_preauth"] -= both
        t["not_counted"]["no_witness_time"] += both
    return t


def _v4_leaves_out_untimed(deals, window, anchor_time, derivation=sh.DERIVATION):
    """Counts a /4 deal with no witnessed time as /3 counts a deal left out (SH §12 counts it)."""
    if derivation == sh.DERIVATION_4:
        deals = [d for d in deals if not d.get("no_witness_time")]
    return _REAL_COUNTS(deals, window, anchor_time, derivation)


def _v4_local_rows_only(deals, window, anchor_time, derivation=sh.DERIVATION):
    """Counts local_times from the rows alone, ignoring no_witness_time (SH §12)."""
    return _REAL_COUNTS([{k: v for k, v in d.items() if k != "no_witness_time"} for d in deals], window,
                        anchor_time, derivation)


def _v5_leaves_shops_out(deals, window, anchor_time, derivation=sh.DERIVATION):
    """Counts a /5 card's deals as /4 counts them, shop purchases left out (SH §14 counts them)."""
    if derivation != sh.DERIVATION_5:
        return _REAL_COUNTS(deals, window, anchor_time, derivation)
    t = _REAL_COUNTS(deals, window, anchor_time, sh.DERIVATION_4)
    t["shop_preauth"] = {"of": t["in_window"]["counted"], "count": 0}
    return t


def _v5_drops_shop_disputes(deals, window, anchor_time, derivation=sh.DERIVATION):
    """Counts a shop purchase under /5 but not its disputes (SH §14 counts them)."""
    if derivation == sh.DERIVATION_5:
        deals = [{**d, "disputes": []} if d.get("counterparty_class") == "shop_preauth" else d for d in deals]
    return _REAL_COUNTS(deals, window, anchor_time, derivation)


def _v5_denominator_as_v4(card: dict, derivation: str) -> bool:
    """A denominator check that reads a /5 card by /4's rules, without SH §14's."""
    if derivation == sh.DERIVATION_5:
        return _REAL_DENOMINATOR({k: v for k, v in card.items() if k != "shop_preauth"}, sh.DERIVATION_4)
    return _REAL_DENOMINATOR(card, derivation)


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
        "does not tie remedied to did_not_hold": ("_denominator", _remedied_unchecked),
        "takes an open unmet row before undecided": ("outcome", _open_unmet_first),
        "lets a dispute hide a final unmet row": ("outcome", _dispute_first),
        "blames the holder for the counterparty's rows": ("outcome", _counterparty_blamed),
        "leaves a not_reached row out": ("outcome", _not_reached_left_out),
        "lets a not_reached row hide an unmet row": ("outcome", _not_reached_first),
        "does not count a ruling not honoured": ("outcome", lambda rows: (
            (o := _REAL_OUTCOME(rows))[0], None if o[1] == "not_honoured" else o[1])),
        "counts a deal left out": ("_counts", _counting_left_out),
        "takes left_out before shop_preauth": ("_counts", _counting_left_out_first),
        "lets a /3 card leave out coverage_start": ("MEMBERS", {**sh.MEMBERS, sh.DERIVATION_3:
                                                                sh.MEMBERS[sh.DERIVATION_3] - {"coverage_start"}}),
        "leaves out a /4 deal without a witness time": ("_counts", _v4_leaves_out_untimed),
        "counts local_times from the rows alone": ("_counts", _v4_local_rows_only),
        "lets a /4 card carry not_counted": ("MEMBERS", {**sh.MEMBERS, sh.DERIVATION_4: sh.MEMBERS[sh.DERIVATION_3]}),
        "leaves /5 shop purchases out as /4 does": ("_counts", _v5_leaves_shops_out),
        "drops a /5 shop purchase's disputes": ("_counts", _v5_drops_shop_disputes),
        "checks a /5 card's denominators as /4's": ("_denominator", _v5_denominator_as_v4),
        "lets a /5 card leave out shop_preauth": ("MEMBERS", {**sh.MEMBERS, sh.DERIVATION_5: sh.MEMBERS[sh.DERIVATION_4]}),
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
