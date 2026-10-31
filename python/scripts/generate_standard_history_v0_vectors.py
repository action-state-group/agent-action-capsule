#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the standard history vectors (``spec/standard-history-v0.md``, cited as SH).

Each case is one card with what a verifier may hold beside it: the policy's window and digest
(SH §5.1), the anchor (SH §6 ``as_of``) and the deal entries (SH §5.2). SH §6 lists the
negatives.

Every card and every expected property is stated here by hand from SH §4 to §6. The script
imports no implementation: ``python/tests/test_standard_history_v0_vectors.py`` runs the Python
reference (``agent_action_capsule.standard_history``) and ``go/standardhistory`` runs the Go one
against these files.

Output: ``vectors/standard-history-v0/`` (or ``--out DIR``). Deterministic: no clock, no
randomness; every digest is a label digest for these vectors only. ``README.md`` is never
rewritten; every file in the directory is listed in ``SHA256SUMS``. Standard library only.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import history_frame

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "standard-history-v0"
SET = "aac-standard-history-v0"
SPEC = "spec/standard-history-v0.md"
GENERATOR = "python/scripts/generate_standard_history_v0_vectors.py"
STATUS = ("Conformance vectors for the informational Standard History Derivation v0 "
          "(spec/standard-history-v0.md), standard_history/1. Every digest is a label digest for these "
          "vectors only.")
PROPERTIES = ("card_form", "counts_integral", "denominator", "window_from_policy", "as_of",
              "counts_recompute")


def label(text: str) -> str:
    return hashlib.sha256(f"standard-history-v0 vectors: {text}".encode()).hexdigest()


ANCHOR = label("the anchor of the holder's stream")
ANCHOR_TIME = "2026-10-28T12:00:00Z"
FIRST_CHECKPOINT = "2026-03-04T09:00:00Z"
AS_OF = {"anchor": ANCHOR, "anchor_time": ANCHOR_TIME, "first_checkpoint_time": FIRST_CHECKPOINT}
POLICY_3M = {"digest": label("the holder's policy, window 3 months"), "window": {"months": 3}}
# 30000 months back from 2026 is before year 1: every deal is after the start (SH §5.1).
POLICY_FAR = {"digest": label("the holder's policy, window 30000 months"), "window": {"months": 30000}}
POLICY_ALL = {"digest": label("the holder's policy, window everything"), "window": {"all": True}}


def amount(value: str, code: str, scale: int) -> dict:
    """SR "Amounts". The band is the asset code, so these are real codes; the deals are not real."""
    return {"assetCode": code, "assetScale": scale, "value": value}


def deal(ref: str, agreed_at: str, role: str, amt: dict, outcome: str, happened: str,
         cls: str | None, disputes: tuple = ()) -> dict:
    d = {"deal": ref, "agreed_at": agreed_at, "role": role, "amount": amt, "outcome": outcome,
         "happened": happened,
         "disputes": [{"side": s, "outcome": o, "forum": f} for s, o, f in disputes]}
    if cls is not None:
        d["counterparty_class"] = cls
    return d


# The holder's stream at the anchor. With the 3-month window, S is 2026-07-28T12:00:00Z (SH §5.1).
DEALS = [
    # 45.00 USD: decade 1.
    deal("deal-01", "2026-09-02T10:00:00Z", "provided", amount("4500", "USD", 2), "held", "stamped_by_both",
         "person_agent"),
    # 120.00 USD: decade 2.
    deal("deal-02", "2026-08-15T10:00:00Z", "bought", amount("12000", "USD", 2), "held", "receipt_only",
         "business_agent", (("raised", "for", "rail"),)),
    # No counterparty_class: counted, and in class_missing. 18.50 USD: decade 1.
    deal("deal-03", "2026-10-20T10:00:00Z", "provided", amount("1850", "USD", 2), "undecided", "no_record",
         None, (("received", "open", "network"),)),
    # Agreed exactly at S: in the window. 9.99 EUR: decade 0.
    deal("deal-04", "2026-07-28T12:00:00Z", "bought", amount("999", "EUR", 2), "did_not_hold", "stamped_by_both",
         "person_agent", (("raised", "split", "auto"),)),
    # A shop purchase paid up front: in the window, not counted. Its dispute counts nowhere.
    deal("deal-05", "2026-09-10T10:00:00Z", "bought", amount("6000", "USD", 2), "held", "receipt_only",
         "shop_preauth", (("received", "open", "rail"),)),
    deal("deal-06", "2026-10-01T10:00:00Z", "bought", amount("500", "USD", 2), "held", "receipt_only",
         "shop_preauth"),
    # One second before S: outside a 3-month window, inside "all". 300 USD: decade 2.
    deal("deal-07", "2026-07-28T11:59:59Z", "provided", amount("300", "USD", 0), "held", "stamped_by_both",
         "person_agent"),
    # 21000 millisatoshi (21 sat): 5 digits, scale 11, so decade 5 - 11 - 1 = -7.
    deal("deal-08", "2026-10-27T10:00:00Z", "provided", amount("21000", "BTC", 11), "held", "receipt_only",
         "business_agent"),
]


def tally(of: int, **parts: int) -> dict:
    return {"of": of, **parts}


def band(currency: str, decade: int | None, of: int, held: int = 0, did_not_hold: int = 0, undecided: int = 0) -> dict:
    return {"currency": currency, "decade": decade, "of": of, "held": held, "did_not_hold": did_not_hold,
            "undecided": undecided}


def disputes_tally(of: int, outcomes: dict, forums: dict) -> dict:
    by_outcome = {o: 0 for o in ("open", "for", "against", "split", "no_finding", "withdrawn")}
    by_outcome.update(outcomes)
    by_forum = {f: 0 for f in ("auto", "network", "rail", "external")}
    by_forum.update(forums)
    return {"of": of, "by_outcome": {"of": of, **by_outcome}, "by_forum": {"of": of, **by_forum}}


NO_DISPUTES = {"raised": disputes_tally(0, {}, {}), "received": disputes_tally(0, {}, {})}


def card(*, holder_kind: str = "person", controller_class: str = "person_declared", window: dict,
         policy: str, in_window: dict, class_missing: dict, outcomes: dict, bands: list, roles: dict,
         happened: dict, disputes: dict) -> dict:
    return {"derivation": "standard_history/1", "holder_kind": holder_kind, "controller_class": controller_class,
            "anchor": ANCHOR, "since": "2026-03", "window": window, "policy": policy,
            "in_window": in_window, "class_missing": class_missing, "outcomes": outcomes, "bands": bands,
            "roles": roles, "happened": happened, "disputes": disputes}


# SH §5 by hand over DEALS, 3-month window: deal-07 is out; deal-05 and deal-06 are not counted.
PERSON_3M = card(
    window={"months": 3}, policy=POLICY_3M["digest"],
    in_window=tally(7, counted=5, not_counted=2),
    class_missing=tally(5, count=1),
    outcomes=tally(5, held=3, did_not_hold=1, undecided=1),
    bands=[band("BTC", -7, 1, held=1), band("EUR", 0, 1, did_not_hold=1),
           band("USD", 1, 2, held=1, undecided=1), band("USD", 2, 1, held=1)],
    roles=tally(5, provided=3, bought=2),
    happened=tally(5, stamped_by_both=2, receipt_only=2, no_record=1),
    disputes={"raised": disputes_tally(2, {"for": 1, "split": 1}, {"rail": 1, "auto": 1}),
              "received": disputes_tally(1, {"open": 1}, {"network": 1})},
)

# The same stream with window "everything", as a node: deal-07 joins (held, stamped, USD decade 2).
NODE_ALL = card(
    holder_kind="node", controller_class="node_declared",
    window={"all": True}, policy=POLICY_ALL["digest"],
    in_window=tally(8, counted=6, not_counted=2),
    class_missing=tally(6, count=1),
    outcomes=tally(6, held=4, did_not_hold=1, undecided=1),
    bands=[band("BTC", -7, 1, held=1), band("EUR", 0, 1, did_not_hold=1),
           band("USD", 1, 2, held=1, undecided=1), band("USD", 2, 2, held=2)],
    roles=tally(6, provided=4, bought=2),
    happened=tally(6, stamped_by_both=3, receipt_only=2, no_record=1),
    disputes=PERSON_3M["disputes"],
)

# SH §5.1's clamp: anchor on 31 May, 3 months back is 28 February (2027 is not a leap year).
CLAMP_AS_OF = {"anchor": ANCHOR, "anchor_time": "2027-05-31T00:00:00Z", "first_checkpoint_time": FIRST_CHECKPOINT}
CLAMP_DEALS = [
    deal("deal-21", "2027-02-28T00:00:00Z", "provided", amount("2500", "GBP", 2), "held", "stamped_by_both",
         "person_agent"),
    deal("deal-22", "2027-02-27T23:59:59Z", "provided", amount("2500", "GBP", 2), "held", "stamped_by_both",
         "person_agent"),
]
CLAMP_CARD = card(
    window={"months": 3}, policy=POLICY_3M["digest"],
    in_window=tally(1, counted=1, not_counted=0), class_missing=tally(1, count=0),
    outcomes=tally(1, held=1, did_not_hold=0, undecided=0), bands=[band("GBP", 1, 1, held=1)],
    roles=tally(1, provided=1, bought=0), happened=tally(1, stamped_by_both=1, receipt_only=0, no_record=0),
    disputes=NO_DISPUTES,
)

# Every deal outside the window: every tally is 0 of 0, and bands is empty.
EMPTY_AS_OF = {"anchor": ANCHOR, "anchor_time": "2027-06-30T00:00:00Z", "first_checkpoint_time": FIRST_CHECKPOINT}
EMPTY_CARD = card(
    window={"months": 3}, policy=POLICY_3M["digest"],
    in_window=tally(0, counted=0, not_counted=0), class_missing=tally(0, count=0),
    outcomes=tally(0, held=0, did_not_hold=0, undecided=0), bands=[],
    roles=tally(0, provided=0, bought=0), happened=tally(0, stamped_by_both=0, receipt_only=0, no_record=0),
    disputes=NO_DISPUTES,
)

# A 3-month window across a year end, a sub-unit deal and a zero amount: anchor 2027-01-15, so S is
# 2026-10-15. 250 sat (250000 msat) is decade 6 - 11 - 1 = -6; a zero amount has no decade (null)
# and sorts first in its currency.
SMALL_AS_OF = {"anchor": ANCHOR, "anchor_time": "2027-01-15T00:00:00Z", "first_checkpoint_time": FIRST_CHECKPOINT}
SMALL_DEALS = [
    deal("deal-31", "2026-10-15T00:00:00Z", "provided", amount("250000", "BTC", 11), "held", "stamped_by_both",
         "person_agent"),
    deal("deal-32", "2026-12-01T10:00:00Z", "bought", amount("0", "USD", 2), "undecided", "no_record", None),
    deal("deal-33", "2026-11-01T10:00:00Z", "bought", amount("1500", "USD", 2), "held", "receipt_only",
         "business_agent"),
    deal("deal-34", "2026-10-14T23:59:59Z", "bought", amount("1500", "USD", 2), "held", "receipt_only",
         "business_agent"),
]
SMALL_CARD = card(
    window={"months": 3}, policy=POLICY_3M["digest"],
    in_window=tally(3, counted=3, not_counted=0), class_missing=tally(3, count=1),
    outcomes=tally(3, held=2, did_not_hold=0, undecided=1),
    bands=[band("BTC", -6, 1, held=1), band("USD", None, 1, undecided=1), band("USD", 1, 1, held=1)],
    roles=tally(3, provided=1, bought=2), happened=tally(3, stamped_by_both=1, receipt_only=1, no_record=1),
    disputes=NO_DISPUTES,
)

# The decade rule on the amounts a payment adapter writes (SR "Amounts"): 1 msat, 1 sat, 250 sat and
# 1 BTC over Lightning (BTC, scale 11), and 1 cent of USDC on Base (CAIP-19, scale 6).
USDC = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
DECADE_DEALS = [
    deal(f"deal-4{i}", f"2026-10-0{i}T10:00:00Z", "provided", amt, "held", "stamped_by_both", "person_agent")
    for i, amt in enumerate([amount("1", "BTC", 11), amount("1000", "BTC", 11), amount("250000", "BTC", 11),
                             amount("100000000000", "BTC", 11), amount("10000", USDC, 6)], start=1)
]
DECADE_CARD = card(
    window={"months": 3}, policy=POLICY_3M["digest"],
    in_window=tally(5, counted=5, not_counted=0), class_missing=tally(5, count=0),
    outcomes=tally(5, held=5, did_not_hold=0, undecided=0),
    # "BTC" sorts before "eip155:..." by code point.
    bands=[band("BTC", -11, 1, held=1), band("BTC", -8, 1, held=1), band("BTC", -6, 1, held=1),
           band("BTC", 0, 1, held=1), band(USDC, -2, 1, held=1)],
    roles=tally(5, provided=5, bought=0), happened=tally(5, stamped_by_both=5, receipt_only=0, no_record=0),
    disputes=NO_DISPUTES,
)

# deal-05 (a shop purchase paid up front: held, bought, receipt_only, USD decade 1, one received
# open rail dispute) counted as if it were not shop_preauth. Every tally still agrees with the others.
SHOP_COUNTED = copy.deepcopy(PERSON_3M)
SHOP_COUNTED.update(
    in_window=tally(7, counted=6, not_counted=1),
    class_missing=tally(6, count=1),
    outcomes=tally(6, held=4, did_not_hold=1, undecided=1),
    bands=[band("BTC", -7, 1, held=1), band("EUR", 0, 1, did_not_hold=1),
           band("USD", 1, 3, held=2, undecided=1), band("USD", 2, 1, held=1)],
    roles=tally(6, provided=3, bought=3),
    happened=tally(6, stamped_by_both=2, receipt_only=3, no_record=1),
    disputes={"raised": PERSON_3M["disputes"]["raised"],
              "received": disputes_tally(2, {"open": 2}, {"network": 1, "rail": 1})},
)


def mutate(base: dict, fn) -> dict:
    c = copy.deepcopy(base)
    fn(c)
    return c


def props(**overrides: str) -> dict:
    p = {k: "PASS" for k in PROPERTIES}
    p.update(overrides)
    return p


def case(cid: str, description: str, sections: list, card_value: dict, expected: dict, *,
         policy: dict | None = None, as_of: dict | None = None, deals: list | None = None) -> dict:
    inputs: dict = {"card": card_value}
    if policy is not None:
        inputs["policy"] = policy
    if as_of is not None:
        inputs["as_of"] = as_of
    if deals is not None:
        inputs["deals"] = deals
    fails = [k for k in PROPERTIES if expected[k] == "FAIL"]
    standard = not fails and all(expected[k] == "PASS" for k in ("card_form", "counts_integral", "denominator"))
    return {"id": cid, "description": description, "sections": sections, "inputs": inputs,
            "expected": {"properties": expected, "standard": standard, "fails": fails}}


FULL = {"policy": POLICY_3M, "as_of": AS_OF, "deals": DEALS}
NC = "NOT_CHECKED"


def cases() -> list:
    return [
        # Positive.
        case("person-3-months", "A person's card, 3-month window, checked with the policy, the anchor and "
             "every deal entry: one deal outside the window, two shop purchases not counted, one deal "
             "without counterparty_class", ["§4", "§5", "§6", "§7"], PERSON_3M, props(), **FULL),
        case("person-3-months-without-deals", "The same card, checked without the deal entries: the counts "
             "are the holder's statement", ["§2", "§6"], PERSON_3M, props(counts_recompute=NC),
             policy=POLICY_3M, as_of=AS_OF),
        case("person-3-months-card-only", "The same card, checked with nothing beside it",
             ["§6"], PERSON_3M, props(window_from_policy=NC, as_of=NC, counts_recompute=NC)),
        case("node-all", "A node's card over the same stream, window everything: the deal outside 3 months "
             "now counts", ["§4", "§5.1", "§5.3"], NODE_ALL, props(),
             policy=POLICY_ALL, as_of=AS_OF, deals=DEALS),
        case("window-month-end", "Anchor on 31 May: 3 months back is 28 February, and a deal one second "
             "earlier is outside", ["§5.1"], CLAMP_CARD, props(),
             policy=POLICY_3M, as_of=CLAMP_AS_OF, deals=CLAMP_DEALS),
        case("empty-window", "No deal in the window: every tally is 0 of 0", ["§4", "§5.3"], EMPTY_CARD,
             props(), policy=POLICY_3M, as_of=EMPTY_AS_OF, deals=DEALS),
        case("year-end-small-and-zero", "A 3-month window across a year end; a 250-sat deal in decade -6 "
             "and a zero amount in the band without a decade", ["§4", "§5.1", "§5.3"], SMALL_CARD, props(),
             policy=POLICY_3M, as_of=SMALL_AS_OF, deals=SMALL_DEALS),
        case("window-before-year-one", "A 30000-month window starts before year 1, so it counts every deal",
             ["§5.1"], mutate(NODE_ALL, lambda c: c.update(holder_kind="person", controller_class="person_declared",
                                                           window={"months": 30000}, policy=POLICY_FAR["digest"])),
             props(), policy=POLICY_FAR, as_of=AS_OF, deals=DEALS),
        case("decade-examples", "Signed decades: 1 msat -11, 1 sat -8, 250 sat -6, 1 BTC 0, 1 cent of "
             "USDC -2", ["§4", "§5.3"], DECADE_CARD, props(), policy=POLICY_3M, as_of=AS_OF, deals=DECADE_DEALS),
        # Negative.
        case("percentage-fraction", "A share stated as a fraction in place of a count",
             ["§4 Counts", "§6"], mutate(PERSON_3M, lambda c: c["outcomes"].update(held=0.6)),
             props(counts_integral="FAIL", denominator=NC, counts_recompute=NC), **FULL),
        case("percentage-member", "A percentage member beside the counts",
             ["§4", "§6"], mutate(PERSON_3M, lambda c: c["outcomes"].update(held_percent=60)),
             props(card_form="FAIL", denominator=NC, counts_recompute=NC), **FULL),
        case("count-without-denominator", "A tally without its of", ["§4 Denominators", "§6"],
             mutate(PERSON_3M, lambda c: c["roles"].pop("of")),
             props(denominator="FAIL", counts_recompute=NC), **FULL),
        case("tallies-disagree", "happened partitions its own of, but counts more deals than were counted",
             ["§4 Denominators", "§6"],
             mutate(PERSON_3M, lambda c: c.update(happened=tally(6, stamped_by_both=2, receipt_only=2,
                                                                  no_record=2))),
             props(denominator="FAIL", counts_recompute=NC), **FULL),
        case("counted-shop-purchase", "A shop purchase paid up front counted, every tally consistent",
             ["§5.3", "§7", "§6"], SHOP_COUNTED, props(counts_recompute="FAIL"), **FULL),
        case("window-not-in-policy", "The card states a 12-month window; the policy sets 3 months",
             ["§5.1", "§6"], mutate(PERSON_3M, lambda c: c.update(window={"months": 12})),
             props(window_from_policy="FAIL"), **FULL),
        case("counterparty-member", "A member naming counterparties", ["§4", "§6"],
             mutate(PERSON_3M, lambda c: c.update(counterparties=["an example shop"])),
             props(card_form="FAIL", denominator=NC, counts_recompute=NC), **FULL),
        case("since-day", "since carries a day, finer than a month", ["§4", "§6"],
             mutate(PERSON_3M, lambda c: c.update(since="2026-03-04")),
             props(card_form="FAIL", denominator=NC, as_of="FAIL", counts_recompute=NC), **FULL),
        case("since-non-ascii-digits", "since written in Arabic-Indic digits", ["§4", "§6"],
             mutate(PERSON_3M, lambda c: c.update(since="\u0662\u0660\u0662\u0666-03")),
             props(card_form="FAIL", denominator=NC, as_of="FAIL", counts_recompute=NC), **FULL),
        case("bands-unsorted", "Two bands out of order", ["§4", "§6"],
             mutate(PERSON_3M, lambda c: c["bands"].insert(0, c["bands"].pop(1))),
             props(card_form="FAIL", denominator=NC, counts_recompute=NC), **FULL),
        case("band-duplicate", "One band split into two entries", ["§4", "§6"],
             mutate(PERSON_3M, lambda c: c["bands"].__setitem__(slice(2, 3), [band("USD", 1, 1, held=1),
                                                                              band("USD", 1, 1, undecided=1)])),
             props(card_form="FAIL", denominator=NC, counts_recompute=NC), **FULL),
        case("currency-free-text", "A band's currency is a name, not an SR assetCode", ["§4", "§6", "§9"],
             mutate(PERSON_3M, lambda c: c["bands"][0].update(currency="Example Bakery")),
             props(card_form="FAIL", denominator=NC, counts_recompute=NC), **FULL),
        case("node-person-class", "A node card with the person controller class", ["§4", "§6"],
             mutate(NODE_ALL, lambda c: c.update(controller_class="person_declared")),
             props(card_form="FAIL", denominator=NC, counts_recompute=NC),
             policy=POLICY_ALL, as_of=AS_OF, deals=DEALS),
        case("node-class-free-text", "A node card whose controller_class is a name", ["§4", "§6", "§9"],
             mutate(NODE_ALL, lambda c: c.update(controller_class="alice_smith")),
             props(card_form="FAIL", denominator=NC, counts_recompute=NC),
             policy=POLICY_ALL, as_of=AS_OF, deals=DEALS),
        case("band-empty", "A band with no counted deal in it", ["§4", "§6"],
             mutate(EMPTY_CARD, lambda c: c["bands"].append(band("USD", 1, 0))),
             props(denominator="FAIL", counts_recompute=NC), policy=POLICY_3M, as_of=EMPTY_AS_OF, deals=DEALS),
        case("window-all-false", "A window of {\"all\": false}", ["§4", "§6"],
             mutate(PERSON_3M, lambda c: c.update(window={"all": False})),
             props(card_form="FAIL", denominator=NC, window_from_policy="FAIL", counts_recompute=NC), **FULL),
        case("class-missing-over", "class_missing counts more deals than its of", ["§4 Denominators", "§6"],
             mutate(PERSON_3M, lambda c: c.update(class_missing=tally(5, count=6))),
             props(denominator="FAIL", counts_recompute=NC), **FULL),
        case("dispute-forum-total", "A dispute tally's by_forum counts more disputes than the tally",
             ["§4 Denominators", "§6"],
             mutate(PERSON_3M, lambda c: c["disputes"]["raised"].update(
                 by_forum={"of": 3, "auto": 1, "network": 0, "rail": 2, "external": 0})),
             props(denominator="FAIL", counts_recompute=NC), **FULL),
        case("other-anchor", "The card names another anchor than the one answered at", ["§4", "§6"],
             mutate(PERSON_3M, lambda c: c.update(anchor=label("another anchor"))),
             props(as_of="FAIL"), **FULL),
    ]


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def check_frame(all_cases: list) -> None:
    """HF §6.3: the instance's counting table (``spec/history-frame/``) matches what these vectors
    emit, and every case's ``standard`` is HF §4.5's acceptance rule under the table's list."""
    table, _ = history_frame.load("standard_history/1")
    assert table["properties"] == list(PROPERTIES), "counting table: properties"
    assert table["card_members"] == list(PERSON_3M), "counting table: card members"
    t = table["tallies"]
    for name in ("in_window", "class_missing", "outcomes", "roles", "happened", "disputes"):
        assert t[name] == list(PERSON_3M[name]), f"counting table: tally {name}"
    assert t["band"] == list(PERSON_3M["bands"][0]), "counting table: band tally"
    raised = PERSON_3M["disputes"]["raised"]
    assert t["dispute"] == list(raised), "counting table: dispute tally"
    assert t["by_outcome"] == list(raised["by_outcome"]) and t["by_forum"] == list(raised["by_forum"])
    every_deal = [d for c in all_cases for d in c["inputs"].get("deals", [])]
    assert all(set(d) <= set(table["inputs"]["deal_entry"]) for d in every_deal), "counting table: deal entry"
    assert {d["counterparty_class"] for d in every_deal if "counterparty_class" in d} <= set(
        table["inputs"]["counterparty_class"]), "counting table: counterparty_class"
    for c in all_cases:
        statuses = c["expected"]["properties"]
        assert c["expected"]["standard"] is history_frame.accepted(statuses, table["may_be_not_checked"]), c["id"]


def build() -> dict:
    all_cases = cases()
    ids = [c["id"] for c in all_cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    check_frame(all_cases)
    corpus = {"set": SET, "status": STATUS, "spec": SPEC, "properties": list(PROPERTIES),
              "count": len(all_cases), "cases": all_cases}
    files = {"vectors.json": _dump(corpus)}
    files["manifest.json"] = _dump({
        "set": SET, "status": STATUS, "spec": SPEC, "generator": GENERATOR,
        "files": [{"path": name, "sha256": hashlib.sha256(data).hexdigest(), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    files = sorted((p.relative_to(out).as_posix(), p) for p in out.rglob("*") if p.is_file())
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}" for rel, p in files if rel != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    write(args.out)


if __name__ == "__main__":
    main()
