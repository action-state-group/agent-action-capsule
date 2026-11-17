#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the standard history vectors (``spec/standard-history-v0.md``, cited as SH).

Each case is one card with what a verifier may hold beside it: the policy's window and digest
(SH §5.1), the anchor (SH §6 ``as_of``) and the deal entries (SH §5.2). SH §6 lists the
negatives. ``vectors.json`` holds the ``standard_history/1`` cases; ``vectors-2.json`` holds the
``standard_history/2`` cases and ``vectors-3.json`` the ``standard_history/3`` ones (SH §11), each
naming the token it is checked under in ``inputs.derivation``.

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
STATUS_2 = ("Conformance vectors for the informational Standard History Derivation v0 "
            "(spec/standard-history-v0.md), standard_history/2: deals without a recorded amount. Every "
            "digest is a label digest for these vectors only.")
STATUS_3 = ("Conformance vectors for the informational Standard History Derivation v0 "
            "(spec/standard-history-v0.md), standard_history/3: deals counted from their term rows, in "
            "five lines, with the coverage start. Every digest is a label digest for these vectors only.")
SH1, SH2, SH3 = "standard_history/1", "standard_history/2", "standard_history/3"
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


def deal(ref: str, agreed_at: str, role: str, amt: dict | None, outcome: str, happened: str,
         cls: str | None, disputes: tuple = ()) -> dict:
    """A deal entry (SH §5.2). ``amt`` None is an unpriced deal (/2 only): the entry has no amount."""
    d = {"deal": ref, "agreed_at": agreed_at, "role": role, "amount": amt, "outcome": outcome,
         "happened": happened,
         "disputes": [{"side": s, "outcome": o, "forum": f} for s, o, f in disputes]}
    if amt is None:
        del d["amount"]
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
         policy: dict | None = None, as_of: dict | None = None, deals: list | None = None,
         derivation: str | None = None) -> dict:
    inputs: dict = {"card": card_value}
    if derivation is not None:
        inputs["derivation"] = derivation
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
        case("person-3-months-without-policy", "The same card, checked with the anchor and every deal entry "
             "but without the policy: the counts recompute over the card's own window, and the window is the "
             "holder's statement", ["§6"], PERSON_3M, props(window_from_policy=NC),
             as_of=AS_OF, deals=DEALS),
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
        case("window-not-in-policy", "The card states a 12-month window and the 3-month window's counts; the "
             "policy sets 3 months. The counts are recomputed over the card's own window, so they differ too",
             ["§5.1", "§6"], mutate(PERSON_3M, lambda c: c.update(window={"months": 12})),
             props(window_from_policy="FAIL", counts_recompute="FAIL"), **FULL),
        case("window-not-in-policy-counts-match", "A card over window everything, checked against a policy "
             "that sets 3 months: the counts are right for the card's own window, which is not the policy's",
             ["§5.1", "§6"], NODE_ALL, props(window_from_policy="FAIL"),
             policy=POLICY_3M, as_of=AS_OF, deals=DEALS),
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


# standard_history/2 (SH §4, §5.2, §5.3): DEALS and two deals whose records give no agreed amount.
UNPRICED_DEALS = DEALS + [
    # Counted and unpriced: held, provided, receipt_only, one raised dispute the holder withdrew.
    deal("deal-09", "2026-09-20T10:00:00Z", "provided", None, "held", "receipt_only", "person_agent",
         (("raised", "withdrawn", "external"),)),
    # Unpriced and a shop purchase paid up front: in the window, not counted, so in no tally but in_window.
    deal("deal-10", "2026-10-05T10:00:00Z", "bought", None, "held", "receipt_only", "shop_preauth"),
    # Counted and unpriced, undecided, without counterparty_class: in unpriced.undecided and class_missing.
    deal("deal-11", "2026-10-12T10:00:00Z", "bought", None, "undecided", "no_record", None),
    # Unpriced and before the window start: in no count at all.
    deal("deal-12", "2026-06-01T10:00:00Z", "provided", None, "did_not_hold", "no_record", "person_agent"),
]


def card2(base: dict, unpriced: dict, **members) -> dict:
    """A /2 card: ``base``'s members with ``members`` replaced, and ``unpriced``, in the counting
    table's member order."""
    c = {**base, **members, "derivation": SH2}
    out = {}
    for k in c:
        out[k] = c[k]
        if k == "bands":
            out["unpriced"] = unpriced
    return out


NO_UNPRICED = tally(0, held=0, did_not_hold=0, undecided=0)

# SH §5 by hand over UNPRICED_DEALS, 3-month window: PERSON_3M's counts, deal-09 and deal-11 counted
# in every tally and in `unpriced` but in no band, deal-10 in in_window.not_counted only, deal-12 in
# nothing.
PERSON_3M_2 = card2(
    PERSON_3M, tally(2, held=1, did_not_hold=0, undecided=1),
    in_window=tally(10, counted=7, not_counted=3),
    class_missing=tally(7, count=2),
    outcomes=tally(7, held=4, did_not_hold=1, undecided=2),
    roles=tally(7, provided=4, bought=3),
    happened=tally(7, stamped_by_both=2, receipt_only=3, no_record=2),
    disputes={"raised": disputes_tally(3, {"for": 1, "split": 1, "withdrawn": 1},
                                       {"rail": 1, "auto": 1, "external": 1}),
              "received": PERSON_3M["disputes"]["received"]},
)
# The same stream with no unpriced deal: PERSON_3M's counts and `unpriced` 0 of 0.
PERSON_3M_2_PRICED = card2(PERSON_3M, NO_UNPRICED)
FULL_2 = {"policy": POLICY_3M, "as_of": AS_OF, "deals": UNPRICED_DEALS, "derivation": SH2}


def cases_2() -> list:
    return [
        # Positive.
        case("unpriced-counted", "Two counted deals without a recorded amount, one held and one undecided: "
             "every total counts them, no band does, and unpriced is 2 of 2; an unpriced shop purchase is "
             "only not_counted, and an unpriced deal before the window counts nowhere",
             ["§4", "§5.2", "§5.3", "§6"], PERSON_3M_2, props(), **FULL_2),
        case("unpriced-without-deals", "The same card, checked without the deal entries: the counts, "
             "unpriced included, are the holder's statement", ["§2", "§6"], PERSON_3M_2,
             props(counts_recompute=NC), policy=POLICY_3M, as_of=AS_OF, derivation=SH2),
        case("unpriced-card-only", "The same card, checked with nothing beside it", ["§6"], PERSON_3M_2,
             props(window_from_policy=NC, as_of=NC, counts_recompute=NC), derivation=SH2),
        case("unpriced-none", "A /2 card over a stream whose every deal has an amount: unpriced is 0 of 0",
             ["§4", "§5.3"], PERSON_3M_2_PRICED, props(), policy=POLICY_3M, as_of=AS_OF, deals=DEALS,
             derivation=SH2),
        # Negative.
        case("unpriced-left-out", "The unpriced deals left out of every tally, the tallies agreeing with "
             "each other", ["§3", "§5.3", "§6"],
             card2(PERSON_3M, NO_UNPRICED, in_window=tally(8, counted=5, not_counted=3)),
             props(counts_recompute="FAIL"), **FULL_2),
        case("unpriced-in-band", "The unpriced deals counted in a zero-amount USD band instead of unpriced, "
             "the tallies agreeing with each other", ["§5.3", "§6"],
             mutate(PERSON_3M_2, lambda c: c.update(
                 unpriced=NO_UNPRICED,
                 bands=[band("BTC", -7, 1, held=1), band("EUR", 0, 1, did_not_hold=1),
                        band("USD", None, 2, held=1, undecided=1), band("USD", 1, 2, held=1, undecided=1),
                        band("USD", 2, 1, held=1)])),
             props(counts_recompute="FAIL"), **FULL_2),
        case("unpriced-outside-outcomes", "unpriced counts a deal but outcomes and the other totals do "
             "not", ["§4 Denominators", "§6"],
             card2(PERSON_3M, tally(1, held=1, did_not_hold=0, undecided=0),
                   in_window=tally(8, counted=5, not_counted=3)),
             props(denominator="FAIL", counts_recompute=NC), **FULL_2),
        case("v2-without-unpriced", "A /2 card without the unpriced member", ["§4", "§6"],
             mutate(PERSON_3M_2, lambda c: c.pop("unpriced")),
             props(card_form="FAIL", denominator=NC, counts_recompute=NC), **FULL_2),
        case("unpriced-with-currency", "unpriced names a currency, as if it were a band", ["§4", "§6"],
             mutate(PERSON_3M_2, lambda c: c["unpriced"].update(currency="USD")),
             props(card_form="FAIL", denominator=NC, counts_recompute=NC), **FULL_2),
        case("v1-card-for-v2-request", "A /1 card answering a /2 request", ["§3", "§6"], PERSON_3M,
             props(card_form="FAIL", denominator=NC, counts_recompute=NC),
             policy=POLICY_3M, as_of=AS_OF, deals=DEALS, derivation=SH2),
        case("v2-card-for-v1-request", "A /2 card answering a /1 request", ["§3", "§6"], PERSON_3M_2_PRICED,
             props(card_form="FAIL", denominator=NC, counts_recompute=NC),
             policy=POLICY_3M, as_of=AS_OF, deals=DEALS, derivation=SH1),
        case("v1-card-with-unpriced", "A /1 card that carries unpriced, checked under /1", ["§4", "§6"],
             PERSON_3M_2_PRICED | {"derivation": SH1},
             props(card_form="FAIL", denominator=NC, counts_recompute=NC),
             policy=POLICY_3M, as_of=AS_OF, deals=DEALS, derivation=SH1),
    ]


# standard_history/3 (SH §11). Each deal entry carries its row results as of the anchor's time T.
COVERAGE_START = "2026-04-10T08:00:00Z"
AS_OF_3 = {**AS_OF, "coverage_start_time": COVERAGE_START}
# A later anchor: S is 2026-08-27T12:00:00Z, so the same deals are in the window.
ANCHOR_B = label("a later anchor of the holder's shelf log")
AS_OF_3B = {"anchor": ANCHOR_B, "anchor_time": "2026-11-27T12:00:00Z", "first_checkpoint_time": FIRST_CHECKPOINT,
            "coverage_start_time": COVERAGE_START}


def row(owed_by: str, status: str, value: str | None = None, remedy: str | None = None,
        local: bool = False) -> dict:
    """A row result (SH §11.2). An unmet row that is not ruled carries remedy none unless given."""
    r = {"owed_by": owed_by, "status": status}
    if value is not None:
        r["value"] = value
    if remedy is None and value == "not_met" and status in ("agreed_so_far", "agreed", "uncontested"):
        remedy = "none"
    if remedy is not None:
        r["remedy"] = remedy
    if local:
        r["local"] = True
    return r


def deal3(ref: str, agreed_at: str, role: str, amt: dict | None, rows: list, happened: str, cls: str | None,
          disputes: tuple = (), left_out: str | None = None) -> dict:
    """A /3 deal entry (SH §11.2): /2's entry with ``rows`` in place of ``outcome``."""
    d = deal(ref, agreed_at, role, amt, "held", happened, cls, disputes)
    del d["outcome"]
    d["rows"] = rows
    if left_out is not None:
        d["left_out"] = left_out
    return d


H, C = "holder", "counterparty"
MET, NOT_MET = "met", "not_met"


def deals3(later: bool) -> list:
    """The holder's shelf at the first anchor, or (``later``) at the later one. Only deal-302 and deal-314
    change between them, and neither book has a new fact: their rows' dates passed."""
    return [
        # held: every row agreed as met; a row whose date can no longer be set is left out. One row
        # rests on a record with no witnessed time (local).
        deal3("deal-301", "2026-09-02T10:00:00Z", "provided", amount("4500", "USD", 2),
              [row(H, "agreed", MET), row(C, "agreed", MET, local=True), row(C, "not_reached")],
              "stamped_by_both", "person_agent"),
        # held_so_far: the other side's row is not yet due; at the later anchor it has no statement
        # after its due date, so undecided.
        deal3("deal-302", "2026-09-05T10:00:00Z", "bought", amount("12000", "USD", 2),
              [row(H, "agreed", MET), row(C, "no_statement" if later else "not_due")], "receipt_only",
              "business_agent", (("raised", "for", "rail"),)),
        # did_not_hold, not_remedied: the holder's row agreed as not met, no ruling.
        deal3("deal-303", "2026-09-10T10:00:00Z", "bought", amount("999", "EUR", 2),
              [row(H, "agreed", NOT_MET), row(C, "agreed", MET)], "stamped_by_both", "person_agent"),
        # did_not_hold, remedy_pending: ruled not met, remedy ordered and not yet due. No class.
        deal3("deal-304", "2026-09-12T10:00:00Z", "provided", amount("1850", "USD", 2),
              [row(H, "ruled", NOT_MET, "due")], "receipt_only", None),
        # did_not_hold, remedied: one unmet row ruled with its remedy made, another agreed as not met
        # and remedied by the holder without a ruling.
        deal3("deal-305", "2026-09-15T10:00:00Z", "provided", amount("21000", "BTC", 11),
              [row(H, "ruled", NOT_MET, "made"), row(H, "agreed", NOT_MET, "made"), row(C, "uncontested", MET)],
              "stamped_by_both", "person_agent"),
        # did_not_hold, other_side: only the counterparty's row was not met. Unpriced.
        deal3("deal-306", "2026-09-20T10:00:00Z", "provided", None,
              [row(H, "agreed", MET), row(C, "uncontested", NOT_MET)], "receipt_only", "person_agent"),
        # undecided wins over did_not_hold: a row in dispute and a row agreed as not met.
        deal3("deal-307", "2026-09-25T10:00:00Z", "bought", amount("300", "USD", 0),
              [row(H, "agreed", NOT_MET), row(C, "in_dispute")], "no_record", "business_agent",
              (("received", "open", "network"),)),
        # ruling_not_honoured wins over undecided: the remedy's date passed without one.
        deal3("deal-308", "2026-10-01T10:00:00Z", "provided", amount("5000", "EUR", 2),
              [row(H, "ruled", NOT_MET, "not_honoured"), row(C, "no_statement")], "stamped_by_both",
              "person_agent", (("received", "against", "external"),)),
        # undecided: waiting for the other side on a statement of not met, resting on an untimed
        # record. Zero amount.
        deal3("deal-309", "2026-10-05T10:00:00Z", "bought", amount("0", "USD", 2),
              [row(C, "waiting", NOT_MET, local=True)], "no_record", "business_agent"),
        # undecided: its only row's date can no longer be set, so no row is left. Unpriced.
        deal3("deal-310", "2026-10-10T10:00:00Z", "provided", None,
              [row(H, "not_reached")], "no_record", "person_agent"),
        # Left out: its agreement names witnesses and no time from them is held. Not counted.
        deal3("deal-311", "2026-10-12T10:00:00Z", "provided", amount("1000", "USD", 2),
              [row(H, "agreed", MET)], "stamped_by_both", "person_agent", left_out="no_witness_time"),
        # A shop purchase paid up front: not counted, its dispute counts nowhere.
        deal3("deal-312", "2026-10-15T10:00:00Z", "bought", amount("6000", "USD", 2),
              [row(C, "agreed", MET)], "receipt_only", "shop_preauth", (("received", "open", "rail"),)),
        # Before the window at both anchors.
        deal3("deal-313", "2026-06-01T10:00:00Z", "provided", amount("4500", "USD", 2),
              [row(H, "agreed", NOT_MET)], "stamped_by_both", "person_agent"),
        # held_so_far: agreed as met, inside the contest window; at the later anchor the window has
        # ended, so agreed and held.
        deal3("deal-314", "2026-10-20T10:00:00Z", "provided", amount("2500", "USD", 2),
              [row(H, "agreed" if later else "agreed_so_far", MET), row(C, "uncontested", MET)], "receipt_only",
              "person_agent"),
    ]


DEALS_3, DEALS_3B = deals3(False), deals3(True)


def lines(of: int, held: int = 0, held_so_far: int = 0, did_not_hold: int = 0, undecided: int = 0,
          ruling_not_honoured: int = 0) -> dict:
    return {"of": of, "held": held, "held_so_far": held_so_far, "did_not_hold": did_not_hold,
            "undecided": undecided, "ruling_not_honoured": ruling_not_honoured}


def band3(currency: str, decade: int | None, of: int, **parts: int) -> dict:
    return {"currency": currency, "decade": decade, **lines(of, **parts)}


def split(of: int, not_remedied: int = 0, remedy_pending: int = 0, remedied: int = 0, other_side: int = 0) -> dict:
    return {"of": of, "not_remedied": not_remedied, "remedy_pending": remedy_pending, "remedied": remedied,
            "other_side": other_side}


def card3(*, anchor: str = ANCHOR, outcomes: dict, did_not_hold: dict, bands: list, unpriced: dict) -> dict:
    """A /3 card over DEALS_3 or DEALS_3B (3-month window), in the counting table's member order. Only
    the lines move between the two anchors; every other tally is the same."""
    return {"derivation": SH3, "holder_kind": "person", "controller_class": "person_declared",
            "anchor": anchor, "since": "2026-03", "coverage_start": "2026-04", "window": {"months": 3},
            "policy": POLICY_3M["digest"],
            "in_window": tally(13, counted=11, not_counted=2), "class_missing": tally(11, count=1),
            "outcomes": outcomes, "did_not_hold": did_not_hold, "local_times": tally(11, count=2),
            "bands": bands, "unpriced": unpriced,
            "roles": tally(11, provided=7, bought=4),
            "happened": tally(11, stamped_by_both=4, receipt_only=4, no_record=3),
            "disputes": {"raised": disputes_tally(1, {"for": 1}, {"rail": 1}),
                         "received": disputes_tally(2, {"open": 1, "against": 1}, {"network": 1, "external": 1})}}


# SH §11 by hand over DEALS_3 at the first anchor: deal-313 is out of the window; deal-311 (left out)
# and deal-312 (shop) are not counted; deal-304 has no class.
PERSON_3M_3 = card3(
    outcomes=lines(11, held=1, held_so_far=2, did_not_hold=4, undecided=3, ruling_not_honoured=1),
    did_not_hold=split(4, not_remedied=1, remedy_pending=1, remedied=1, other_side=1),
    bands=[band3("BTC", -7, 1, did_not_hold=1), band3("EUR", 0, 1, did_not_hold=1),
           band3("EUR", 1, 1, ruling_not_honoured=1), band3("USD", None, 1, undecided=1),
           band3("USD", 1, 3, held=1, held_so_far=1, did_not_hold=1),
           band3("USD", 2, 2, held_so_far=1, undecided=1)],
    unpriced=lines(2, did_not_hold=1, undecided=1),
)
# The same deals at the later anchor: deal-302 is now undecided and deal-314 held.
PERSON_3M_3B = card3(
    anchor=ANCHOR_B,
    outcomes=lines(11, held=2, did_not_hold=4, undecided=4, ruling_not_honoured=1),
    did_not_hold=split(4, not_remedied=1, remedy_pending=1, remedied=1, other_side=1),
    bands=[band3("BTC", -7, 1, did_not_hold=1), band3("EUR", 0, 1, did_not_hold=1),
           band3("EUR", 1, 1, ruling_not_honoured=1), band3("USD", None, 1, undecided=1),
           band3("USD", 1, 3, held=2, did_not_hold=1), band3("USD", 2, 2, undecided=2)],
    unpriced=lines(2, did_not_hold=1, undecided=1),
)
FULL_3 = {"policy": POLICY_3M, "as_of": AS_OF_3, "deals": DEALS_3, "derivation": SH3}


def cases_3() -> list:
    return [
        # Positive.
        case("lines-and-split", "Every line and every part of the split, a deal where undecided and "
             "did_not_hold both apply (the first wins), a ruling not honoured that wins over undecided, a deal "
             "left out without a witness time, a shop purchase, two unpriced deals and a zero amount",
             ["§11.2", "§11.3", "§11.4", "§11.6", "§11.7"], PERSON_3M_3, props(), **FULL_3),
        case("quiet-deals-later-anchor", "The same deals at a later anchor with no new fact: a row not yet "
             "due now has no statement (held_so_far to undecided), a contest window has ended (held_so_far to "
             "held)", ["§11.1", "§11.3"], PERSON_3M_3B, props(),
             policy=POLICY_3M, as_of=AS_OF_3B, deals=DEALS_3B, derivation=SH3),
        case("lines-without-shelf", "The first card, checked without the deal entries: the counts are the "
             "holder's statement", ["§11.7", "§11.8"], PERSON_3M_3, props(counts_recompute=NC),
             policy=POLICY_3M, as_of=AS_OF_3, derivation=SH3),
        case("lines-card-only", "The first card, checked with nothing beside it", ["§11.7"], PERSON_3M_3,
             props(window_from_policy=NC, as_of=NC, counts_recompute=NC), derivation=SH3),
        # Negative.
        case("line-not-first", "deal-307 counted as did_not_hold (not remedied) though undecided applies "
             "first, every tally agreeing with the others", ["§11.3", "§11.7"],
             mutate(PERSON_3M_3, lambda c: c.update(
                 outcomes=lines(11, held=1, held_so_far=2, did_not_hold=5, undecided=2, ruling_not_honoured=1),
                 did_not_hold=split(5, not_remedied=2, remedy_pending=1, remedied=1, other_side=1),
                 bands=c["bands"][:5] + [band3("USD", 2, 2, held_so_far=1, did_not_hold=1)])),
             props(counts_recompute="FAIL"), **FULL_3),
        case("left-out-counted", "deal-311, left out for want of a witness time, counted as held, every tally "
             "agreeing with the others", ["§11.2", "§11.7"],
             mutate(PERSON_3M_3, lambda c: c.update(
                 in_window=tally(13, counted=12, not_counted=1), class_missing=tally(12, count=1),
                 outcomes=lines(12, held=2, held_so_far=2, did_not_hold=4, undecided=3, ruling_not_honoured=1),
                 bands=c["bands"][:4] + [band3("USD", 1, 4, held=2, held_so_far=1, did_not_hold=1),
                                         c["bands"][5]],
                 local_times=tally(12, count=2), roles=tally(12, provided=8, bought=4),
                 happened=tally(12, stamped_by_both=5, receipt_only=4, no_record=3))),
             props(counts_recompute="FAIL"), **FULL_3),
        case("local-times-dropped", "The two counted deals whose rows rest on an untimed record left out of "
             "local_times", ["§11.2", "§11.6", "§11.7"],
             mutate(PERSON_3M_3, lambda c: c.update(local_times=tally(11, count=0))),
             props(counts_recompute="FAIL"), **FULL_3),
        case("refund-not-remedied", "deal-305, whose unmet rows are remedied (one by a ruling, one by the "
             "holder without one), counted as not remedied", ["§11.4", "§11.7"],
             mutate(PERSON_3M_3, lambda c: c.update(did_not_hold=split(4, not_remedied=2, remedy_pending=1,
                                                                       other_side=1))),
             props(counts_recompute="FAIL"), **FULL_3),
        case("split-not-the-line", "The split partitions its own of, which is not the did_not_hold line",
             ["§11.6", "§11.7"],
             mutate(PERSON_3M_3, lambda c: c.update(did_not_hold=split(3, not_remedied=1, remedy_pending=1,
                                                                       remedied=1))),
             props(denominator="FAIL", counts_recompute=NC), **FULL_3),
        case("band-three-outcomes", "A band counted by the three outcomes of /1 and /2", ["§11.6", "§11.7"],
             mutate(PERSON_3M_3, lambda c: c["bands"].__setitem__(0, band("BTC", -7, 1, did_not_hold=1))),
             props(card_form="FAIL", denominator=NC, counts_recompute=NC), **FULL_3),
        case("no-coverage-start", "A /3 card without coverage_start", ["§11.6", "§11.7"],
             mutate(PERSON_3M_3, lambda c: c.pop("coverage_start")),
             props(card_form="FAIL", denominator=NC, as_of="FAIL", counts_recompute=NC), **FULL_3),
        case("coverage-start-before-since", "coverage_start before since", ["§11.5", "§11.7"],
             mutate(PERSON_3M_3, lambda c: c.update(coverage_start="2026-02")),
             props(card_form="FAIL", denominator=NC, as_of="FAIL", counts_recompute=NC), **FULL_3),
        case("coverage-start-other-month", "coverage_start is not the month of the coverage start",
             ["§11.5", "§11.7"], mutate(PERSON_3M_3, lambda c: c.update(coverage_start="2026-05")),
             props(as_of="FAIL"), **FULL_3),
        case("anchor-before-coverage-start", "The anchor is earlier than the coverage start it states",
             ["§11.1", "§11.7"], mutate(PERSON_3M_3, lambda c: c.update(coverage_start="2026-10")),
             props(as_of="FAIL"), policy=POLICY_3M, as_of={**AS_OF_3, "coverage_start_time": "2026-10-29T00:00:00Z"},
             deals=DEALS_3, derivation=SH3),
        case("v2-card-for-v3-request", "A /2 card answering a /3 request", ["§11.7"], PERSON_3M_2_PRICED,
             props(card_form="FAIL", denominator=NC, as_of="FAIL", counts_recompute=NC), **FULL_3),
        case("v3-card-for-v2-request", "A /3 card answering a /2 request", ["§11.7"], PERSON_3M_3,
             props(card_form="FAIL", denominator=NC, counts_recompute=NC),
             policy=POLICY_3M, as_of=AS_OF, deals=DEALS, derivation=SH2),
    ]


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


# HF §6.1: what the standard_history/1 counting table and wording pack restate of this document.
DEAL_ENTRY = ["deal", "agreed_at", "counterparty_class", "role", "amount", "outcome", "happened", "disputes"]  # §5.2
COUNTERPARTY_CLASSES = ["person_agent", "business_agent", "shop_preauth"]  # §7
NOT_COUNTED = ["shop_preauth"]  # §5.3
RECORD_KINDS = ["receipt_document"]  # §8
UNITS = ["deals", "disputes"]  # §4
PACK_STRINGS = {  # §2, §6 "What a verifier shows"
    "count.of": "{count} of {of}",
    "counts.cover": "the counts cover counted deals in the stated window",
    "counts.not_recomputed": "the holder's statement under the holder key, not recomputed",
    "deals.not_counted": "deals in the window not counted",
    "deals.undecided": "counted deals without a decided outcome",
}
PACK_STRINGS_2 = {**PACK_STRINGS, "deals.unpriced": "counted deals without a recorded amount, in no value band"}
# §11.2, §11.8 for /3.
DEAL_ENTRY_3 = ["deal", "agreed_at", "counterparty_class", "left_out", "role", "amount", "rows", "happened",
                "disputes"]
ROW_RESULT = ["owed_by", "status", "value", "remedy", "local"]
ROW_STATUSES = ["not_reached", "not_due", "no_statement", "waiting", "uncontested", "agreed_so_far", "agreed",
                "in_disagreement", "in_dispute", "ruled"]
NOT_COUNTED_3 = ["shop_preauth", "no_witness_time"]
PACK_STRINGS_3 = {
    **PACK_STRINGS_2,
    "deals.undecided": "counted deals not decided: a row in disagreement or dispute, or without the statement it needed",
    "deals.local_times": "counted deals with a row that rests on a record no witness timed",
    "deals.held_so_far": "counted deals held so far, with a row not yet due or a contest window open",
    "deals.did_not_hold.split": "of the deals that did not hold, by what became of the unmet rows",
    "coverage.start": "complete from {coverage_start}; before it, the deals the holder carried into its shelf log",
    "level.recomputed": "recounted from the holder's whole shelf",
    "level.form_only": "checked for its form only",
    "anchor.unwitnessed": "unwitnessed: no witness receipt for this snapshot",
    "anchor.witnessed_only": "the witness timed this snapshot, not the records the counts rest on",
}


def check_frame(all_cases: list, instance: str = SH1) -> None:
    """HF §6.3: the instance's counting table and wording pack (``spec/history-frame/``) equal, member
    for member, what this generator's constants and cases give, and every case's ``standard`` is
    HF §4.5's acceptance rule under the table's ``may_be_not_checked``."""
    if instance == SH3:
        check_frame_3(all_cases)
        return
    table, pack = history_frame.load(instance)
    model = PERSON_3M if instance == SH1 else PERSON_3M_2
    raised = PERSON_3M["disputes"]["raised"]
    every_deal = [d for c in all_cases for d in c["inputs"].get("deals", [])]
    assert all(set(d) <= set(DEAL_ENTRY) for d in every_deal), "deal entry"
    assert {d["counterparty_class"] for d in every_deal if "counterparty_class" in d} <= set(COUNTERPARTY_CLASSES)
    # §5.3 on the positive case: in_window.not_counted is the deals in the window of a class in NOT_COUNTED.
    person = next(c for c in all_cases if c["id"] == ("person-3-months" if instance == SH1 else "unpriced-counted"))
    in_window = [d for d in person["inputs"]["deals"] if d["agreed_at"] >= "2026-07-28T12:00:00Z"]
    assert model["in_window"]["not_counted"] == sum(d.get("counterparty_class") in NOT_COUNTED for d in in_window)
    standard = [c["expected"]["properties"] for c in all_cases if c["expected"]["standard"]]
    expected_table = {
        **history_frame.header("counting_table", instance),
        "inputs": {"deal_entry": DEAL_ENTRY,
                   "dispute_entry": list(deal("x", "", "", {}, "", "", None, (("s", "o", "f"),))["disputes"][0]),
                   "counterparty_class": COUNTERPARTY_CLASSES, "not_counted": NOT_COUNTED,
                   "record_kinds": RECORD_KINDS},
        "card_members": list(model),
        "tallies": {**{name: list(model[name]) for name in
                       ("in_window", "class_missing", "outcomes")},
                    "band": list(model["bands"][0]),
                    **({"unpriced": list(model["unpriced"])} if "unpriced" in model else {}),
                    **{name: list(model[name]) for name in ("roles", "happened", "disputes")},
                    "dispute": list(raised), "by_outcome": list(raised["by_outcome"]),
                    "by_forum": list(raised["by_forum"])},
        "units": UNITS,
        "properties": list(PROPERTIES),
        "may_be_not_checked": history_frame.not_checked_when_accepted(standard, list(PROPERTIES)),
    }
    assert table == expected_table, "counting table differs from this generator"
    assert pack == {**history_frame.header("wording_pack", instance), "language": "en",
                    "strings": PACK_STRINGS if instance == SH1 else PACK_STRINGS_2}, \
        "wording pack differs from this generator"
    for c in all_cases:
        statuses = c["expected"]["properties"]
        assert c["expected"]["standard"] is history_frame.accepted(statuses, table["may_be_not_checked"]), c["id"]


def check_frame_3(all_cases: list) -> None:
    """HF §6.3 for /3 (SH §11): its counting table and wording pack restate §11 and this generator's
    cases."""
    table, pack = history_frame.load(SH3)
    model = PERSON_3M_3
    raised = model["disputes"]["raised"]
    every_deal = [d for c in all_cases for d in c["inputs"].get("deals", [])]
    assert all(set(d) <= set(DEAL_ENTRY_3) for d in every_deal), "deal entry"
    every_row = [r for d in every_deal for r in d["rows"]]
    assert all(set(r) <= set(ROW_RESULT) for r in every_row), "row result"
    assert {r["status"] for r in every_row} <= set(ROW_STATUSES), "row status"
    in_window = [d for d in DEALS_3 if d["agreed_at"] >= "2026-07-28T12:00:00Z"]
    assert model["in_window"]["not_counted"] == sum(
        d.get("counterparty_class") in NOT_COUNTED_3 or d.get("left_out") in NOT_COUNTED_3 for d in in_window)
    standard = [c["expected"]["properties"] for c in all_cases if c["expected"]["standard"]]
    expected_table = {
        **history_frame.header("counting_table", SH3),
        "inputs": {"deal_entry": DEAL_ENTRY_3,
                   "row_result": ROW_RESULT,
                   "row_status": ROW_STATUSES,
                   "row_value": ["met", "not_met"],
                   "remedy": ["none", "due", "made", "not_honoured"],
                   "unruled_remedy": ["none", "made"],
                   "owed_by": ["holder", "counterparty"],
                   "dispute_entry": ["side", "outcome", "forum"],
                   "counterparty_class": COUNTERPARTY_CLASSES, "not_counted": NOT_COUNTED_3,
                   "record_kinds": RECORD_KINDS},
        "card_members": list(model),
        "tallies": {"in_window": list(model["in_window"]), "class_missing": list(model["class_missing"]),
                    "outcomes": list(model["outcomes"]), "did_not_hold": list(model["did_not_hold"]),
                    "local_times": list(model["local_times"]),
                    "band": list(model["bands"][0]), "unpriced": list(model["unpriced"]),
                    **{name: list(model[name]) for name in ("roles", "happened", "disputes")},
                    "dispute": list(raised), "by_outcome": list(raised["by_outcome"]),
                    "by_forum": list(raised["by_forum"])},
        "units": UNITS,
        "properties": list(PROPERTIES),
        "may_be_not_checked": history_frame.not_checked_when_accepted(standard, list(PROPERTIES)),
    }
    assert table == expected_table, "counting table differs from this generator"
    assert pack == {**history_frame.header("wording_pack", SH3), "language": "en", "strings": PACK_STRINGS_3}, \
        "wording pack differs from this generator"
    for c in all_cases:
        assert c["expected"]["standard"] is history_frame.accepted(c["expected"]["properties"],
                                                                   table["may_be_not_checked"]), c["id"]


def build() -> dict:
    all_cases, all_cases_2, all_cases_3 = cases(), cases_2(), cases_3()
    ids = [c["id"] for c in all_cases + all_cases_2 + all_cases_3]
    assert len(ids) == len(set(ids)), "duplicate case id"
    check_frame(all_cases)
    check_frame([c for c in all_cases_2 if c["inputs"]["derivation"] == SH2], SH2)
    check_frame([c for c in all_cases_3 if c["inputs"]["derivation"] == SH3], SH3)
    corpus = {"set": SET, "status": STATUS, "spec": SPEC, "properties": list(PROPERTIES),
              "count": len(all_cases), "cases": all_cases}
    corpus_2 = {"set": SET, "status": STATUS_2, "spec": SPEC, "derivation": SH2, "properties": list(PROPERTIES),
                "count": len(all_cases_2), "cases": all_cases_2}
    corpus_3 = {"set": SET, "status": STATUS_3, "spec": SPEC, "derivation": SH3, "properties": list(PROPERTIES),
                "count": len(all_cases_3), "cases": all_cases_3}
    files = {"vectors.json": _dump(corpus), "vectors-2.json": _dump(corpus_2), "vectors-3.json": _dump(corpus_3)}
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
