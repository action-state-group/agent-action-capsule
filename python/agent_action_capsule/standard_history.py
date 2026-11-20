# SPDX-License-Identifier: BSD-3-Clause
"""The ``standard_history/1`` to ``standard_history/4`` derivations (``spec/standard-history-v0.md``,
cited as SH; ``/3`` is SH §11 and ``/4`` is SH §12).

Two functions, each for the token its ``derivation`` names (``/1`` when omitted):

* :func:`derive_card` builds a card from the deal entries (SH §5.2), the policy's window and
  digest (SH §5.1) and the anchor. It is the holder's side.
* :func:`check_card` reports the six card properties of SH §6 for a card, from whatever the
  caller holds: the policy, the anchor, the deal entries. What it does not hold, it reports
  ``NOT_CHECKED``.

The vectors of ``vectors/standard-history-v0/`` are this module's tests, and the Go package
``go/standardhistory`` runs the same vectors. Standard library only.
"""
from __future__ import annotations

import calendar
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from .canonical import too_deep

__all__ = [
    "DERIVATION",
    "DERIVATION_2",
    "DERIVATION_3",
    "DERIVATION_4",
    "DERIVATIONS",
    "PROPERTIES",
    "COUNTERPARTY_CLASSES",
    "derive_card",
    "check_card",
    "is_standard",
]

DERIVATION = "standard_history/1"
#: SH §4, §5.3: /2 also counts the counted deals with no recorded amount, in ``unpriced``.
DERIVATION_2 = "standard_history/2"
#: SH §11: /3 counts each deal's outcome from its term rows, counts the deals that did not hold
#: that the holder remedied or whose ruling it did not honour, and carries the shelf log's coverage
#: start.
DERIVATION_3 = "standard_history/3"
#: SH §12: /4 is /3 except that it leaves no deal out for want of a witness time: no ``left_out``
#: and no ``not_counted`` tally.
DERIVATION_4 = "standard_history/4"
DERIVATIONS = (DERIVATION, DERIVATION_2, DERIVATION_3, DERIVATION_4)
#: The tokens that count a shelf log's deals from their term rows (SH §11, §12).
SHELF = (DERIVATION_3, DERIVATION_4)

#: SH §6, in the order a verifier reports them.
PROPERTIES = ("card_form", "counts_integral", "denominator", "window_from_policy", "as_of",
              "counts_recompute")

#: SH §7.
COUNTERPARTY_CLASSES = ("person_agent", "business_agent", "shop_preauth")
NOT_COUNTED = "shop_preauth"

HOLDER_KINDS = ("person", "node")
#: SH §4: the one controller class /1 allows for each holder kind.
CONTROLLER_CLASSES = {"person": "person_declared", "node": "node_declared"}
ROLES = ("provided", "bought")
OUTCOMES = ("held", "did_not_hold", "undecided")
HAPPENED = ("stamped_by_both", "receipt_only", "no_record")
#: SH §11.6: the parts of not_counted, in the order the first that applies wins.
NOT_COUNTED_3 = ("shop_preauth", "no_witness_time")
#: SH §11.2: a row result's members' values.
ROW_STATUSES = ("not_reached", "not_due", "no_statement", "waiting", "uncontested", "agreed_so_far",
                "agreed", "in_disagreement", "in_dispute", "ruled")
VALUED = frozenset(("waiting", "uncontested", "agreed_so_far", "agreed", "ruled"))
ROW_VALUES = ("met", "not_met")
REMEDIES = ("none", "due", "made", "not_honoured")
#: SH §11.2: the remedy states of an unmet row that is not ruled: none, or made by the holder's own
#: remedy record, with no ruling.
UNRULED_REMEDIES = ("none", "made")
UNMET_STATUSES = ("agreed_so_far", "agreed", "uncontested")
OWED_BY = ("holder", "counterparty")
LEFT_OUT = ("no_witness_time",)
SIDES = ("raised", "received")
DISPUTE_OUTCOMES = ("open", "for", "against", "split", "no_finding", "withdrawn")
FORUMS = ("auto", "network", "rail", "external")

# SH §4: each tally's parts. `of` is every tally's denominator.
TALLIES = {
    "in_window": ("counted", "not_counted"),
    "class_missing": ("count",),
    "outcomes": OUTCOMES,
    "roles": ROLES,
    "happened": HAPPENED,
}
CARD_MEMBERS = frozenset(("derivation", "holder_kind", "controller_class", "anchor", "since", "window",
                          "policy", "bands", "disputes") + tuple(TALLIES))
#: SH §4: the members of each token's card.
MEMBERS = {DERIVATION: CARD_MEMBERS, DERIVATION_2: CARD_MEMBERS | {"unpriced"},
           DERIVATION_3: CARD_MEMBERS | {"unpriced", "coverage_start", "not_counted", "remedied",
                                         "not_honoured", "local_times"},
           DERIVATION_4: CARD_MEMBERS | {"unpriced", "coverage_start", "remedied", "not_honoured",
                                         "local_times"}}
BAND_KEYS = ("currency", "decade")
MAX_COUNT = 2 ** 53 - 1

HEX64 = re.compile(r"[0-9a-f]{64}")
# ASCII digits only: Python's \d also matches other scripts' digits, which RE2 does not.
MONTH = re.compile(r"[0-9]{4}-(?:0[1-9]|1[0-2])")
TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")   # IP §5.2
VALUE = re.compile(r"0|[1-9][0-9]*")                       # SR "Amounts"
# SR "Amounts" assetCode: an ISO 4217 alphabetic code (BTC included), or a CAIP-19 asset type.
CURRENCY = re.compile(r"[A-Z]{3}|[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}")


def _tallies(derivation: str) -> dict:
    t = dict(TALLIES)
    if derivation == DERIVATION_3:
        t["not_counted"] = NOT_COUNTED_3
    if derivation in SHELF:
        t["remedied"] = ("count",)
        t["not_honoured"] = ("count",)
        t["local_times"] = ("count",)
    return t


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _time(text: Any) -> datetime:
    if not isinstance(text, str) or not TIME.fullmatch(text):
        raise ValueError(f"not an IP §5.2 time: {text!r}")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _window_start(anchor_time: datetime, months: int) -> datetime | None:
    """SH §5.1: the same time of day and day of the month, `months` calendar months earlier,
    clamped to the last day of a shorter month. None when that is before year 1, the first year a
    time can name: every deal is then after the start."""
    total = anchor_time.year * 12 + (anchor_time.month - 1) - int(months)
    year, month = divmod(total, 12)
    if year < 1:
        return None
    month += 1
    day = min(anchor_time.day, calendar.monthrange(year, month)[1])
    return anchor_time.replace(year=year, month=month, day=day)


def _in_window(agreed_at: datetime, window: Mapping[str, Any], anchor_time: datetime) -> bool:
    if agreed_at > anchor_time:
        return False
    if window.get("all") is True:
        return True
    start = _window_start(anchor_time, window["months"])
    return start is None or agreed_at >= start


def _decade(amount: Mapping[str, Any]) -> int | None:
    """SH §5.3: floor(log10(value / 10^assetScale)), exactly digits(value) - assetScale - 1;
    None for a zero amount."""
    value, scale = amount.get("value"), amount.get("assetScale")
    if not isinstance(value, str) or not VALUE.fullmatch(value):
        raise ValueError(f"amount value is not an exact integer string: {value!r}")
    if not isinstance(scale, int) or isinstance(scale, bool) or not 0 <= scale <= 255:
        raise ValueError(f"amount assetScale out of range: {scale!r}")
    return None if value == "0" else len(value) - scale - 1


#: SH §11.2: the members a /3 deal entry may carry; a /4 entry has ``no_witness_time`` in place of
#: ``left_out`` (SH §12). /1 and /2 entries are read as SH §5.2 says.
_ENTRY_MEMBERS = frozenset(("deal", "agreed_at", "counterparty_class", "role", "amount", "rows",
                            "happened", "disputes"))
ENTRY_MEMBERS = {DERIVATION_3: _ENTRY_MEMBERS | {"left_out"}, DERIVATION_4: _ENTRY_MEMBERS | {"no_witness_time"}}
ROW_MEMBERS = frozenset(("owed_by", "status", "value", "remedy", "local"))


def _check_row(ref: str, row: Any) -> None:
    """SH §11.2: a row result, with ``value`` and ``remedy`` exactly where the status carries them,
    and ``local`` only as ``true``."""
    if not isinstance(row, Mapping) or not set(row) <= ROW_MEMBERS:
        raise ValueError(f"deal {ref}: malformed row result {row!r}")
    status = row.get("status")
    if row.get("owed_by") not in OWED_BY or status not in ROW_STATUSES:
        raise ValueError(f"deal {ref}: malformed row result {row!r}")
    if ("value" in row) != (status in VALUED) or ("value" in row and row["value"] not in ROW_VALUES):
        raise ValueError(f"deal {ref}: row value {row!r}")
    unmet = status in UNMET_STATUSES and row.get("value") == "not_met"
    allowed = REMEDIES if status == "ruled" else UNRULED_REMEDIES if unmet else ()
    if ("remedy" in row) != bool(allowed) or ("remedy" in row and row["remedy"] not in allowed):
        raise ValueError(f"deal {ref}: row remedy {row!r}")
    if "local" in row and row["local"] is not True:
        raise ValueError(f"deal {ref}: row local {row!r}")


def _check_entry(deal: Mapping[str, Any], derivation: str) -> None:
    """The deal entry's form (SH §5.2; under /3, §11.2; under /4, §12). A malformed entry is the
    caller's error, never a count. ``amount`` may be absent except under /1: a /1 entry cannot be
    filled without it (SH §3)."""
    if not isinstance(deal, Mapping):
        raise ValueError("a deal entry is not an object")
    if not isinstance(deal.get("deal"), str) or not deal["deal"]:
        raise ValueError("deal entry without a deal reference")
    v3 = derivation in SHELF
    if v3 and not set(deal) <= ENTRY_MEMBERS[derivation]:
        raise ValueError(f"deal {deal['deal']}: a member a {derivation} entry does not have")
    _time(deal.get("agreed_at"))
    if "counterparty_class" in deal and deal["counterparty_class"] not in COUNTERPARTY_CLASSES:
        raise ValueError(f"unknown counterparty_class: {deal['counterparty_class']!r}")
    checks = [("role", ROLES), ("happened", HAPPENED)] + ([] if v3 else [("outcome", OUTCOMES)])
    for member, values in checks:
        if deal.get(member) not in values:
            raise ValueError(f"deal {deal['deal']}: {member} {deal.get(member)!r}")
    if v3:
        if "left_out" in deal and deal["left_out"] not in LEFT_OUT:
            raise ValueError(f"deal {deal['deal']}: left_out {deal['left_out']!r}")
        if "no_witness_time" in deal and deal["no_witness_time"] is not True:
            raise ValueError(f"deal {deal['deal']}: no_witness_time {deal['no_witness_time']!r}")
        rows = deal.get("rows")
        if not isinstance(rows, list) or not rows:
            raise ValueError(f"deal {deal['deal']}: rows is not a non-empty array")
        for row in rows:
            _check_row(deal["deal"], row)
    if "amount" in deal or derivation == DERIVATION:
        amount = deal.get("amount")
        if (not isinstance(amount, Mapping) or not isinstance(amount.get("assetCode"), str)
                or not CURRENCY.fullmatch(amount["assetCode"])):
            raise ValueError(f"deal {deal['deal']}: amount without an SR assetCode")
        _decade(amount)
    disputes = deal.get("disputes")
    if not isinstance(disputes, list):
        raise ValueError(f"deal {deal['deal']}: disputes is not an array")
    for d in disputes:
        if (not isinstance(d, Mapping) or d.get("side") not in SIDES
                or d.get("outcome") not in DISPUTE_OUTCOMES or d.get("forum") not in FORUMS):
            raise ValueError(f"deal {deal['deal']}: malformed dispute {d!r}")


def outcome(rows: Sequence[Mapping[str, Any]]) -> tuple[str, str | None]:
    """SH §11.3 and §11.4: a counted /3 deal's outcome, the first rule that applies, and for a
    ``did_not_hold`` deal whether the holder did not honour a ruling (``"not_honoured"``) or
    remedied its unmet rows (``"remedied"``); None otherwise. Only rows the holder owed can make a
    deal ``did_not_hold``; the counterparty's unmet rows are read as met."""
    own = [r for r in rows if r["owed_by"] == "holder"]
    if any(r["status"] == "ruled" and r["remedy"] == "not_honoured" for r in own):
        return "did_not_hold", "not_honoured"
    unmet = [r for r in own if r["status"] in UNMET_STATUSES + ("ruled",) and r["value"] == "not_met"]
    # Remedied when every unmet row has its remedy made, by a ruling or without one.
    failed = ("did_not_hold", "remedied" if all(r["remedy"] == "made" for r in unmet) else None)
    # A final unmet row comes before the rows still open, so a dispute cannot hide it.
    if any(r["status"] != "agreed_so_far" for r in unmet):
        return failed
    if any(r["status"] in ("in_disagreement", "in_dispute", "no_statement")
           or (r["status"] == "waiting" and r["value"] == "not_met") for r in rows):
        return "undecided", None
    if unmet:
        return failed
    # A row not reached comes after did_not_hold, so it cannot hide an unmet row.
    if any(r["status"] in ("not_reached", "not_due", "waiting", "agreed_so_far") for r in rows):
        return "undecided", None
    return "held", None


def _zero(parts: Sequence[str]) -> dict:
    return {"of": 0, **{p: 0 for p in parts}}


def _counts(deals: Sequence[Mapping[str, Any]], window: Mapping[str, Any], anchor_time: datetime,
            derivation: str = DERIVATION) -> dict:
    """The tallies SH §5 derives from the deal entries, for the token's card."""
    t = {name: _zero(parts) for name, parts in _tallies(derivation).items()}
    if derivation != DERIVATION:
        t["unpriced"] = _zero(OUTCOMES)
    bands: dict = {}
    disputes = {side: {"of": 0, "by_outcome": _zero(DISPUTE_OUTCOMES), "by_forum": _zero(FORUMS)}
                for side in SIDES}
    for deal in deals:
        _check_entry(deal, derivation)
        if not _in_window(_time(deal["agreed_at"]), window, anchor_time):
            continue
        t["in_window"]["of"] += 1
        # SH §11.2: under /3 a deal left out is not counted either; /4 leaves none out (SH §12).
        if deal.get("counterparty_class") == NOT_COUNTED or (derivation == DERIVATION_3 and "left_out" in deal):
            t["in_window"]["not_counted"] += 1
            if derivation == DERIVATION_3:
                reason = "shop_preauth" if deal.get("counterparty_class") == NOT_COUNTED else "no_witness_time"
                t["not_counted"]["of"] += 1
                t["not_counted"][reason] += 1
            continue
        t["in_window"]["counted"] += 1
        t["class_missing"]["of"] += 1
        if "counterparty_class" not in deal:
            t["class_missing"]["count"] += 1
        if derivation in SHELF:
            result, detail = outcome(deal["rows"])
            if result == "did_not_hold":
                for name in ("remedied", "not_honoured"):
                    t[name]["of"] += 1
                    t[name]["count"] += int(detail == name)
            t["local_times"]["of"] += 1
            # SH §12: under /4 a deal with no witnessed time is in local_times whatever its rows say.
            if any(r.get("local") for r in deal["rows"]) or deal.get("no_witness_time"):
                t["local_times"]["count"] += 1
        else:
            result = deal["outcome"]
        for name, value in (("outcomes", result), ("roles", deal["role"]), ("happened", deal["happened"])):
            t[name]["of"] += 1
            t[name][value] += 1
        if "amount" not in deal:
            # SH §5.3: an unpriced deal (/2 only) is in `unpriced` and in no band.
            band = t["unpriced"]
        else:
            key = (deal["amount"]["assetCode"], _decade(deal["amount"]))
            band = bands.setdefault(key, {"currency": key[0], "decade": key[1], **_zero(OUTCOMES)})
        band["of"] += 1
        band[result] += 1
        for d in deal["disputes"]:
            tally = disputes[d["side"]]
            tally["of"] += 1
            for sub, member in (("by_outcome", "outcome"), ("by_forum", "forum")):
                tally[sub]["of"] += 1
                tally[sub][d[member]] += 1
    t["bands"] = [bands[k] for k in sorted(bands, key=_band_order)]
    t["disputes"] = disputes
    return t


def _band_order(key: tuple) -> tuple:
    """SH §4: by currency, then decade, the zero-amount band (decade null) first."""
    currency, decade = key
    return (currency, decade is not None, decade if decade is not None else 0)


def derive_card(*, holder_kind: str, controller_class: str, anchor: str, anchor_time: str,
                first_checkpoint_time: str, policy: Mapping[str, Any],
                deals: Sequence[Mapping[str, Any]], derivation: str = DERIVATION,
                coverage_start_time: str | None = None) -> dict:
    """The card of the token ``derivation`` that SH §4 (under /3, §11.6) states for these inputs.
    ``policy`` is ``{"digest", "window"}`` (SH §5.1). ``coverage_start_time`` is the time of the
    shelf log's coverage start (SH §11.5), required under /3 and /4 only.

    Raises ``ValueError`` on a malformed input, a /1 deal entry without an amount included.
    """
    if derivation not in DERIVATIONS:
        raise ValueError(f"not a standard_history token: {derivation!r}")
    if not _policy_window(policy["window"]):
        raise ValueError(f"not a policy window: {policy['window']!r}")
    window = _whole(policy["window"])
    _time(first_checkpoint_time)
    card = {"derivation": derivation, "holder_kind": holder_kind, "controller_class": controller_class,
            "anchor": anchor, "since": first_checkpoint_time[:7], "window": dict(window),
            "policy": policy["digest"]}
    if derivation in SHELF:
        _time(coverage_start_time)
        if not first_checkpoint_time <= coverage_start_time <= anchor_time:
            raise ValueError("the coverage start is not between the first checkpoint and the anchor")
        card["coverage_start"] = coverage_start_time[:7]
    card.update(_counts(deals, window, _time(anchor_time), derivation))
    return card


def _window_form(w: Any) -> bool:
    if not isinstance(w, Mapping):
        return False
    if set(w) == {"all"}:
        return w["all"] is True
    return (set(w) == {"months"} and _is_number(w["months"]) and w["months"] >= 1)


def _whole(w: Mapping[str, Any]) -> dict:
    """A policy window with its month count as an int (3.0 is 3, as JCS writes it)."""
    return {"all": True} if "all" in w else {"months": int(w["months"])}


def _policy_window(w: Any) -> bool:
    """A policy's window: a card's window form, with a whole number of months."""
    return _window_form(w) and ("all" in w or (float(w["months"]).is_integer() and w["months"] <= MAX_COUNT))


def _tally_form(t: Any, parts: Sequence[str]) -> bool:
    """SH §6 card_form: exactly the tally's parts, each a number, and optionally `of`."""
    if not isinstance(t, Mapping) or not set(parts) <= set(t) <= set(parts) | {"of"}:
        return False
    return all(_is_number(v) for v in t.values())


def _card_form(card: Any, derivation: str) -> bool:
    if not isinstance(card, Mapping) or set(card) != MEMBERS[derivation]:
        return False
    if card["derivation"] != derivation or card["holder_kind"] not in HOLDER_KINDS:
        return False
    if card["controller_class"] != CONTROLLER_CLASSES[card["holder_kind"]]:
        return False
    for member in ("anchor", "policy"):
        if not isinstance(card[member], str) or not HEX64.fullmatch(card[member]):
            return False
    if not isinstance(card["since"], str) or not MONTH.fullmatch(card["since"]):
        return False
    if not _window_form(card["window"]):
        return False
    if not all(_tally_form(card[name], parts) for name, parts in _tallies(derivation).items()):
        return False
    if derivation != DERIVATION and not _tally_form(card["unpriced"], OUTCOMES):
        return False
    if derivation in SHELF:
        start = card["coverage_start"]
        if not isinstance(start, str) or not MONTH.fullmatch(start) or start < card["since"]:
            return False
    bands = card["bands"]
    if not isinstance(bands, list):
        return False
    keys = []
    for band in bands:
        if not isinstance(band, Mapping) or not set(BAND_KEYS) <= set(band):
            return False
        if not isinstance(band["currency"], str) or not CURRENCY.fullmatch(band["currency"]):
            return False
        if band["decade"] is not None and not _is_number(band["decade"]):
            return False
        if not _tally_form({k: v for k, v in band.items() if k not in BAND_KEYS}, OUTCOMES):
            return False
        keys.append(_band_order((band["currency"], band["decade"])))
    if any(a >= b for a, b in zip(keys, keys[1:])):
        return False
    disputes = card["disputes"]
    if not isinstance(disputes, Mapping) or set(disputes) != set(SIDES):
        return False
    for d in disputes.values():
        if not isinstance(d, Mapping) or not {"by_outcome", "by_forum"} <= set(d) <= {"of", "by_outcome", "by_forum"}:
            return False
        if "of" in d and not _is_number(d["of"]):
            return False
        if not (_tally_form(d["by_outcome"], DISPUTE_OUTCOMES) and _tally_form(d["by_forum"], FORUMS)):
            return False
    return True


def _numbers(v: Any):
    if isinstance(v, Mapping):
        for x in v.values():
            yield from _numbers(x)
    elif isinstance(v, list):
        for x in v:
            yield from _numbers(x)
    elif _is_number(v):
        yield v


def _integral(n: Any, low: int) -> bool:
    return not (isinstance(n, float) and not n.is_integer()) and low <= n <= MAX_COUNT


def _counts_integral(card: Any) -> bool:
    """SH §6: every number an integer of at most 2^53 - 1 in magnitude, and 0 or more except a
    band's decade. A card travels as JCS, which writes 75.0 as 75, so the check is on the value,
    not on how it was written."""
    decades: list = []
    rest = card
    if isinstance(card, Mapping) and isinstance(card.get("bands"), list):
        bands = []
        for band in card["bands"]:
            if isinstance(band, Mapping) and "decade" in band:
                decades.append(band["decade"])
                band = {k: v for k, v in band.items() if k != "decade"}
            bands.append(band)
        rest = {**card, "bands": bands}
    return (all(_integral(n, 0) for n in _numbers(rest))
            and all(_integral(n, -MAX_COUNT) for n in _numbers(decades)))


def _partitions(t: Mapping[str, Any], parts: Sequence[str]) -> bool:
    return "of" in t and sum(t[p] for p in parts) == t["of"]


def _denominator(card: Mapping[str, Any], derivation: str) -> bool:
    """SH §4 "Denominators" (under /3 and /4, §11.6). Run only on a card whose form and counts are PASS."""
    for name, parts in _tallies(derivation).items():
        t = card[name]
        if "of" not in t:
            return False
        if name in ("class_missing", "remedied", "not_honoured", "local_times"):
            if t["count"] > t["of"]:
                return False
        elif not _partitions(t, parts):
            return False
    counted = card["in_window"]["counted"]
    if any(card[name]["of"] != counted for name in ("class_missing", "outcomes", "roles", "happened")):
        return False
    if derivation in SHELF and card["local_times"]["of"] != counted:
        return False
    if derivation == DERIVATION_3 and card["not_counted"]["of"] != card["in_window"]["not_counted"]:
        return False
    for band in card["bands"]:
        if not _partitions(band, OUTCOMES) or band["of"] < 1:
            return False
    # SH §4: on a /2 card the bands and `unpriced` together partition the outcomes.
    priced = list(card["bands"])
    if "unpriced" in card:
        if not _partitions(card["unpriced"], OUTCOMES):
            return False
        priced.append(card["unpriced"])
    for o in ("of",) + OUTCOMES:
        if sum(band[o] for band in priced) != card["outcomes"][o]:
            return False
    if derivation in SHELF:
        # SH §11.4: a did_not_hold deal is in at most one of the two counts.
        did_not_hold = card["outcomes"]["did_not_hold"]
        if (any(card[name]["of"] != did_not_hold for name in ("remedied", "not_honoured"))
                or card["remedied"]["count"] + card["not_honoured"]["count"] > did_not_hold):
            return False
    for d in card["disputes"].values():
        if "of" not in d:
            return False
        if not (_partitions(d["by_outcome"], DISPUTE_OUTCOMES) and _partitions(d["by_forum"], FORUMS)):
            return False
        if d["by_outcome"]["of"] != d["of"] or d["by_forum"]["of"] != d["of"]:
            return False
    return True


def _status(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def check_card(card: Any, *, policy: Mapping[str, Any] | None = None,
               as_of: Mapping[str, Any] | None = None,
               deals: Sequence[Mapping[str, Any]] | None = None,
               derivation: str = DERIVATION) -> dict:
    """The six card properties of SH §6, in order, for a card checked under the token
    ``derivation``, the one the request named.

    ``policy`` is ``{"digest", "window"}`` (SH §5.1); ``as_of`` is ``{"anchor", "anchor_time",
    "first_checkpoint_time"}``, and under /3 and /4 also ``"coverage_start_time"`` (SH §11.7); ``deals`` is every deal entry the stream holds at the anchor, passed only when the verifier has
    shown coverage and no payload member the mapping reads is withheld (SH §6 "Handing the
    material"); the counts are recomputed over the card's own
    window, so the policy is not needed for them. Each is optional; a property that needs a missing one is ``NOT_CHECKED``. Raises ``ValueError`` on a
    malformed input, never on a malformed card. A card nested deeper than the shared
    128-level limit reads as no card, as Go's ``Check`` reads one it cannot parse.
    """
    if derivation not in DERIVATIONS:
        raise ValueError(f"not a standard_history token: {derivation!r}")
    parsed = not too_deep(card)
    if not parsed:
        card = None
    p = {}
    p["card_form"] = _status(_card_form(card, derivation))
    p["counts_integral"] = _status(parsed and _counts_integral(card))
    if p["card_form"] == "PASS" and p["counts_integral"] == "PASS":
        p["denominator"] = _status(_denominator(card, derivation))
    else:
        p["denominator"] = "NOT_CHECKED"
    if policy is None:
        p["window_from_policy"] = "NOT_CHECKED"
    else:
        if not _policy_window(policy.get("window")):
            raise ValueError(f"not a policy window: {policy.get('window')!r}")
        p["window_from_policy"] = _status(isinstance(card, Mapping) and _window_form(card.get("window"))
                                          and card["window"] == policy["window"]
                                          and card.get("policy") == policy.get("digest"))
    if as_of is None:
        p["as_of"] = "NOT_CHECKED"
    else:
        _time(as_of.get("first_checkpoint_time"))
        ok = (isinstance(card, Mapping) and card.get("anchor") == as_of.get("anchor")
              and card.get("since") == as_of["first_checkpoint_time"][:7])
        if derivation in SHELF:
            _time(as_of.get("coverage_start_time"))
            _time(as_of.get("anchor_time"))
            # SH §11.1: the anchor is at or after the coverage start.
            ok = (ok and card.get("coverage_start") == as_of["coverage_start_time"][:7]
                  and as_of["coverage_start_time"] <= as_of.get("anchor_time", ""))
        p["as_of"] = _status(ok)
    ready = (deals is not None and as_of is not None
             and all(p[k] == "PASS" for k in ("card_form", "counts_integral", "denominator")))
    if not ready:
        p["counts_recompute"] = "NOT_CHECKED"
    else:
        derived = _counts(deals, _whole(card["window"]), _time(as_of.get("anchor_time")), derivation)
        p["counts_recompute"] = _status(all(card[k] == v for k, v in derived.items()))
    return p


def is_standard(properties: Mapping[str, str]) -> bool:
    """SH §6: a standard card has no FAIL, and its form, counts and denominators PASS."""
    return (all(properties.get(k) in ("PASS", "NOT_CHECKED") for k in PROPERTIES)
            and all(properties[k] == "PASS" for k in ("card_form", "counts_integral", "denominator")))
