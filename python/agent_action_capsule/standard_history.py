# SPDX-License-Identifier: BSD-3-Clause
"""The ``standard_history/1`` derivation (``spec/standard-history-v0.md``, cited as SH).

Two functions:

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

__all__ = [
    "DERIVATION",
    "PROPERTIES",
    "COUNTERPARTY_CLASSES",
    "derive_card",
    "check_card",
    "is_standard",
]

DERIVATION = "standard_history/1"

#: SH §6, in the order a verifier reports them.
PROPERTIES = ("card_form", "counts_integral", "denominator", "window_from_policy", "as_of",
              "counts_recompute")

#: SH §7.
COUNTERPARTY_CLASSES = ("person_agent", "business_agent", "shop_preauth")
NOT_COUNTED = "shop_preauth"

HOLDER_KINDS = ("person", "node")
PERSON_CLASS = "person_declared"
ROLES = ("provided", "bought")
OUTCOMES = ("held", "did_not_hold", "undecided")
HAPPENED = ("stamped_by_both", "receipt_only", "no_record")
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
BAND_KEYS = ("currency", "decade")
MAX_COUNT = 2 ** 53 - 1

HEX64 = re.compile(r"[0-9a-f]{64}")
TOKEN = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*")
MONTH = re.compile(r"\d{4}-(?:0[1-9]|1[0-2])")
TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")   # IP §5.2
VALUE = re.compile(r"0|[1-9][0-9]*")                       # SR "Amounts"


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _time(text: Any) -> datetime:
    if not isinstance(text, str) or not TIME.fullmatch(text):
        raise ValueError(f"not an IP §5.2 time: {text!r}")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _window_start(anchor_time: datetime, months: int) -> datetime:
    """SH §5.1: the same time of day and day of the month, `months` calendar months earlier,
    clamped to the last day of a shorter month."""
    total = anchor_time.year * 12 + (anchor_time.month - 1) - months
    year, month = divmod(total, 12)
    month += 1
    day = min(anchor_time.day, calendar.monthrange(year, month)[1])
    return anchor_time.replace(year=year, month=month, day=day)


def _in_window(agreed_at: datetime, window: Mapping[str, Any], anchor_time: datetime) -> bool:
    if agreed_at > anchor_time:
        return False
    if window.get("all") is True:
        return True
    return agreed_at >= _window_start(anchor_time, window["months"])


def _decade(amount: Mapping[str, Any]) -> int:
    """SH §5.3: digits of the whole part, minus one; 0 when the whole part is 0."""
    value, scale = amount.get("value"), amount.get("assetScale")
    if not isinstance(value, str) or not VALUE.fullmatch(value):
        raise ValueError(f"amount value is not an exact integer string: {value!r}")
    if not isinstance(scale, int) or isinstance(scale, bool) or not 0 <= scale <= 255:
        raise ValueError(f"amount assetScale out of range: {scale!r}")
    whole = int(value) // 10 ** scale
    return len(str(whole)) - 1 if whole else 0


def _check_entry(deal: Mapping[str, Any]) -> None:
    """The deal entry's form (SH §5.2). A malformed entry is the caller's error, never a count."""
    if not isinstance(deal, Mapping):
        raise ValueError("a deal entry is not an object")
    if not isinstance(deal.get("deal"), str) or not deal["deal"]:
        raise ValueError("deal entry without a deal reference")
    _time(deal.get("agreed_at"))
    if "counterparty_class" in deal and deal["counterparty_class"] not in COUNTERPARTY_CLASSES:
        raise ValueError(f"unknown counterparty_class: {deal['counterparty_class']!r}")
    for member, values in (("role", ROLES), ("outcome", OUTCOMES), ("happened", HAPPENED)):
        if deal.get(member) not in values:
            raise ValueError(f"deal {deal['deal']}: {member} {deal.get(member)!r}")
    amount = deal.get("amount")
    if not isinstance(amount, Mapping) or not isinstance(amount.get("assetCode"), str) or not amount["assetCode"]:
        raise ValueError(f"deal {deal['deal']}: amount without an assetCode")
    _decade(amount)
    disputes = deal.get("disputes")
    if not isinstance(disputes, list):
        raise ValueError(f"deal {deal['deal']}: disputes is not an array")
    for d in disputes:
        if (not isinstance(d, Mapping) or d.get("side") not in SIDES
                or d.get("outcome") not in DISPUTE_OUTCOMES or d.get("forum") not in FORUMS):
            raise ValueError(f"deal {deal['deal']}: malformed dispute {d!r}")


def _zero(parts: Sequence[str]) -> dict:
    return {"of": 0, **{p: 0 for p in parts}}


def _counts(deals: Sequence[Mapping[str, Any]], window: Mapping[str, Any], anchor_time: datetime) -> dict:
    """The tallies SH §5 derives from the deal entries."""
    t = {name: _zero(parts) for name, parts in TALLIES.items()}
    bands: dict = {}
    disputes = {side: {"of": 0, "by_outcome": _zero(DISPUTE_OUTCOMES), "by_forum": _zero(FORUMS)}
                for side in SIDES}
    for deal in deals:
        _check_entry(deal)
        if not _in_window(_time(deal["agreed_at"]), window, anchor_time):
            continue
        t["in_window"]["of"] += 1
        if deal.get("counterparty_class") == NOT_COUNTED:
            t["in_window"]["not_counted"] += 1
            continue
        t["in_window"]["counted"] += 1
        t["class_missing"]["of"] += 1
        if "counterparty_class" not in deal:
            t["class_missing"]["count"] += 1
        for name, member in (("outcomes", "outcome"), ("roles", "role"), ("happened", "happened")):
            t[name]["of"] += 1
            t[name][deal[member]] += 1
        key = (deal["amount"]["assetCode"], _decade(deal["amount"]))
        band = bands.setdefault(key, {"currency": key[0], "decade": key[1], **_zero(OUTCOMES)})
        band["of"] += 1
        band[deal["outcome"]] += 1
        for d in deal["disputes"]:
            tally = disputes[d["side"]]
            tally["of"] += 1
            for sub, member in (("by_outcome", "outcome"), ("by_forum", "forum")):
                tally[sub]["of"] += 1
                tally[sub][d[member]] += 1
    t["bands"] = [bands[k] for k in sorted(bands)]
    t["disputes"] = disputes
    return t


def derive_card(*, holder_kind: str, controller_class: str, anchor: str, anchor_time: str,
                first_checkpoint_time: str, policy: Mapping[str, Any],
                deals: Sequence[Mapping[str, Any]]) -> dict:
    """The card SH §4 states for these inputs. ``policy`` is ``{"digest", "window"}`` (SH §5.1).

    Raises ``ValueError`` on a malformed input.
    """
    window = policy["window"]
    if not _policy_window(window):
        raise ValueError(f"not a policy window: {window!r}")
    _time(first_checkpoint_time)
    card = {"derivation": DERIVATION, "holder_kind": holder_kind, "controller_class": controller_class,
            "anchor": anchor, "since": first_checkpoint_time[:7], "window": dict(window),
            "policy": policy["digest"]}
    card.update(_counts(deals, window, _time(anchor_time)))
    return card


def _window_form(w: Any) -> bool:
    if not isinstance(w, Mapping):
        return False
    if set(w) == {"all"}:
        return w["all"] is True
    return (set(w) == {"months"} and _is_number(w["months"]) and w["months"] >= 1)


def _policy_window(w: Any) -> bool:
    """A policy's window: a card's window form, with a whole number of months."""
    return _window_form(w) and ("all" in w or (float(w["months"]).is_integer() and w["months"] <= MAX_COUNT))


def _tally_form(t: Any, parts: Sequence[str]) -> bool:
    """SH §6 card_form: exactly the tally's parts, each a number, and optionally `of`."""
    if not isinstance(t, Mapping) or not set(parts) <= set(t) <= set(parts) | {"of"}:
        return False
    return all(_is_number(v) for v in t.values())


def _card_form(card: Any) -> bool:
    if not isinstance(card, Mapping) or set(card) != CARD_MEMBERS:
        return False
    if card["derivation"] != DERIVATION or card["holder_kind"] not in HOLDER_KINDS:
        return False
    cls = card["controller_class"]
    if not isinstance(cls, str) or not TOKEN.fullmatch(cls):
        return False
    if (card["holder_kind"] == "person") != (cls == PERSON_CLASS):
        return False
    for member in ("anchor", "policy"):
        if not isinstance(card[member], str) or not HEX64.fullmatch(card[member]):
            return False
    if not isinstance(card["since"], str) or not MONTH.fullmatch(card["since"]):
        return False
    if not _window_form(card["window"]):
        return False
    if not all(_tally_form(card[name], parts) for name, parts in TALLIES.items()):
        return False
    bands = card["bands"]
    if not isinstance(bands, list):
        return False
    keys = []
    for band in bands:
        if not isinstance(band, Mapping) or not set(BAND_KEYS) <= set(band):
            return False
        if not isinstance(band["currency"], str) or not band["currency"] or not _is_number(band["decade"]):
            return False
        if not _tally_form({k: v for k, v in band.items() if k not in BAND_KEYS}, OUTCOMES):
            return False
        keys.append((band["currency"], band["decade"]))
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


def _counts_integral(card: Any) -> bool:
    """SH §6: every number an integer value from 0 to 2^53 - 1. A card travels as JCS, which
    writes 75.0 as 75, so the check is on the value, not on how it was written."""
    for n in _numbers(card):
        if isinstance(n, float) and not n.is_integer():
            return False
        if not 0 <= n <= MAX_COUNT:
            return False
    return True


def _partitions(t: Mapping[str, Any], parts: Sequence[str]) -> bool:
    return "of" in t and sum(t[p] for p in parts) == t["of"]


def _denominator(card: Mapping[str, Any]) -> bool:
    """SH §4 "Denominators". Run only on a card whose form and counts are PASS."""
    for name, parts in TALLIES.items():
        t = card[name]
        if "of" not in t:
            return False
        if name == "class_missing":
            if t["count"] > t["of"]:
                return False
        elif not _partitions(t, parts):
            return False
    counted = card["in_window"]["counted"]
    if any(card[name]["of"] != counted for name in ("class_missing", "outcomes", "roles", "happened")):
        return False
    for band in card["bands"]:
        if not _partitions(band, OUTCOMES):
            return False
    for o in ("of",) + OUTCOMES:
        if sum(band[o] for band in card["bands"]) != card["outcomes"][o]:
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
               deals: Sequence[Mapping[str, Any]] | None = None) -> dict:
    """The six card properties of SH §6, in order.

    ``policy`` is ``{"digest", "window"}`` (SH §5.1); ``as_of`` is ``{"anchor", "anchor_time",
    "first_checkpoint_time"}``; ``deals`` is every deal entry the stream holds at the anchor. Each
    is optional; a property that needs a missing one is ``NOT_CHECKED``. Raises ``ValueError`` on a
    malformed input, never on a malformed card.
    """
    p = {}
    p["card_form"] = _status(_card_form(card))
    p["counts_integral"] = _status(_counts_integral(card))
    if p["card_form"] == "PASS" and p["counts_integral"] == "PASS":
        p["denominator"] = _status(_denominator(card))
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
        first = _time(as_of.get("first_checkpoint_time"))
        p["as_of"] = _status(isinstance(card, Mapping) and card.get("anchor") == as_of.get("anchor")
                             and card.get("since") == first.strftime("%Y-%m"))
    ready = (deals is not None and policy is not None and as_of is not None
             and all(p[k] == "PASS" for k in ("card_form", "counts_integral", "denominator")))
    if not ready:
        p["counts_recompute"] = "NOT_CHECKED"
    else:
        derived = _counts(deals, policy["window"], _time(as_of.get("anchor_time")))
        p["counts_recompute"] = _status(all(card[k] == v for k, v in derived.items()))
    return p


def is_standard(properties: Mapping[str, str]) -> bool:
    """SH §6: a standard card has no FAIL, and its form, counts and denominators PASS."""
    return (all(properties[k] in ("PASS", "NOT_CHECKED") for k in PROPERTIES)
            and all(properties[k] == "PASS" for k in ("card_form", "counts_integral", "denominator")))
