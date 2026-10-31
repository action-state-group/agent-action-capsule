# SPDX-License-Identifier: BSD-3-Clause
"""The History frame's instance documents (``spec/history-frame-v0.md``, cited as HF).

Each instance of the frame pins one counting table and one wording pack, by the digests HF §6
lists. ``DIGESTS`` restates that list. ``load`` reads an instance's two documents from
``spec/history-frame/``, and fails unless their digests are the listed ones and the pack meets
HF §5.3. The instance generators call it and then assert that each document equals, member for
member, the one their own constants and cases give (HF §6.3): when a document and the instance's text disagree, the change that made them disagree
is wrong, and the generator stops it.

Standard library only.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "spec" / "history-frame"
FRAME = "history-frame/0"

# HF §6: each instance identifier, its two documents and their digests (SHA-256 of UTF-8 of JCS).
FILES = {
    "standard_history/1": ("standard-history-1-table.json", "standard-history-1-pack.json"),
    "personal_history_basic/1": ("personal-history-basic-1-table.json", "personal-history-basic-1-pack.json"),
    "personal_history_outcome/1": ("personal-history-outcome-1-table.json", "personal-history-outcome-1-pack.json"),
    "inference-service-history/0": ("inference-service-history-0-table.json", "inference-service-history-0-pack.json"),
}
DIGESTS = {
    "standard_history/1": {
        "table": "31122b837d2bea44dd3f559ca90a69f666c146ebb3f1b4d9f7df1c1fd3d47c53",
        "pack": "dcea1ee99942d0b4dc78b380b63f7854964d132925de18fdeb30b336e9877b74",
    },
    "personal_history_basic/1": {
        "table": "d7f17129d98f5b849c59fb4d906bc3e9c57ce13fe08d00433fbe09161125ebb1",
        "pack": "b3e4868affdaeede5eeadb0d909d4e4f665260d6a68a3c10896ab9a0abf6be60",
    },
    "personal_history_outcome/1": {
        "table": "a332d408c5ea2566b8f650769f92044c1b075c028cfcd64b112b626fc7b7e97c",
        "pack": "00dce14b0bfdda0187b274727dd34d7b6a8bd5d5bf3884b934f6840604fc6d47",
    },
    "inference-service-history/0": {
        "table": "3307e6f1e58759aea656b3e84afa8e21b00a14a260e5cc11513c379eb92c7057",
        "pack": "693ae7f8f259ec37bf9b177f6373c295d6a851abf359859e8e5a3e627d08ed82",
    },
}


def jcs(value: Any) -> bytes:
    """UTF-8 of RFC 8785 JCS for the value space of these documents: no numbers, ASCII member names."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def json_digest(value: Any) -> str:
    return hashlib.sha256(jcs(value)).hexdigest()


def read(name: str) -> dict:
    return json.loads((DOCS / name).read_text(encoding="utf-8"))


def strings(value: Any) -> set[str]:
    """Every text string in ``value``: member names and string values, at every level."""
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        out = set(value)
        for v in value.values():
            out |= strings(v)
        return out
    if isinstance(value, list):
        out = set()
        for v in value:
            out |= strings(v)
        return out
    return set()


def header_ok(doc: dict, kind: str, instance: str) -> bool:
    return doc.get("document") == kind and doc.get("frame") == FRAME and doc.get("instance") == instance


def pack_form(table: dict, pack: dict, instance: str) -> bool:
    """HF §5.3: exactly the pack members, every string a non-empty text, and no string one that the
    instance's counting table carries (those are what its properties check)."""
    if set(pack) != {"document", "frame", "instance", "language", "strings"} or not header_ok(pack, "wording_pack",
                                                                                              instance):
        return False
    texts = pack["strings"]
    if not isinstance(texts, dict) or not texts or not all(isinstance(v, str) and v for v in texts.values()):
        return False
    carried = strings({k: v for k, v in table.items() if k not in ("document", "frame", "instance")})
    return not (set(texts.values()) & carried)


def load(instance: str) -> tuple[dict, dict]:
    """The instance's counting table and wording pack, checked against HF §6 and §5.3."""
    table_file, pack_file = FILES[instance]
    table, pack = read(table_file), read(pack_file)
    assert header_ok(table, "counting_table", instance), f"{table_file}: not {instance}'s counting table"
    assert json_digest(table) == DIGESTS[instance]["table"], f"{table_file}: digest is not the one HF §6 lists"
    assert json_digest(pack) == DIGESTS[instance]["pack"], f"{pack_file}: digest is not the one HF §6 lists"
    assert pack_form(table, pack, instance), f"{pack_file}: not a wording pack under HF §5.3"
    return table, pack


def header(kind: str, instance: str) -> dict:
    """HF §5.1's members of one document."""
    return {"document": kind, "frame": FRAME, "instance": instance}


def not_checked_when_accepted(accepted_statuses: list[dict], order: list[str]) -> list[str]:
    """The properties, in report order, that are ``NOT_CHECKED`` in some accepted case: what the
    vectors show the instance's ``may_be_not_checked`` to be (HF §4.5)."""
    seen = {k for statuses in accepted_statuses for k, v in statuses.items() if v == "NOT_CHECKED"}
    return [k for k in order if k in seen]


def accepted(statuses: dict, may_be_not_checked: list[str]) -> bool:
    """HF §4.5: every property ``PASS``, except that one the instance lists may be ``NOT_CHECKED``."""
    return all(v == "PASS" or (v == "NOT_CHECKED" and k in may_be_not_checked) for k, v in statuses.items())
