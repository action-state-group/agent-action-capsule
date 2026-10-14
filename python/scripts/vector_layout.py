# SPDX-License-Identifier: BSD-3-Clause
"""Shared JSON layout helpers for the vector generators.

Released vector files are compared byte for byte, so member order and
indentation are part of what a generator must reproduce. These helpers name
the layouts the released corpus uses.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from agent_action_capsule.canonical import LOCAL_ONLY_FIELDS, jcs


def sort_members(value: Any) -> Any:
    """Return ``value`` with every object's members in sorted order."""
    if isinstance(value, dict):
        return {key: sort_members(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [sort_members(item) for item in value]
    return value


def preimage(capsule: dict) -> str:
    """The Capsule ID preimage: plain JCS without ``capsule_id`` and local-only fields."""
    excluded = {"capsule_id", *LOCAL_ONLY_FIELDS}
    return jcs({key: val for key, val in capsule.items() if key not in excluded}).decode("utf-8")


def ledger_preimages(ledger: list[dict]) -> dict:
    """Name each ledger member's preimage; a one-member ledger uses the bare key."""
    if len(ledger) == 1:
        return {"capsule_id": preimage(ledger[0])}
    return {f"ledger[{index}].capsule_id": preimage(item) for index, item in enumerate(ledger)}


def dumps(value: Any, *, sort_keys: bool = False) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=sort_keys) + "\n"


def hand_dumps(value: dict, expand: Iterable[tuple[str, ...]] = ()) -> str:
    """Render ``value`` in the hand-written layout of the spec-derived cases.

    The root object and each object at a path in ``expand`` get one member
    per line; every other member value stays on its line in compact
    ``json.dumps`` form.
    """
    expanded = {(), *expand}

    def render(item: Any, path: tuple[str, ...], indent: int) -> str:
        if not (isinstance(item, dict) and path in expanded):
            return json.dumps(item, ensure_ascii=False)
        pad = "  " * (indent + 1)
        members = [
            f"{pad}{json.dumps(key, ensure_ascii=False)}: {render(val, (*path, key), indent + 1)}"
            for key, val in item.items()
        ]
        return "{\n" + ",\n".join(members) + "\n" + "  " * indent + "}"

    return render(value, (), 0) + "\n"


def append_cases(manifest_path: Path, entries: list[dict]) -> None:
    """Append manifest entries, replacing an already listed one in place.

    Replacing keeps the released order and lets an edited entry reach the
    manifest instead of leaving it stale.
    """
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    listed = {case["name"]: index for index, case in enumerate(manifest["cases"])}
    for entry in entries:
        if entry["name"] in listed:
            manifest["cases"][listed[entry["name"]]] = entry
        else:
            manifest["cases"].append(entry)
    manifest["count"] = len(manifest["cases"])
    manifest_path.write_text(dumps(manifest), encoding="utf-8")
