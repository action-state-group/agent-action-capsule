# SPDX-License-Identifier: BSD-3-Clause
"""Sealed test Capsules built on :meth:`Capsule.seal`, the package's public
sealing boundary.

AAC's tests verify; they do not exercise a producer. ``sealed()`` only fills
the format-4 fields every Capsule carries, so a test states the fields it
cares about and nothing else. It deliberately applies no producer policy (no
default disposition, no generated ``action_id``, no ``effect_attestation``
rewriting): a test that needs one of those passes it explicitly.
"""
from __future__ import annotations

import dataclasses
from typing import Any

from agent_action_capsule import AssuranceBlock, Capsule, derive_effect_mode
from agent_action_capsule.versions import DEFAULT_FORMAT_VERSION, DEFAULT_SPEC_VERSION

TIMESTAMP = "2026-06-13T00:00:00Z"

_DEFAULTS: dict[str, Any] = {
    "spec_version": DEFAULT_SPEC_VERSION,
    "format_version": DEFAULT_FORMAT_VERSION,
    "canonicalization_id": "jcs",
    "action_id": "act-1",
    "action_type": "decide",
    "operator": "OP",
    "developer": "DEV",
    "timestamp": TIMESTAMP,
}


def sealed(**fields: Any) -> dict:
    """Seal a format-4 Capsule from ``fields`` over test defaults.

    ``assurance`` defaults to a self-attested block whose ``effect_mode`` and
    ``ledger_mode`` agree with the supplied ``effect`` and ``chain``, the
    consistency a verifier checks; pass ``assurance=None`` to omit the block.
    """
    values = {**_DEFAULTS, **fields}
    if "assurance" not in fields:
        effect = values.get("effect")
        values["assurance"] = AssuranceBlock(
            attestation_mode="self_attested",
            effect_mode=derive_effect_mode(dataclasses.asdict(effect) if effect is not None else None),
            ledger_mode="chained" if values.get("chain") is not None else "standalone",
        )
    return Capsule(**values).seal()
