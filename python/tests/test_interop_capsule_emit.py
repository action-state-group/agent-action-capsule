# SPDX-License-Identifier: BSD-3-Clause
"""Cross-library interop regression: capsule-emit producer -> AAC verifier.

Guards the capsule_id preimage contract across the two libraries. capsule-emit
attaches the COSE_Sign1 producer envelope (``signature``) and its signing
``key_id`` to each ledger line AFTER it computes the capsule_id — so those
fields are excluded from the id's preimage (see capsule-emit
``canonicalization._LOCAL_ONLY_FIELDS`` and AAC ``canonical.LOCAL_ONLY_FIELDS``).

If AAC's ``compute_capsule_id`` excludes only ``capsule_id`` (the pre-0.2.0
bug), it hashes ``signature`` + ``key_id`` into the preimage the producer did
not, so EVERY emitted capsule fails check-2 with ``capsule_id_mismatch``. This
test recomputes the id over a REAL capsule-emit-produced ledger and asserts
every capsule verifies with no mismatch.

The fixture ``fixtures/capsule_emit_ledger.jsonl`` was produced by running
capsule-emit ``seal()`` with ``CAPSULE_WITNESS=off`` (2 independent format-4
capsules + 1 chained "confirms" capsule). It is committed statically so the
test needs no live capsule-emit dependency; regenerate it (same procedure) when
the wire format changes.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_action_capsule.canonical import compute_capsule_id
from agent_action_capsule.verify import verify_store

FIXTURE = Path(__file__).parent / "fixtures" / "capsule_emit_ledger.jsonl"


def _load_ledger() -> list[dict]:
    lines = [ln for ln in FIXTURE.read_text().splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]


def test_fixture_is_real_capsule_emit_output() -> None:
    """Sanity: the fixture carries the producer-envelope fields the bug tripped
    over (signature + key_id) and at least one chained capsule."""
    capsules = _load_ledger()
    assert len(capsules) >= 3
    assert all(c.get("canonicalization_id") == "jcs" for c in capsules)
    assert all("signature" in c and "key_id" in c for c in capsules)
    assert any("chain" in c for c in capsules)


def test_recomputed_capsule_id_matches_producer() -> None:
    """AAC recomputes the SAME capsule_id capsule-emit committed, for every
    capsule including the chained one. RED before the LOCAL_ONLY_FIELDS fix."""
    for capsule in _load_ledger():
        recomputed = compute_capsule_id(dict(capsule))
        assert recomputed == capsule["capsule_id"], (
            f"capsule_id_mismatch: AAC recomputed {recomputed} != producer "
            f"{capsule['capsule_id']} (action_id={capsule.get('action_id')!r})"
        )


def test_verify_store_ok_no_capsule_id_mismatch() -> None:
    """The store verifier reports ok=True and zero capsule_id_mismatch findings
    over the real capsule-emit ledger."""
    capsules = _load_ledger()
    results = verify_store(capsules)
    mismatches = [
        (i, f)
        for i, res in enumerate(results)
        for f in res.findings
        if f.code == "capsule_id_mismatch"
    ]
    assert not mismatches, f"unexpected capsule_id_mismatch findings: {mismatches}"
    not_ok = [(i, res.errors) for i, res in enumerate(results) if not res.ok]
    assert not not_ok, f"capsules failed verify: {not_ok}"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
