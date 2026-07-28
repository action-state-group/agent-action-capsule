#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""GAR-capsule demo — draft-sato-soos-gar-03 §6.2 fields wrapped in an AAC envelope.

Reads sample-gar-block.json (the SAR), computes the SAR digest, builds a
sealed AAC capsule that carries the digest in its extensions block, then
verifies the capsule. Run from the repo root:

    cd python && pip install -e . && python ../examples/gar-capsule/demo.py

Canonicalization (SAR digest):
    digest = SHA-256( JCS( normalize(sar) ) )

Absent-field normalization (§2) DROPS:
    - null members (e.g. acd_session_id when no ACD session is active)
    - empty arrays (hem_events, cap_violations when nothing to report)
    - empty objects (after their own members are dropped)

This rule is LOAD-BEARING for interoperability: SOOS-side implementations
MUST apply the same normalization before calling JCS, or the digest will not
match. Tom's "sorted-key-stringify" produces byte-for-byte identical output
AFTER normalization — i.e., normalize first, then JCS-serialize.
"""
from __future__ import annotations

import hashlib
import json
import pathlib

from agent_action_capsule import verify
from agent_action_capsule.canonical import jcs, normalize

_HERE = pathlib.Path(__file__).parent

# ---------------------------------------------------------------------------
# SAR digest
# ---------------------------------------------------------------------------

def load_sar() -> dict:
    """Load the sample GAR block (SAR) from disk, strip _comment/_draft_basis."""
    raw = json.loads((_HERE / "sample-gar-block.json").read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def sar_digest(sar: dict) -> str:
    """SHA-256 over JCS(normalize(sar)).

    Normalization drops null members and empty containers before JCS is applied.
    SOOS implementations must apply the same normalization step before calling
    JCS, or the digest will not match (absent-field normalization §2).
    """
    return hashlib.sha256(jcs(normalize(sar))).hexdigest()


# ---------------------------------------------------------------------------
# Capsule builder
# ---------------------------------------------------------------------------

def build_gar_capsule(sar: dict) -> dict:
    """Build and seal an AAC capsule wrapping the GAR block's SAR digest."""
    digest = sar_digest(sar)

    # Capsule envelope per draft-mih-scitt-agent-action-capsule §5.1
    capsule: dict = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-03",
        "format_version": "2",
        "_draft_basis": "draft-sato-soos-gar-03",
        "operator": sar.get("so_id", "unknown"),
        "developer": sar.get("agent_id", "unknown"),
        "timestamp": sar["timestamp"],
        "action_id": f"gar-block/{sar['soos.gar.block_id']}",
        "action_type": "decide",
        "assurance": {
            "attestation_mode": "self_attested",
            "effect_mode": "not_applicable",
            "ledger_mode": "standalone",
        },
        "disposition": {
            "decision": "accept",
            "approver": "policy",
            "human_disposed": False,
            "verdict_class": "executed",
        },
        "extensions": {
            "soos.gar": {
                "sar_digest": digest,
            },
        },
    }

    # Seal: compute capsule_id = JSON-DIGEST over capsule minus capsule_id + chain
    from agent_action_capsule.canonical import compute_capsule_id
    capsule["capsule_id"] = compute_capsule_id(capsule)
    return capsule


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sar = load_sar()

    digest = sar_digest(sar)
    print(f"SAR digest:  {digest}")

    # Show what normalization dropped
    sar_norm = normalize(sar)
    dropped = [k for k in sar if k not in sar_norm]
    if dropped:
        print(f"Normalization dropped (null/empty): {dropped}")

    capsule = build_gar_capsule(sar)
    print(f"capsule_id:  {capsule['capsule_id']}")

    result = verify(capsule)
    print(f"verify ok:   {result.ok}")
    for f in result.findings:
        print(f"  [{f.severity}] check {f.check} {f.code}: {f.detail}")

    assert result.ok, "GAR capsule should verify"
    print("GAR capsule demo complete.")
