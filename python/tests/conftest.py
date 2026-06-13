# SPDX-License-Identifier: BSD-3-Clause
import pytest

from agent_action_capsule import (
    AssuranceBlock,
    Capsule,
    Disposition,
    EffectRecord,
    compute_capsule_id,
)

HEX_A = "a" * 64
HEX_B = "b" * 64


def reseal(d: dict) -> dict:
    """Recompute capsule_id over the mutated dict (capsule_id + chain excluded)."""
    out = dict(d)
    out["capsule_id"] = compute_capsule_id(out)
    return out


def base_executed() -> dict:
    """A valid 'executed' Capsule with a confirmed effect, sealed."""
    return Capsule(
        spec_version="draft-mih-scitt-agent-action-capsule-00",
        format_version="2",
        action_id="act-1",
        action_type="decide",
        operator="ACME-CO",
        developer="agent@v1",
        timestamp="2026-06-13T00:00:00Z",
        effect=EffectRecord(
            status="confirmed",
            type="write_order",
            response_digest=HEX_A,
            irreversibility_class="two_way",
            effect_attestation="gate_executed",
        ),
        assurance=AssuranceBlock(
            attestation_mode="self_attested", effect_mode="confirmed", ledger_mode="standalone"
        ),
        disposition=Disposition(
            decision="accept", approver="human", human_disposed=True, verdict_class="executed"
        ),
    ).seal()


def base_blocked() -> dict:
    """A valid 'blocked' Capsule: no effect, not_applicable, sealed."""
    return Capsule(
        spec_version="draft-mih-scitt-agent-action-capsule-00",
        format_version="2",
        action_id="act-2",
        action_type="decide",
        operator="ACME-CO",
        developer="agent@v1",
        timestamp="2026-06-13T00:00:00Z",
        assurance=AssuranceBlock(
            attestation_mode="self_attested", effect_mode="not_applicable", ledger_mode="standalone"
        ),
        disposition=Disposition(
            decision="reject", approver="policy", human_disposed=False, verdict_class="blocked"
        ),
    ).seal()


@pytest.fixture
def executed():
    return base_executed()


@pytest.fixture
def blocked():
    return base_blocked()
