# SPDX-License-Identifier: BSD-3-Clause
"""Rung 1 — emit: high-level sealed-Capsule builder with self-attestation.

``emit()`` is the single-call path from "I just ran an AI action" to a sealed,
verifiable Agent Action Capsule. It handles:

- Building the ``model_attestation`` block (commits model_id, provider, and
  compute_attestation to the capsule_id digest so tampering any of the three
  makes verification fail).
- Deriving ``assurance.effect_mode`` from the effect record status.
- Wiring the ``chain`` block when a prior capsule id is supplied (rung 2
  chaining primitive).
- Defaulting ``assurance.attestation_mode`` to ``"self_attested"`` (§5.3).
- Returning the sealed dict ready for storage, anchoring, or forwarding.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Any

from .contracts import (
    AssuranceBlock,
    Chain,
    ConstraintRecord,
    Disposition,
    EffectRecord,
    ModelAttestation,
    derive_effect_mode,
)
from .parse import Capsule

__all__ = ["emit", "DEFAULT_SPEC_VERSION", "DEFAULT_FORMAT_VERSION"]

DEFAULT_SPEC_VERSION = "draft-mih-scitt-agent-action-capsule-01"
DEFAULT_FORMAT_VERSION = "2"


def _utc_now() -> str:
    """RFC 3339 UTC timestamp with a Z suffix."""
    now = datetime.now(timezone.utc)
    return now.isoformat().replace("+00:00", "Z")


def emit(
    action_id: str,
    action_type: str,
    operator: str,
    developer: str,
    *,
    model_id: str,
    provider: str,
    timestamp: str | None = None,
    compute_attestation: dict[str, Any] | None = None,
    effect: EffectRecord | None = None,
    prior_capsule_id: str | None = None,
    chain_relation: str = "follows",
    disposition: Disposition | None = None,
    constraints: tuple[ConstraintRecord, ...] = (),
    spec_version: str = DEFAULT_SPEC_VERSION,
    format_version: str = DEFAULT_FORMAT_VERSION,
) -> dict:
    """Build and seal a Capsule with self-attestation (§5.3).

    Returns the sealed dict with ``capsule_id`` computed over the canonical
    capsule form (§5.1). The ``model_attestation`` block — carrying
    ``model_id``, ``provider``, and ``compute_attestation`` — is part of the
    canonical form, so the ``capsule_id`` commits all three values: any
    post-seal tamper to these fields makes ``verify()`` fail.

    Args:
        action_id: Unique identifier for this action (spec §5.1 REQUIRED).
        action_type: Action category string, e.g. ``"decide"`` (spec §5.1 REQUIRED).
        operator: The tenant / scoping party identifier (spec §5.1 REQUIRED).
        developer: The agent identifier + version (spec §5.1 REQUIRED).
        model_id: The model name/version that ran this action, e.g.
            ``"claude-sonnet-4-6"`` (committed to capsule_id).
        provider: Inference provider, e.g. ``"anthropic"`` (committed to capsule_id).
        timestamp: ISO-8601 / RFC 3339 UTC string; defaults to now.
        compute_attestation: Best-effort compute context from inference metadata.
            Typically ``{"endpoint": "<url>", "chip": "<accelerator-id>"}``.
            Committed to capsule_id when present.
        effect: Optional effect record (rung 2 may/did binding). When status is
            ``"dispatched"`` the assurance effect_mode is
            ``"dispatched_unconfirmed"``; when ``"confirmed"`` it is
            ``"confirmed"`` (and response_digest is required by EffectRecord).
        prior_capsule_id: 64-hex capsule_id of the capsule this one follows.
            When supplied the chain block is set (rung 2 chaining primitive)
            and ledger_mode becomes ``"chained"``.
        chain_relation: Registry-governed chain.relation value (default
            ``"follows"``). Ignored when prior_capsule_id is None.
        disposition: Optional disposition block (§5.4).
        constraints: Constraint records (§8.1); defaults to empty tuple.
        spec_version: Spec revision string (defaults to ``-01``).
        format_version: Serialization suite version (defaults to ``"2"``).

    Returns:
        Sealed capsule dict with ``capsule_id`` at the top level.
    """
    ts = timestamp or _utc_now()

    model_att = ModelAttestation(
        model_id=model_id,
        provider=provider,
        compute_attestation=compute_attestation,
    )

    chain: Chain | None = None
    if prior_capsule_id is not None:
        chain = Chain(parent_capsule_id=prior_capsule_id, relation=chain_relation)

    # Ensure effect_attestation is set when the effect has been dispatched or
    # confirmed (§5.2 requires it; the verifier grades it). Default to
    # "runtime_claimed" — the weakest registered grade — which is appropriate
    # for self-attested capsules where the issuer asserts completion but no
    # independent witness confirms it. Callers that can grade higher should
    # set effect_attestation on the EffectRecord directly.
    if effect is not None and effect.effect_attestation is None:
        status = effect.status
        if status in ("dispatched", "confirmed", "failed", "reverted"):
            effect = dataclasses.replace(effect, effect_attestation="runtime_claimed")

    effect_dict = dataclasses.asdict(effect) if effect is not None else None
    effect_mode = derive_effect_mode(effect_dict)
    ledger_mode = "chained" if chain is not None else "standalone"

    assurance = AssuranceBlock(
        attestation_mode="self_attested",
        effect_mode=effect_mode,
        ledger_mode=ledger_mode,
    )

    capsule = Capsule(
        spec_version=spec_version,
        format_version=format_version,
        action_id=action_id,
        action_type=action_type,
        operator=operator,
        developer=developer,
        timestamp=ts,
        model_attestation=model_att,
        effect=effect,
        assurance=assurance,
        disposition=disposition,
        chain=chain,
        constraints=constraints,
    )
    return capsule.seal()
