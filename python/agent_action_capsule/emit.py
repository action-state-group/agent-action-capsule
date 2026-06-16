# SPDX-License-Identifier: BSD-3-Clause
"""Rung 1 — emit: sealed-Capsule builder with self-attestation.

``emit()`` is the single-call path from "an AI action just occurred" to a
sealed, verifiable Agent Action Capsule. It handles:

- Building the ``model_attestation`` block when ``model_id`` / ``provider``
  are supplied (commits them to the ``capsule_id`` digest so tampering any of
  the three fields makes verification fail).
- Deriving ``assurance.effect_mode`` from the effect record status.
- Wiring the ``chain`` block when a prior capsule id is supplied (rung 2
  chaining primitive).
- Defaulting ``assurance.attestation_mode`` to ``"self_attested"`` (§5.3).
- Returning the sealed dict ready for storage, anchoring, or forwarding.

**action_type convention**:
- ``"fyi"`` — passive observation (default); the emit tier records what
  happened but does not gate or decide. Framework adapters use this.
- ``"decide"`` — consequential; the capsule records a gate decision or tool
  call with real-world effects. Pass explicitly when emitting consequential
  actions.
"""
from __future__ import annotations

import dataclasses
import uuid
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

__all__ = [
    "emit",
    "DEFAULT_SPEC_VERSION",
    "DEFAULT_FORMAT_VERSION",
    # Aliases for backward-compat with the emit-tier adapter surface.
    "SPEC_VERSION",
    "FORMAT_VERSION",
]

DEFAULT_SPEC_VERSION = "draft-mih-scitt-agent-action-capsule-01"
DEFAULT_FORMAT_VERSION = "2"

# Aliases used by the adapter tier (framework adapters import these names).
SPEC_VERSION = DEFAULT_SPEC_VERSION
FORMAT_VERSION = DEFAULT_FORMAT_VERSION


def _utc_now() -> str:
    now = datetime.now(timezone.utc)
    return now.isoformat().replace("+00:00", "Z")


def emit(
    action_id: str | None = None,
    action_type: str = "fyi",
    operator: str = "",
    developer: str = "",
    *,
    model_id: str | None = None,
    provider: str | None = None,
    timestamp: str | None = None,
    compute_attestation: dict[str, Any] | None = None,
    effect: EffectRecord | None = None,
    prior_capsule_id: str | None = None,
    chain_relation: str = "follows",
    disposition: Disposition | None = None,
    constraints: tuple[ConstraintRecord, ...] = (),
    spec_version: str = DEFAULT_SPEC_VERSION,
    format_version: str = DEFAULT_FORMAT_VERSION,
    # Adapter-tier convenience params: used to build action_id when not given.
    tool_name: str | None = None,
    tool_input: Any = None,  # noqa: ARG001 — carried for future traceability
    tool_output: Any = None,  # noqa: ARG001 — carried for future traceability
) -> dict:
    """Build and seal a Capsule with self-attestation (§5.3).

    Returns the sealed dict with ``capsule_id`` computed over the canonical
    capsule form (§5.1). When ``model_id`` and ``provider`` are supplied, the
    ``model_attestation`` block is included and committed to the ``capsule_id``;
    any post-seal tamper to those fields makes ``verify()`` fail.

    Args:
        action_id: Unique identifier for this action. Defaults to a UUID4
            incorporating ``tool_name`` when not supplied.
        action_type: Action category. ``"fyi"`` (default) for passive
            observation; ``"decide"`` for consequential gate decisions.
        operator: The tenant / scoping party identifier (spec §5.1).
        developer: The agent identifier + version (spec §5.1).
        model_id: Model name/version, e.g. ``"claude-sonnet-4-6"``. When
            supplied together with ``provider``, a ``model_attestation`` block
            is created and committed to the ``capsule_id``.
        provider: Inference provider, e.g. ``"anthropic"``.
        timestamp: ISO-8601 / RFC 3339 UTC string; defaults to now.
        compute_attestation: Best-effort compute context. Committed to
            ``capsule_id`` when ``model_id`` + ``provider`` are also present.
        effect: Optional effect record (rung 2 may/did binding).
        prior_capsule_id: 64-hex capsule_id of the capsule this one follows.
        chain_relation: Registry-governed chain.relation value (default
            ``"follows"``). Ignored when ``prior_capsule_id`` is None.
        disposition: Optional disposition block (§5.4). When omitted on an
            ``"fyi"`` action a sensible default is applied automatically.
        constraints: Constraint records (§8.1); defaults to empty tuple.
        spec_version: Spec revision string (defaults to ``-01``).
        format_version: Serialization suite version (defaults to ``"2"``).
        tool_name: Name of the tool that was called. Used to build a readable
            ``action_id`` when one is not provided.
        tool_input: Tool input (currently ignored in the capsule body; reserved
            for future traceability fields).
        tool_output: Tool output (currently ignored in the capsule body; reserved
            for future traceability fields).

    Returns:
        Sealed capsule dict with ``capsule_id`` at the top level.
    """
    # Derive action_id from tool_name if not supplied.
    if action_id is None:
        base = tool_name or "tool-call"
        action_id = f"{base}/{uuid.uuid4()}"

    ts = timestamp or _utc_now()

    # ModelAttestation only when both model_id + provider are given.
    model_att: ModelAttestation | None = None
    if model_id is not None and provider is not None:
        model_att = ModelAttestation(
            model_id=model_id,
            provider=provider,
            compute_attestation=compute_attestation,
        )

    chain: Chain | None = None
    if prior_capsule_id is not None:
        # Adapter-tier chains use "sequence"; full-API chains use "follows" or explicit.
        # Preserve whatever chain_relation was passed; default is "follows".
        chain = Chain(parent_capsule_id=prior_capsule_id, relation=chain_relation)

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

    # Default disposition for fyi/observer calls: accept, policy-approved, executed.
    if disposition is None and action_type == "fyi":
        disposition = Disposition(
            decision="accept",
            approver="policy",
            human_disposed=False,
            verdict_class="executed",
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
