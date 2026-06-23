# SPDX-License-Identifier: BSD-3-Clause
"""Typed producer-side carriers and structural constants.

The carriers here are the *producer* path: their constructors enforce the
invariants the spec states a producer MUST NOT violate, so a non-conforming
Capsule cannot be built or signed (§5.4 disposition honesty + closed approver
enum; §5.2 the confirmed-effect binding and the status/digest table). The
*consumer* path is the verifier (verify.py), which never raises and instead
reports findings over arbitrary bytes.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "HEX64",
    "is_hex64",
    "EFFECT_STATUSES",
    "NEVER_DISPATCH_VERDICT_CLASSES",
    "VALID_APPROVERS",
    "ATTESTATION_MODES",
    "EFFECT_MODES",
    "LEDGER_MODES",
    "LEDGER_MODE_RANK",
    "DOMAIN_VALUES",
    "PROVENANCE_VALUES",
    "PROVENANCE_RANK",
    "derive_effect_mode",
    "Disposition",
    "ExpiryPolicy",
    "EffectRecord",
    "AssuranceBlock",
    "Chain",
    "ConstraintRecord",
    "ModelAttestation",
    "SelfReportedReasoning",
    "InvariantError",
]

HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


def is_hex64(v: Any) -> bool:
    return isinstance(v, str) and bool(HEX64.match(v))


# Effect Record reserved statuses (§5.2).
EFFECT_STATUSES = frozenset({"planned", "dispatched", "confirmed", "failed", "reverted"})

# verdict_class values that by their kind never dispatch an effect (§5.4.2): each
# REQUIRES the derived effect_mode to be "not_applicable". `resolved` is in the
# set (the non-executing closure, per the pairing rule). timeout / errored /
# executed are deliberately NOT in the set.
NEVER_DISPATCH_VERDICT_CLASSES = frozenset(
    {
        "blocked",
        "hitl_dispatched",
        "denied",
        "engine_failure",
        "deferred",
        "needs_decision",
        "expired",
        "escalated",
        "resolved",
    }
)

# disposition.approver is a closed enum (§5.4), not registry-governed.
VALID_APPROVERS = frozenset({"human", "policy"})

# assurance closed enums (§5.3).
ATTESTATION_MODES = frozenset({"self_attested", "anchored"})
EFFECT_MODES = frozenset({"not_applicable", "dispatched_unconfirmed", "confirmed"})
LEDGER_MODES = frozenset({"standalone", "chained", "anchored"})
LEDGER_MODE_RANK = {"standalone": 0, "chained": 1, "anchored": 2}

# §-02 domain and provenance registry seeds (REGISTRY.md §8/§9).
# domain: the capsule's epistemic role — "action" (default), "memory", or "reasoning".
# provenance: dedup rank signal — "gate"(3) > "runtime"(2) > "collector"(1).
# Both are open/registry-governed; unknown values are informational, never rejected.
DOMAIN_VALUES = frozenset({"action", "memory", "reasoning"})
PROVENANCE_VALUES = frozenset({"gate", "runtime", "collector"})
PROVENANCE_RANK = {"gate": 3, "runtime": 2, "collector": 1}

# Open-items predicate verdict_class set (§5.4.4).
OPEN_ITEM_VERDICT_CLASSES = frozenset(
    {"deferred", "needs_decision", "hitl_dispatched", "escalated", "blocked"}
)


class InvariantError(ValueError):
    """A producer-side invariant the spec states a Producer MUST NOT violate."""


def derive_effect_mode(effect: Mapping[str, Any] | None) -> str:
    """Derive ``assurance.effect_mode`` from the Effect Record (§5.2).

    - no Effect Record / status "planned" -> "not_applicable"
      (planned asserts no execution; the planned carve);
    - status "confirmed" with a well-formed response_digest -> "confirmed";
      "confirmed" WITHOUT one demotes to "dispatched_unconfirmed" (the
      confirmed-effect binding failed — check 3 reports it as an error);
    - status "dispatched" / "failed" / "reverted" -> "dispatched_unconfirmed";
    - missing or unknown status -> "dispatched_unconfirmed" (never "confirmed").
    """
    if effect is None:
        return "not_applicable"
    status = effect.get("status")
    if status == "planned":
        return "not_applicable"
    if status == "confirmed":
        return "confirmed" if is_hex64(effect.get("response_digest")) else "dispatched_unconfirmed"
    # dispatched / failed / reverted / missing / unknown
    return "dispatched_unconfirmed"


@dataclass(frozen=True)
class ExpiryPolicy:
    """§5.4 expiry_policy (deferral dispositions only)."""

    ttl_seconds: int
    on_expiry: str

    def __post_init__(self) -> None:
        # "integer count of seconds, never a duration string" (§5.4). bool is an
        # int subclass but is not a count of seconds.
        if isinstance(self.ttl_seconds, bool) or not isinstance(self.ttl_seconds, int):
            raise InvariantError("expiry_policy.ttl_seconds MUST be an integer (§5.4)")
        if self.on_expiry not in ("expired", "escalated"):
            raise InvariantError("expiry_policy.on_expiry MUST be 'expired' or 'escalated' (§5.4)")


@dataclass(frozen=True)
class Disposition:
    """§5.4 disposition block. The honesty invariant and the closed approver enum
    are enforced here so a violating Capsule cannot be constructed."""

    decision: str
    approver: str
    human_disposed: bool = False
    authority: str | None = None
    verdict_class: str | None = None
    reason_digest: str | None = None
    expiry_policy: ExpiryPolicy | None = None

    def __post_init__(self) -> None:
        # decision is REQUIRED (§5.4) — a non-empty string. Defense-in-depth so a
        # directly-constructed Disposition(decision=None) also fails, not only the
        # strict parse path. (Registry-governed value; not enum-checked here.)
        if not isinstance(self.decision, str) or not self.decision:
            raise InvariantError("disposition.decision is REQUIRED and a non-empty string (§5.4)")
        # Closed approver enum (§5.4): an unknown approver value is not a
        # conforming Capsule.
        if self.approver not in VALID_APPROVERS:
            raise InvariantError(
                f"disposition.approver MUST be one of {sorted(VALID_APPROVERS)} "
                f"(§5.4); got {self.approver!r}"
            )
        # Honesty invariant (§5.4): human_disposed=true REQUIRES approver "human".
        if self.human_disposed and self.approver != "human":
            raise InvariantError(
                "human_disposed=true REQUIRES approver='human' (§5.4); a producer "
                f"MUST NOT claim a human disposed what a {self.approver!r} did"
            )
        if self.reason_digest is not None and not is_hex64(self.reason_digest):
            raise InvariantError("disposition.reason_digest MUST be a 64-hex JSON-DIGEST (§5.4)")


@dataclass(frozen=True)
class EffectRecord:
    """§5.2 Effect Record. The confirmed-effect binding and the status/digest
    table are enforced at construction."""

    status: str
    type: str | None = None
    request_digest: str | None = None
    response_digest: str | None = None
    external_ref: str | None = None
    irreversibility_class: str | None = None
    effect_attestation: str | None = None

    def __post_init__(self) -> None:
        # status is REQUIRED (§5.2) — a non-empty string. Defense-in-depth so a
        # directly-constructed EffectRecord(status=None) fails with a structured
        # InvariantError rather than a downstream error. (Reserved-but-extensible
        # value; not enum-checked here — an unknown status is informational.)
        if not isinstance(self.status, str) or not self.status:
            raise InvariantError("effect.status is REQUIRED and a non-empty string (§5.2)")
        # The confirmed-effect invariant (§5.2): MUST NOT emit confirmed without a
        # well-formed response_digest over the observed response.
        if self.status == "confirmed" and not is_hex64(self.response_digest):
            raise InvariantError(
                "effect.status 'confirmed' REQUIRES a 64-hex response_digest over "
                "the observed response (§5.2 confirmed-effect invariant)"
            )
        # Status/digest table (§5.2).
        if self.status == "planned" and (
            self.request_digest is not None or self.response_digest is not None
        ):
            raise InvariantError(
                "effect.status 'planned': request_digest and response_digest MUST "
                "be absent (§5.2)"
            )
        if self.status == "dispatched" and self.response_digest is not None:
            raise InvariantError(
                "effect.status 'dispatched': response_digest MUST be absent (§5.2)"
            )
        for name in ("request_digest", "response_digest"):
            v = getattr(self, name)
            if v is not None and not is_hex64(v):
                raise InvariantError(f"effect.{name} MUST be a 64-hex JSON-DIGEST when present")


@dataclass(frozen=True)
class AssuranceBlock:
    """§5.3 assurance object — three closed-enum modes."""

    attestation_mode: str
    effect_mode: str
    ledger_mode: str

    def __post_init__(self) -> None:
        if self.attestation_mode not in ATTESTATION_MODES:
            raise InvariantError("assurance.attestation_mode invalid (§5.3)")
        if self.effect_mode not in EFFECT_MODES:
            raise InvariantError("assurance.effect_mode invalid (§5.3)")
        if self.ledger_mode not in LEDGER_MODES:
            raise InvariantError("assurance.ledger_mode invalid (§5.3)")


@dataclass(frozen=True)
class Chain:
    """§5.4.4 chain block {parent_capsule_id, relation}. relation is
    registry-governed; an unknown value is informational (not rejected), so it is
    NOT enum-checked here."""

    parent_capsule_id: str
    relation: str

    def __post_init__(self) -> None:
        if not is_hex64(self.parent_capsule_id):
            raise InvariantError("chain.parent_capsule_id MUST be a 64-hex capsule_id (§5.1, §5.4.4)")
        if not isinstance(self.relation, str) or not self.relation:
            raise InvariantError("chain.relation MUST be a non-empty string")


@dataclass(frozen=True)
class ConstraintRecord:
    """§8.1 Constraint Record — the public verdict of one deterministic check.
    Represented as data only; manifest-aware checking is Class 2 (out of scope)."""

    id: str
    result: str
    severity: str | None = None
    blocking: bool | None = None
    check_type: str | None = None
    method: str | None = None
    evidence_digest: str | None = None

    def __post_init__(self) -> None:
        if self.result not in ("pass", "fail", "n/a"):
            raise InvariantError("constraint.result MUST be 'pass', 'fail', or 'n/a' (§8.1)")
        if self.evidence_digest is not None and not is_hex64(self.evidence_digest):
            raise InvariantError("constraint.evidence_digest MUST be a 64-hex JSON-DIGEST when present")


@dataclass(frozen=True)
class ModelAttestation:
    """Model identity and compute-context block — committed to capsule_id.

    All fields enter the canonical capsule form and therefore the capsule_id
    digest. model_id and provider are optional: a compute-only block (no model
    identity) is valid for producers that cannot name the model but still want
    to commit I/O digests. When present, model_id and provider MUST appear
    together (both or neither).

    compute_attestation is best-effort from inference metadata:
    {"agent_input_digest": "...", "agent_output_digest": "...", "runtime": "..."}.
    Absent when the runtime does not surface this information.
    """

    model_id: str | None = None
    provider: str | None = None
    compute_attestation: dict | None = None

    def __post_init__(self) -> None:
        # model_id and provider MUST appear together when either is given.
        if (self.model_id is None) != (self.provider is None):
            raise InvariantError(
                "model_attestation.model_id and .provider MUST both be present "
                "or both absent — supply both or neither"
            )
        if self.model_id is not None and (not isinstance(self.model_id, str) or not self.model_id):
            raise InvariantError("model_attestation.model_id MUST be a non-empty string")
        if self.provider is not None and (not isinstance(self.provider, str) or not self.provider):
            raise InvariantError("model_attestation.provider MUST be a non-empty string")
        if self.compute_attestation is not None and not isinstance(self.compute_attestation, dict):
            raise InvariantError("model_attestation.compute_attestation MUST be an object when present")


@dataclass(frozen=True)
class SelfReportedReasoning:
    """Self-reported reasoning trace — §-02 first-class layer.

    A digest of the CoT or reasoning content that produced this action.
    Explicitly self-reported and unattested: the producer asserts the digest,
    and CoT faithfulness is not verifiable (models are known to produce
    unfaithful CoT). Distinct from disposition.reason_digest (the gate's
    verdict rationale) and from domain='reasoning' (a standalone reasoning
    capsule rather than an action capsule).

    Committed to capsule_id so any post-seal tamper is detectable.
    """

    digest: str

    def __post_init__(self) -> None:
        if not is_hex64(self.digest):
            raise InvariantError("self_reported_reasoning.digest MUST be a 64-hex JSON-DIGEST (§-02)")
