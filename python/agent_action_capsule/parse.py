# SPDX-License-Identifier: BSD-3-Clause
"""Producer/typed path: build and seal a Capsule, or strictly parse one.

``Capsule.seal()`` computes ``capsule_id`` per §5.1 (the JSON-DIGEST of the
canonical capsule form). ``parse_capsule`` builds the typed carriers from a dict
and therefore RAISES (InvariantError) on a non-conforming Capsule — the strict
producer/round-trip path, as distinct from ``verify()`` which never raises.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields
from typing import Any

from .canonical import compute_capsule_id
from .contracts import (
    AssuranceBlock,
    Chain,
    ConstraintRecord,
    Disposition,
    EffectRecord,
    ExpiryPolicy,
    InvariantError,
)

__all__ = ["Capsule", "parse_capsule"]


def _block_to_dict(obj: Any) -> dict:
    """Dataclass -> dict, dropping members whose value is None."""
    out: dict[str, Any] = {}
    for f in fields(obj):
        v = getattr(obj, f.name)
        if v is None:
            continue
        if isinstance(v, ExpiryPolicy):
            v = _block_to_dict(v)
        out[f.name] = v
    return out


@dataclass(frozen=True)
class Capsule:
    """The Agent Action Capsule envelope (§5.1) plus its typed sub-blocks."""

    spec_version: str
    format_version: str
    action_id: str
    action_type: str
    operator: str
    developer: str
    timestamp: str
    effect: EffectRecord | None = None
    assurance: AssuranceBlock | None = None
    disposition: Disposition | None = None
    chain: Chain | None = None
    constraints: tuple[ConstraintRecord, ...] = ()

    def to_dict(self) -> dict:
        """The envelope as a JSON object (without capsule_id)."""
        out: dict[str, Any] = {
            "spec_version": self.spec_version,
            "format_version": self.format_version,
            "action_id": self.action_id,
            "action_type": self.action_type,
            "operator": self.operator,
            "developer": self.developer,
            "timestamp": self.timestamp,
        }
        if self.effect is not None:
            out["effect"] = _block_to_dict(self.effect)
        if self.assurance is not None:
            out["assurance"] = _block_to_dict(self.assurance)
        if self.disposition is not None:
            out["disposition"] = _block_to_dict(self.disposition)
        if self.constraints:
            out["constraints"] = [_block_to_dict(c) for c in self.constraints]
        if self.chain is not None:
            out["chain"] = _block_to_dict(self.chain)
        return out

    def seal(self) -> dict:
        """Return the full Capsule dict with ``capsule_id`` computed over the
        canonical capsule form (§5.1)."""
        body = self.to_dict()
        cid = compute_capsule_id(body)
        # capsule_id is excluded from its own digest; place it on the sealed dict.
        sealed = {"spec_version": body["spec_version"], "format_version": body["format_version"], "capsule_id": cid}
        for k, v in body.items():
            if k not in sealed:
                sealed[k] = v
        return sealed


def _opt(d: Mapping[str, Any], key: str):
    v = d.get(key)
    return v if isinstance(v, Mapping) else None


def parse_capsule(d: Mapping[str, Any]) -> Capsule:
    """Strictly build typed carriers from a Capsule dict. Raises InvariantError on
    a non-conforming Capsule (the producer/round-trip path)."""
    if not isinstance(d, Mapping):
        raise InvariantError("Capsule must be a JSON object")
    for fld in ("spec_version", "format_version", "action_id", "action_type", "operator", "developer", "timestamp"):
        if not isinstance(d.get(fld), str):
            raise InvariantError(f"{fld} is REQUIRED and MUST be a string (§5.1)")

    eff = _opt(d, "effect")
    effect = EffectRecord(**{k: eff.get(k) for k in (
        "status", "type", "request_digest", "response_digest", "external_ref",
        "irreversibility_class", "effect_attestation") if k in eff}) if eff else None

    asr = _opt(d, "assurance")
    assurance = AssuranceBlock(
        attestation_mode=asr.get("attestation_mode"),
        effect_mode=asr.get("effect_mode"),
        ledger_mode=asr.get("ledger_mode"),
    ) if asr else None

    dis = _opt(d, "disposition")
    disposition = None
    if dis:
        ep = dis.get("expiry_policy")
        expiry = ExpiryPolicy(ttl_seconds=ep.get("ttl_seconds"), on_expiry=ep.get("on_expiry")) if isinstance(ep, Mapping) else None
        disposition = Disposition(
            decision=dis.get("decision"),
            approver=dis.get("approver"),
            human_disposed=bool(dis.get("human_disposed", False)),
            authority=dis.get("authority"),
            verdict_class=dis.get("verdict_class"),
            reason_digest=dis.get("reason_digest"),
            expiry_policy=expiry,
        )

    chn = _opt(d, "chain")
    chain = Chain(parent_capsule_id=chn.get("parent_capsule_id"), relation=chn.get("relation")) if chn else None

    cons = d.get("constraints")
    constraints: tuple[ConstraintRecord, ...] = ()
    if isinstance(cons, list):
        constraints = tuple(
            ConstraintRecord(**{k: c.get(k) for k in (
                "id", "result", "severity", "blocking", "check_type", "method", "evidence_digest") if k in c})
            for c in cons if isinstance(c, Mapping)
        )

    return Capsule(
        spec_version=d["spec_version"], format_version=d["format_version"],
        action_id=d["action_id"], action_type=d["action_type"], operator=d["operator"],
        developer=d["developer"], timestamp=d["timestamp"],
        effect=effect, assurance=assurance, disposition=disposition, chain=chain,
        constraints=constraints,
    )
