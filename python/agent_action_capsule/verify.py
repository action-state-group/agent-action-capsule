# SPDX-License-Identifier: BSD-3-Clause
"""Class 1 verifier (§6).

A verifier validates a Capsule from its own bytes without trusting the producer.
It MUST return a structured result and never throw (§6); a single ``ok`` boolean
gates trust in every other reported field; findings are reported in a fixed
order. Unknown registry values are informational and never a rejection (§4, §12).

This is the Class 1 surface only. Substrate verification (the COSE_Sign1
signature, registration, the Receipt's inclusion proof) is the SCITT/COSE
substrate's, by reference (§6) and is not performed here; consequently this
payload verifier never derives ``anchored`` and reports a claimed ``anchored``
mode as an unverifiable overclaim (§5.3, §registration). Class 2 / manifest-aware
verification (§8.2) is out of scope.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .canonical import FloatInDigestError, compute_capsule_id
from .contracts import (
    LEDGER_MODE_RANK,
    NEVER_DISPATCH_VERDICT_CLASSES,
    VALID_APPROVERS,
    derive_effect_mode,
    is_hex64,
)
from .registries import load_registries

__all__ = ["Finding", "VerificationResult", "verify", "verify_store"]

REQUIRED_FIELDS = (
    "spec_version",
    "format_version",
    "capsule_id",
    "action_id",
    "action_type",
    "operator",
    "developer",
    "timestamp",
)

# effect_mode ordering for overclaim detection (§5.3): "confirmed" is the only
# upgrade; not_applicable and dispatched_unconfirmed are not ordered above one
# another (a never-dispatch verdict needs not_applicable; that is check 4, not an
# overclaim).
_EFFECT_MODE_RANK = {"not_applicable": 0, "dispatched_unconfirmed": 0, "confirmed": 1}
_ATTESTATION_RANK = {"self_attested": 0, "anchored": 1}

# Which capsule field maps to which registry, for the unknown-value check (§6 #8).
_REGISTRY_FIELDS = (
    ("verdict_class", ("disposition", "verdict_class")),
    ("disposition.decision", ("disposition", "decision")),
    ("effect.type", ("effect", "type")),
    ("irreversibility_class", ("effect", "irreversibility_class")),
    ("effect_attestation", ("effect", "effect_attestation")),
    ("chain.relation", ("chain", "relation")),
)


@dataclass(frozen=True)
class Finding:
    """One structured verification finding.

    ``severity``: 'error' gates ``ok``; 'warning' is a non-gating defensive flag
    (e.g. the disposition-honesty assert of §6, which is structurally guaranteed
    at construction and is NOT a live gating check); 'info' is advisory.
    ``check``: the §6 Class-1 check number (1..8) the finding belongs to, or None
    for the defensive/structural-pre-checks that are not in the §6 enumeration.
    """

    code: str
    detail: str
    severity: str = "error"
    check: int | None = None

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"[{self.severity}] check {self.check} {self.code}: {self.detail}"


@dataclass
class VerificationResult:
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    assurance: dict[str, Any] = field(default_factory=dict)
    capsule_id: str | None = None

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "error"]


def _obj(capsule: Mapping[str, Any], key: str) -> Mapping[str, Any] | None:
    v = capsule.get(key)
    return v if isinstance(v, Mapping) else None


def _float_paths(v: Any, path: str = "") -> list[str]:
    out: list[str] = []
    if isinstance(v, bool):
        return out
    if isinstance(v, float):
        return [path or "<root>"]
    if isinstance(v, Mapping):
        for k, val in v.items():
            out += _float_paths(val, f"{path}.{k}" if path else str(k))
    elif isinstance(v, (list, tuple)):
        for i, val in enumerate(v):
            out += _float_paths(val, f"{path}[{i}]")
    return out


def _store_ids(store: Iterable[Any] | None) -> set[str] | None:
    if store is None:
        return None
    ids: set[str] = set()
    for item in store:
        if isinstance(item, Mapping):
            cid = item.get("capsule_id")
            if isinstance(cid, str):
                ids.add(cid)
        elif isinstance(item, str):
            ids.add(item)
    return ids


def verify(
    capsule: Any,
    *,
    store: Iterable[Any] | None = None,
    registries: Mapping[str, frozenset] | None = None,
) -> VerificationResult:
    """Run Class 1 verification (§6) over a single Capsule. Never raises."""
    findings: list[Finding] = []
    try:
        return _verify(capsule, findings, store, registries)
    except Exception as exc:  # never throw (§6)
        findings.append(Finding("verifier_internal_error", repr(exc)))
        return VerificationResult(ok=False, findings=findings)


def _verify(capsule, findings, store, registries) -> VerificationResult:
    if registries is None:
        registries = load_registries()

    if not isinstance(capsule, Mapping):
        findings.append(Finding("not_an_object", "Capsule is not a JSON object", check=1))
        return VerificationResult(ok=False, findings=findings)

    effect = _obj(capsule, "effect")
    disposition = _obj(capsule, "disposition")
    chain = _obj(capsule, "chain")

    # ---- Check 1: Structural ------------------------------------------------
    for fld in REQUIRED_FIELDS:
        if fld not in capsule:
            findings.append(Finding("missing_required_field", f"{fld} is REQUIRED (§5.1)", check=1))
        elif not isinstance(capsule[fld], str):
            findings.append(Finding("field_not_string", f"{fld} MUST be a string (§5.1)", check=1))
    cid = capsule.get("capsule_id")
    if cid is not None and not is_hex64(cid):
        findings.append(Finding("capsule_id_malformed", "capsule_id MUST be 64 lowercase hex (§5.1)", check=1))
    at = capsule.get("action_type")
    if at is not None and at not in ("fyi", "decide"):
        findings.append(Finding("action_type_invalid", "action_type MUST be 'fyi' or 'decide' (§5.1)", check=1))
    for fld in ("effect", "assurance", "disposition", "chain"):
        if fld in capsule and not isinstance(capsule[fld], Mapping):
            findings.append(Finding("block_not_object", f"{fld} MUST be a JSON object when present", check=1))
    if "constraints" in capsule and not isinstance(capsule["constraints"], list):
        findings.append(Finding("constraints_not_array", "constraints MUST be an array when present (§8.1)", check=1))
    for p in _float_paths(capsule):
        findings.append(Finding("float_in_digest_field", f"floating-point value at {p}; §5.1 forbids it", check=1))

    # Structural approver enum (check 1) + the defensive disposition-honesty
    # assert (§6). Honesty is structurally guaranteed at construction and is NOT
    # one of the gating §6 checks; the verifier SHOULD assert it defensively over
    # arbitrary bytes, but reports it as a non-gating 'warning' (not an error),
    # so ok still reflects the gating checks.
    if disposition is not None:
        approver = disposition.get("approver")
        if approver is None:
            findings.append(Finding("missing_required_field", "disposition.approver is REQUIRED (§5.4)", check=1))
        elif approver not in VALID_APPROVERS:
            # Closed enum, structural — NOT an unknown-registry finding (§6).
            findings.append(Finding("approver_invalid", f"disposition.approver MUST be human|policy (§5.4); got {approver!r}", check=1))
        if "decision" not in disposition:
            findings.append(Finding("missing_required_field", "disposition.decision is REQUIRED (§5.4)", check=1))
        hd = disposition.get("human_disposed")
        if not isinstance(hd, bool):
            findings.append(Finding("field_not_bool", "disposition.human_disposed is REQUIRED and boolean (§5.4)", check=1))
        elif hd and approver != "human":
            findings.append(Finding(
                "dishonest_human_disposed",
                "human_disposed=true with a non-human approver (§5.4). Structurally "
                "unconstructable by a conforming producer; reported as a non-gating "
                "defensive warning, not a §6 gating check.",
                severity="warning",
            ))

    # ---- Check 2: Identity --------------------------------------------------
    recomputed = None
    if cid is not None:
        try:
            recomputed = compute_capsule_id(dict(capsule))
        except FloatInDigestError:
            pass  # already reported as float_in_digest_field
        except Exception as exc:
            findings.append(Finding("capsule_id_uncomputable", repr(exc), check=2))
        if recomputed is not None and recomputed != cid:
            findings.append(Finding("capsule_id_mismatch", f"recomputed {recomputed} != carried {cid}", check=2))

    # ---- Check 3: Confirmed-effect binding ----------------------------------
    if effect is not None and effect.get("status") == "confirmed" and not is_hex64(effect.get("response_digest")):
        findings.append(Finding("confirmed_without_response", "effect.status 'confirmed' requires a 64-hex response_digest (§5.2)", check=3))

    effect_mode = derive_effect_mode(effect)

    # ---- Check 4: Verdict/effect orthogonality ------------------------------
    verdict_class = disposition.get("verdict_class") if disposition else None
    if verdict_class in NEVER_DISPATCH_VERDICT_CLASSES and effect_mode != "not_applicable":
        findings.append(Finding(
            "verdict_effect_conflict",
            f"verdict_class {verdict_class!r} never dispatches, but derived effect_mode is {effect_mode!r} (§5.4.2)",
            check=4,
        ))

    # ---- Check 5: Effect-attestation matrix ---------------------------------
    ea = effect.get("effect_attestation") if effect else None
    if effect_mode in ("confirmed", "dispatched_unconfirmed"):
        if ea is None:
            findings.append(Finding("effect_attestation_missing", f"effect_attestation REQUIRED for effect_mode {effect_mode!r} (§5.2)", check=5))
    else:  # not_applicable (includes the planned carve and the no-effect case)
        if ea is not None:
            findings.append(Finding("effect_attestation_present", "effect_attestation MUST be absent for effect_mode 'not_applicable' (§5.2)", check=5))

    # ---- Check 6: Chain semantics (store-level) -----------------------------
    if chain is not None:
        parent = chain.get("parent_capsule_id")
        if not is_hex64(parent):
            findings.append(Finding("chain_parent_malformed", "chain.parent_capsule_id MUST be a 64-hex capsule_id (§5.4.4)", check=6))
        if "relation" not in chain:
            findings.append(Finding("missing_required_field", "chain.relation is REQUIRED when a chain block is present (§5.4.4)", check=6))
        ids = _store_ids(store)
        if ids is None:
            findings.append(Finding("chain_check_store_level", "chain parent-existence and concurrent-supersedes are store-level checks (§6); not run without a store", severity="info", check=6))
        elif isinstance(parent, str) and parent not in ids:
            findings.append(Finding("chain_parent_missing", f"chain parent {parent} not found in the store (§6)", check=6))

    # ---- Check 7: Assurance reconciliation ----------------------------------
    derived = {
        "effect_mode": effect_mode,
        "attestation_mode": "self_attested",  # no receipt verified at this layer
        "ledger_mode": "chained" if chain is not None else "standalone",
    }
    stated = capsule.get("assurance")
    if isinstance(stated, Mapping):
        sm = stated.get("effect_mode")
        if sm in _EFFECT_MODE_RANK and _EFFECT_MODE_RANK[sm] > _EFFECT_MODE_RANK.get(effect_mode, 0):
            findings.append(Finding("assurance_overclaim", f"claimed effect_mode {sm!r} but verifier derived {effect_mode!r} (§5.3)", check=7))
        sa = stated.get("attestation_mode")
        if sa in _ATTESTATION_RANK and _ATTESTATION_RANK[sa] > _ATTESTATION_RANK[derived["attestation_mode"]]:
            findings.append(Finding("assurance_overclaim", f"claimed attestation_mode {sa!r} but no Receipt verified at this layer (§5.3)", severity="info", check=7))
        sl = stated.get("ledger_mode")
        if sl in LEDGER_MODE_RANK and LEDGER_MODE_RANK[sl] > LEDGER_MODE_RANK[derived["ledger_mode"]]:
            findings.append(Finding("assurance_overclaim", f"claimed ledger_mode {sl!r} but verifier derived {derived['ledger_mode']!r} (§5.3)", severity="info", check=7))

    # ---- Check 8: Unknown registry values -----------------------------------
    for reg_name, (block, member) in _REGISTRY_FIELDS:
        blk = _obj(capsule, block)
        if blk is None:
            continue
        val = blk.get(member)
        if val is None:
            continue
        seeded = registries.get(reg_name, frozenset())
        if val not in seeded:
            findings.append(Finding("unknown_registry_value", f"{block}.{member}={val!r} is not a seeded {reg_name} value; informational, not rejected (§12)", severity="info", check=8))
            if reg_name == "effect_attestation":
                findings.append(Finding("effect_attestation_graded_floor", "unknown effect_attestation graded no stronger than 'runtime_claimed' (§5.2)", severity="info", check=8))

    ok = not any(f.severity == "error" for f in findings)
    return VerificationResult(ok=ok, findings=findings, assurance=derived, capsule_id=recomputed)


def verify_store(
    capsules: list[Any],
    *,
    registries: Mapping[str, frozenset] | None = None,
) -> list[VerificationResult]:
    """Verify a ledger of Capsules in order, running the store-level chain checks
    of §6/§5.4.4 (parent existence + concurrent-supersedes). ``capsules`` is in
    ledger order; the earliest supersedes over a given parent is authoritative."""
    if registries is None:
        registries = load_registries()
    results = [verify(c, store=capsules, registries=registries) for c in capsules]

    # Concurrent-supersedes (§5.4.4): earliest in ledger order is authoritative;
    # any later supersedes over the same parent surfaces as an (info) finding.
    seen_parent: set[str] = set()
    for c, res in zip(capsules, results):
        if not isinstance(c, Mapping):
            continue
        chain = c.get("chain")
        if not isinstance(chain, Mapping):
            continue
        if chain.get("relation") != "supersedes":
            continue
        parent = chain.get("parent_capsule_id")
        if not isinstance(parent, str):
            continue
        if parent in seen_parent:
            res.findings.append(Finding("concurrent_supersedes", f"a later supersedes over parent {parent}; the earliest is authoritative (§5.4.4)", severity="info", check=6))
        else:
            seen_parent.add(parent)
    return results
