# SPDX-License-Identifier: BSD-3-Clause
"""Pair-verify for bilateral attestation exchanges.

A bilateral exchange produces two capsules — one from each org — that each
attest over the same action digest (``subject_digest`` or ``action_digest``
in ``compute_attestation``).  This module verifies that pair.

Public API
----------
verify_pair(capsule_a, capsule_b) -> PairVerifyResult
    Verify that two capsules form a valid bilateral pair:
    (1) each verifies individually (Class-1 verify);
    (2) they share the same action digest;
    (3) chain linkage is correct (if present).

PairVerifyResult
    .ok: bool
    .shared_digest: str | None
    .findings: list[PairFinding]
"""
from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["verify_pair", "PairVerifyResult", "PairFinding"]


@dataclass
class PairFinding:
    check: str
    detail: str
    severity: str = "error"  # "error" | "warning"


@dataclass
class PairVerifyResult:
    ok: bool
    shared_digest: str | None
    capsule_id_a: str | None
    capsule_id_b: str | None
    findings: list[PairFinding] = field(default_factory=list)


def _action_digest(cap: dict) -> str | None:
    """Extract the shared action digest from compute_attestation."""
    ca = (cap.get("model_attestation") or {}).get("compute_attestation") or {}
    # bilateral-00 uses "action_digest"; aauth-interop demo uses "subject_digest"
    return ca.get("action_digest") or ca.get("subject_digest")


def verify_pair(capsule_a: dict, capsule_b: dict) -> PairVerifyResult:
    """Verify that two capsules form a valid bilateral pair.

    Checks:
    1. Class-1 verify on capsule_a (hash integrity, format).
    2. Class-1 verify on capsule_b.
    3. Both capsules carry the same action digest in compute_attestation.
    4. Chain linkage: if capsule_b chains to capsule_a, the parent_capsule_id
       matches capsule_a's capsule_id.

    The two orgs are identified by ``operator`` fields; no org identity
    validation is performed here (that is the job of the identity layer).
    """
    from agent_action_capsule import verify as _verify

    findings: list[PairFinding] = []

    cid_a = capsule_a.get("capsule_id")
    cid_b = capsule_b.get("capsule_id")

    # --- Class-1 verify ---
    vr_a = _verify(capsule_a)
    if not vr_a.ok:
        for f in vr_a.findings:
            findings.append(PairFinding(
                check=f"capsule_a.{f.check}",
                detail=f.detail,
                severity=f.severity,
            ))

    vr_b = _verify(capsule_b)
    if not vr_b.ok:
        for f in vr_b.findings:
            findings.append(PairFinding(
                check=f"capsule_b.{f.check}",
                detail=f.detail,
                severity=f.severity,
            ))

    # --- Shared action digest ---
    digest_a = _action_digest(capsule_a)
    digest_b = _action_digest(capsule_b)

    if digest_a is None and digest_b is None:
        findings.append(PairFinding(
            check="shared_digest",
            detail="neither capsule carries an action_digest or subject_digest in compute_attestation",
            severity="warning",
        ))
        shared = None
    elif digest_a != digest_b:
        findings.append(PairFinding(
            check="shared_digest",
            detail=(
                f"action digests differ: capsule_a={digest_a!r} capsule_b={digest_b!r}; "
                "both parties must attest over the same canonical action"
            ),
        ))
        shared = None
    else:
        shared = digest_a

    # --- Chain linkage (optional but verified if present) ---
    chain_b = (capsule_b.get("chain") or {})
    parent_b = chain_b.get("parent_capsule_id")
    if parent_b is not None and cid_a is not None and parent_b != cid_a:
        findings.append(PairFinding(
            check="chain_linkage",
            detail=(
                f"capsule_b.chain.parent_capsule_id={parent_b!r} "
                f"does not match capsule_a.capsule_id={cid_a!r}"
            ),
        ))

    # --- Distinct operators ---
    op_a = capsule_a.get("operator")
    op_b = capsule_b.get("operator")
    if op_a and op_b and op_a == op_b:
        findings.append(PairFinding(
            check="distinct_orgs",
            detail=f"both capsules share the same operator {op_a!r}; "
                   "a bilateral exchange requires two distinct organizational identities",
            severity="warning",
        ))

    ok = all(f.severity != "error" for f in findings)
    return PairVerifyResult(
        ok=ok,
        shared_digest=shared,
        capsule_id_a=cid_a,
        capsule_id_b=cid_b,
        findings=findings,
    )
