# SPDX-License-Identifier: BSD-3-Clause
"""Disclosure Envelope reference verifier (draft-mih-scitt-agent-action-capsule-disclosure-envelope-00).

Verifies a Disclosure Envelope — ``{"capsule": {...}, "disclosures": {...}}`` —
by running Class 1 verification (:func:`agent_action_capsule.verify.verify`)
over ``capsule`` unmodified, and independently recomputing the JSON-DIGEST of
each provided disclosure to compare against the digest committed inside
``capsule``. Reuses the profile's single canonicalization primitive
(:func:`agent_action_capsule.canonical.json_digest`); this module defines no
second hashing path.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .canonical import FloatInDigestError, UnsafeIntegerError, json_digest, vintage_json_digest
from .registries import DISCLOSURE_ELIGIBLE_FIELDS
from .verify import VerificationResult, verify

MATCH = "disclosure_match"
MISMATCH = "disclosure_mismatch"
INELIGIBLE = "disclosure_ineligible_field"
NO_COMMITTED_DIGEST = "disclosure_no_committed_digest"


@dataclass(frozen=True)
class DisclosureFinding:
    member: str
    code: str


@dataclass
class DisclosureEnvelopeResult:
    """Result of verifying a Disclosure Envelope (DE-1 through DE-3).

    ``capsule_result`` is the unmodified Class 1 result for ``envelope["capsule"]``
    and is never gated by disclosure outcomes; ``disclosure_findings`` carries one
    finding per provided ``disclosures`` member. ``ok`` is true only when both the
    capsule verifies AND every provided disclosure matches its committed digest.
    """

    capsule_result: VerificationResult
    disclosure_findings: list[DisclosureFinding] = field(default_factory=list)

    @property
    def disclosures_checked(self) -> int:
        return len(self.disclosure_findings)

    @property
    def disclosures_matched(self) -> int:
        return sum(1 for f in self.disclosure_findings if f.code == MATCH)

    @property
    def ok(self) -> bool:
        return self.capsule_result.ok and all(f.code == MATCH for f in self.disclosure_findings)


def verify_disclosure_envelope(envelope: Any) -> DisclosureEnvelopeResult:
    """Verify a Disclosure Envelope. Never raises (mirrors :func:`verify`'s contract)."""
    if not isinstance(envelope, Mapping):
        return DisclosureEnvelopeResult(capsule_result=verify(envelope))

    capsule = envelope.get("capsule")
    capsule_result = verify(capsule)

    disclosures = envelope.get("disclosures")
    findings: list[DisclosureFinding] = []
    if isinstance(disclosures, Mapping):
        for member, value in sorted(disclosures.items()):
            if member not in DISCLOSURE_ELIGIBLE_FIELDS:
                findings.append(DisclosureFinding(member, INELIGIBLE))
                continue

            stored = _committed_digest(capsule, DISCLOSURE_ELIGIBLE_FIELDS[member])
            if not isinstance(stored, str) or len(stored) != 64:
                findings.append(DisclosureFinding(member, NO_COMMITTED_DIGEST))
                continue

            try:
                if capsule.get("format_version") == "2":
                    computed = vintage_json_digest(value)
                else:
                    computed = json_digest(value)
                matches = computed == stored
            except (FloatInDigestError, UnsafeIntegerError, TypeError, ValueError):
                matches = False

            findings.append(DisclosureFinding(member, MATCH if matches else MISMATCH))

    return DisclosureEnvelopeResult(capsule_result=capsule_result, disclosure_findings=findings)


def build_disclosure_envelope(capsule: Mapping[str, Any], disclosures: Mapping[str, Any]) -> dict[str, Any]:
    """Build a disclosure envelope after enforcing DE-1 through DE-3.

    Raises :class:`ValueError` whose message starts with the verifier finding
    code for an ineligible member, missing commitment, or digest mismatch. This
    pure function neither reads a store or ledger nor depends on emit.
    """
    for member, value in disclosures.items():
        path = DISCLOSURE_ELIGIBLE_FIELDS.get(member)
        if path is None:
            raise ValueError(f"{INELIGIBLE}: {member}")
        stored = _committed_digest(capsule, path)
        if not isinstance(stored, str) or len(stored) != 64:
            raise ValueError(f"{NO_COMMITTED_DIGEST}: {member}")
        try:
            computed = (
                vintage_json_digest(value)
                if capsule.get("format_version") == "2"
                else json_digest(value)
            )
        except (FloatInDigestError, UnsafeIntegerError, TypeError, ValueError) as err:
            raise ValueError(f"{MISMATCH}: {member}") from err
        if computed != stored:
            raise ValueError(f"{MISMATCH}: {member}")
    return {"capsule": capsule, "disclosures": dict(disclosures)}


def _committed_digest(capsule: Any, path: str) -> Any:
    current = capsule
    parts = path.split(".")
    for member in parts[:-1]:
        if not isinstance(current, Mapping):
            return None
        current = current.get(member)
    return current.get(parts[-1]) if isinstance(current, Mapping) else None
