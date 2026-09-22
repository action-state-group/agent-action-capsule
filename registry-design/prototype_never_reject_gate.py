"""DESIGN PROTOTYPE — not wired into any CI workflow.

Demonstrates the mechanics of AAC registry design's Gate A' (the
never-reject case, question 5 of the five_questions template in
entries/TEMPLATE.yaml): a registration must ship a fixture proving that a
verifier which has never seen the newly registered value still does not
reject a record solely because the value is unrecognized
(spec/REGISTRY.md:12-15, "The never-reject invariant").

This module is intentionally minimal: a toy record shape (a single
`verdict_class` field, standing in for any AAC vocabulary field), a correct
verifier that implements the never-reject invariant, and a mutant verifier
that violates it by rejecting unknown values. The test file in this same
directory runs the fixture against both and shows the gate discriminates:
it passes the correct verifier and fails (catches) the mutant.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict


class VerdictClassRecord(TypedDict):
    verdict_class: str


# The set of verdict_class values this verifier build ships with knowledge
# of. A record using a value outside this set is exactly the "unregistered
# value" case the never-reject invariant governs.
KNOWN_VERDICT_CLASS_VALUES = frozenset(
    {
        "executed",
        "blocked",
        "hitl_dispatched",
        "denied",
        "timeout",
        "errored",
        "engine_failure",
        "deferred",
        "needs_decision",
        "expired",
        "escalated",
        "resolved",
        "epoch_boundary",
    }
)


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: str


def _structurally_well_formed(record: VerdictClassRecord) -> bool:
    """Structural checks a real verifier would run regardless of vocabulary
    content: required keys present, correct types. Digest verification is
    out of scope for this prototype (orthogonal to the never-reject
    question); only vocabulary-value handling is under test here.
    """
    return (
        isinstance(record, dict)
        and isinstance(record.get("verdict_class"), str)
        and record.get("verdict_class") != ""
    )


def verify_record_never_reject(record: VerdictClassRecord) -> VerificationResult:
    """Correct verifier: implements the never-reject invariant. An
    unrecognized verdict_class value is informational only and MUST NOT
    cause rejection.
    """
    if not _structurally_well_formed(record):
        return VerificationResult(False, "structurally malformed")

    value = record["verdict_class"]
    if value not in KNOWN_VERDICT_CLASS_VALUES:
        # Never-reject invariant: log/flag as informational, never fail.
        return VerificationResult(
            True, f"structurally valid; verdict_class={value!r} unrecognized (informational)"
        )
    return VerificationResult(True, f"structurally valid; verdict_class={value!r} known")


def verify_record_mutant_rejects_unknown(record: VerdictClassRecord) -> VerificationResult:
    """MUTANT verifier: a naive/incorrect implementation that fails closed
    on any vocabulary value it doesn't recognize. This is the bug the never-
    reject invariant exists to forbid. Used only to prove the gate's fixture
    actually discriminates — never a real verifier.
    """
    if not _structurally_well_formed(record):
        return VerificationResult(False, "structurally malformed")

    value = record["verdict_class"]
    if value not in KNOWN_VERDICT_CLASS_VALUES:
        return VerificationResult(False, f"rejected: unrecognized verdict_class={value!r}")
    return VerificationResult(True, f"structurally valid; verdict_class={value!r} known")


def build_never_reject_fixture(new_value: str) -> VerdictClassRecord:
    """The fixture a registration ships: a minimal, otherwise well-formed
    record carrying the newly registered (and, to this verifier build,
    unknown) value.
    """
    return {"verdict_class": new_value}


if __name__ == "__main__":
    fixture = build_never_reject_fixture("x-example-newly-registered-value")

    correct = verify_record_never_reject(fixture)
    mutant = verify_record_mutant_rejects_unknown(fixture)

    print(f"correct verifier : valid={correct.valid}  reason={correct.reason}")
    print(f"mutant verifier  : valid={mutant.valid}  reason={mutant.reason}")

    assert correct.valid is True, "correct verifier must not reject an unknown value"
    assert mutant.valid is False, "mutant verifier is expected to (incorrectly) reject it"
    print("\nGate A' (never-reject) prototype: fixture discriminates correct vs mutant. OK.")
