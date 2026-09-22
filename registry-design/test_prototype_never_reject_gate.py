"""R4-style test for the Gate A' (never-reject) design prototype.

Both halves shown, per the coder protocol's mutation-testing bar:
  1. What the gate is supposed to catch: a verifier that rejects a record
     solely because it carries an unregistered vocabulary value. The mutant
     verifier below is caught (fails the fixture) -- this half proves the
     gate design actually discriminates a real violation, not a vacuous
     check that always passes.
  2. What the gate must NOT do: reject a correctly-behaving verifier. The
     correct verifier passes the same fixture -- this half proves the gate
     is not simply failing everything, which would make it useless (a gate
     that rejects every entry "catches" every mutant trivially and is
     worthless).

Run: python3 -m pytest registry-design/test_prototype_never_reject_gate.py -v
     (or: python3 registry-design/test_prototype_never_reject_gate.py)
"""

from prototype_never_reject_gate import (
    build_never_reject_fixture,
    verify_record_mutant_rejects_unknown,
    verify_record_never_reject,
)


def test_correct_verifier_never_rejects_unknown_value():
    """Half 1 -- the gate must pass a correct, never-reject-compliant verifier."""
    fixture = build_never_reject_fixture("x-example-newly-registered-value")
    result = verify_record_never_reject(fixture)
    assert result.valid is True
    assert "unrecognized" in result.reason


def test_mutant_verifier_is_caught_rejecting_unknown_value():
    """Half 2 -- the gate must fail (catch) a verifier that violates the
    never-reject invariant by rejecting an unregistered value.
    """
    fixture = build_never_reject_fixture("x-example-newly-registered-value")
    result = verify_record_mutant_rejects_unknown(fixture)
    assert result.valid is False
    assert "rejected" in result.reason


def test_known_value_still_valid_under_both_verifiers():
    """Sanity: a KNOWN value must validate under both verifiers -- the
    never-reject invariant is about UNKNOWN values only; it never
    licenses treating a known, invalid record as valid.
    """
    fixture = {"verdict_class": "executed"}
    assert verify_record_never_reject(fixture).valid is True
    assert verify_record_mutant_rejects_unknown(fixture).valid is True


def test_structurally_malformed_record_rejected_by_both():
    """Sanity: never-reject governs vocabulary values, not structural
    validity -- a malformed record (missing/empty verdict_class) is
    rejected by both verifiers, mutant and correct alike.
    """
    fixture = {"verdict_class": ""}
    assert verify_record_never_reject(fixture).valid is False
    assert verify_record_mutant_rejects_unknown(fixture).valid is False


if __name__ == "__main__":
    test_correct_verifier_never_rejects_unknown_value()
    test_mutant_verifier_is_caught_rejecting_unknown_value()
    test_known_value_still_valid_under_both_verifiers()
    test_structurally_malformed_record_rejected_by_both()
    print("All 4 checks passed (both R4 halves + 2 sanity checks).")
