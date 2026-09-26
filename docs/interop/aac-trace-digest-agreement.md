# AAC ↔ TRACE Digest Agreement — Machine-Checked Fixture

**Status:** Fixture backing the informative crosswalk drafted for
`agentrust-io/trace-spec` (`docs/crosswalks/agent-action-capsule.md` in their tree).
**Checked against:** `agentrust-io/trace-spec` @ `62b8993eee77daeecbad6b11ec835a6f9ff5d534` (2026-09-22).
**Applicable to:** `draft-mih-scitt-agent-action-capsule` format 4 (plain JCS,
`json_digest = HEX(SHA-256(JCS(v)))`) ↔ TRACE Trust Record canonicalization
(`trace-v0.2.md` §3.2.2, RFC 8785 JCS).

---

## Purpose

The informative crosswalk to TRACE claims that an Agent Action Capsule fills
TRACE's registered `rel: "behavior-trace"` slot with no change to either
specification (§3.1.2). That claim is only checkable if the two specifications'
canonicalization actually agrees byte-for-byte where a verifier following
either spec would compute a digest. This fixture proves agreement, rather than
asserting it, over the cases RFC 8785 implementations are documented to
diverge on.

## What is exercised

TRACE's own spec (§3.2.2) names the exact two libraries that disagree:
`canonicalize` 4.0.0 (npm) and `rfc8785` 0.1.4 (PyPI). This repo's JCS
(`agent_action_capsule.canonical`) is cross-checked directly against
`rfc8785` 0.1.4 — the PyPI package TRACE names — rather than against a
re-implementation of TRACE's algorithm, so the comparison is between two
independent implementations, not one implementation and its own description
of itself.

| Divergence case | TRACE §3.2.2 requirement | AAC requirement (spec §2) |
|---|---|---|
| Non-ASCII string values | UTF-8, RFC 8259 §7 escaping only | same (plain JCS) |
| Non-BMP / supplementary-plane object key | UTF-16 code-unit sort, not code-point sort | same (plain JCS, RFC 8785 §3.2.3) |
| High-BMP object key | UTF-16 code-unit sort | same |
| Integer at exactly ±(2^53 − 1) | MUST accept (boundary itself is in-range) | MUST accept |
| Integer outside ±(2^53 − 1) | MUST reject (raised from RFC 8785 Appendix B note 1 SHOULD to a MUST) | producer MUST represent as a decimal string (§2) |

The fixture capsule (`aac-trace-digest-agreement-positive-capsule.json`)
combines the four in-range divergence cases (non-ASCII strings, the two
BMP/non-BMP key cases, and the safe-integer boundary itself, exercised at
both `safe_max` and `safe_min`) into one `extension` object so the digest
computed is over one real preimage, not four isolated micro-cases. The
fifth case — an integer outside the safe range — cannot appear in any real
preimage under the §2 producer rule, so it is exercised separately via the
`boundary_exceeded` mutation below, which both implementations refuse to
digest at all.

## Fixture files

- `aac-trace-digest-agreement-vector.json` — the vector: pinned digests, the
  checked-against commit, and the boundary-exceeded case.
- `aac-trace-digest-agreement-positive-capsule.json` — the positive capsule.
- `aac-trace-digest-agreement-mutant-capsule.json` — the same capsule with one
  nested leaf changed three levels down (`extension.trace_digest_agreement_test.😀`).
- `../../python/tests/test_interop_trace_digest_agreement.py` — the check.

## Verifier contract

1. Take the capsule_id preimage (every member except `capsule_id`).
2. Compute `sha256(JCS(preimage))` with AAC's `json_digest()`.
3. Compute `sha256(rfc8785.dumps(preimage))` independently.
4. The two MUST be byte-identical, not merely digest-identical — the test
   compares `jcs(preimage) == rfc8785.dumps(preimage)` before it compares
   digests, so a collision cannot mask a canonicalization mismatch.
5. A digest computed over a mutated nested value MUST differ from the
   unmutated digest under both implementations (`test_mutant_nested_key_perturbation_is_caught`).
   This is not academic: a canonicalizer bug that serializes a nested object
   as `{}` while leaving outer bytes intact — documented and fixed in a
   Capsule-side viewer on 2026-09-16 — produces exactly the false-agreement
   this check exists to catch.
6. An integer at 2^53 (the first value `canonicalize` 4.0.0 and `rfc8785`
   0.1.4 are documented to disagree on) MUST be rejected by both AAC's
   `json_digest()` and `rfc8785.dumps()` before either produces bytes
   (`test_boundary_exceeded_integer_is_rejected_by_both_implementations`).
   The two-library disagreement TRACE documents therefore has no preimage
   either format will ever digest.

## Scope

This fixture checks digest-computation agreement only. It does not restate
the field-mapping, `capsule_id`-vs-`digest` distinction, or verifier
obligations set out in the crosswalk prose itself — see
`docs/crosswalks/agent-action-capsule.md` in `agentrust-io/trace-spec` for
that. It does not depend on, and does not assert, anything about
`agent-action-capsule#95` (`ran_under`) or the CPB provisional artifact-type
registry.
