# AAC registration pipeline — design (not activated)

**Status: DESIGN ONLY.** Nothing in this directory is wired into
`.github/workflows/`, generates `registry.json`, or has any effect on
`spec/REGISTRY.md`. It is the Phase 2 deliverable of
`[cpb-registry-activation-and-aac-side]` (see
`/dev/asg/_work/cpb-registry-activation-and-aac-side-memo-2026-09-22.md` for
the full Phase 0/1/2 writeup this belongs to). It exists so that when Steven
rules on Phase 1(b) (the third CPB Designated Expert seat) and Phase 1(d)
(whether ASG-owned artifact types consolidate here), there is a reviewable,
already-mutant-checked design to activate rather than a blank page.

## Why AAC needs this at all (one-line recap of Phase 0)

`scitt-payload-binding`'s own spec text (`-05.md:1277`) and registry header
say CPB "neither creates nor depends on an artifact-type registry" —
artifact-type material is profile-owned. AAC's `spec/REGISTRY.md` already
carries 15 of AAC's own vocabularies as prose tables (`verdict_class`,
`disposition.decision`, `effect.type`, `irreversibility_class`,
`effect_attestation`, `chain.relation`, `citation_purpose`, and others), but
has no PR-based filing template, machine schema, or CI validation around
them — every registration today is a hand-edited Markdown table row. CPB's
`registry/entries/*.yaml` + `.github/validate_registry_entries.py` pipeline
(PR #77, `cpb-registry-operational-standup`) is the pattern worth porting;
its *questions* are not, because CPB's seven questions are about
**construction** (what bytes, what's excluded, what canonicalization) and
AAC's registries are **vocabularies** (what does this token mean, not what
bytes produce it).

## What ports unchanged from CPB

- **The rung model.** `owner_authored` / `third_party_documented` /
  `provisional` / `reserved`, with the same status mapping
  (`owner_authored` → `owner-confirmed`, etc.) and the same Rung 3
  ("provisional") holding pen for filings whose spec isn't pinned enough
  yet.
- **Fork-safe `pull_request_target` CI.** Same reason CPB needed it: a
  registrant's PR from a fork must be validated without granting the fork
  write access or secrets.
- **Gate A, generalized.** CPB's Gate A is a *discriminating vector* — a
  test case that passes for this entry and fails for at least one existing
  neighbour, both directions. AAC's equivalent (see "AAC's five questions"
  below, question 5) is not a construction-discrimination test — vocabulary
  values don't have byte-level constructions to discriminate — it is the
  **never-reject case**: a registration ships a fixture proving a verifier
  that has never seen the new value still does not reject the record. This
  is the mechanically-checkable analogue that actually matters for AAC,
  because AAC's real invariant (`spec/REGISTRY.md:12-15`, "The never-reject
  invariant") is about unknown values, not about telling two known values
  apart.
- **Gate B, unchanged.** A spec-revision-pinned consuming profile — the
  entry's own specification does not count. Same rule, same reason: a
  vocabulary value that nothing outside its own defining draft consumes is
  unfalsifiable as "in use."
- **Commit-pinned references.** A branch or tag is not a pin, for the same
  reason CPB requires it — a moving ref lets a cited construction change
  out from under an already-promoted entry.
- **Editors MUST NOT fill in a registrant's answers.** Direct port —
  AAC editors have exactly the same incentive problem CPB editors do.
- **`"TBD — <why>"`, never a blank.** Direct port.
- **A mutation-tested validator.** See `prototype_never_reject_gate.py`
  below — ported as a design pattern (write the check, then prove a mutant
  that removes/breaks it is caught), not as CPB's literal test file.

## What does NOT port — AAC's five questions vs CPB's seven

CPB's seven questions (`registry/entries/TEMPLATE.yaml`, current
`origin/main`) are digest-input bytes, exclusion set, canonicalization
profile, hash algorithm, representation, composite-or-not, cross-language
parity. None of these have meaning for a vocabulary token — a
`verdict_class` value like `hitl_dispatched` has no digest-input bytes to
exclude. AAC's registries need their own questions, made mechanical from the
designated-expert guidance already stated in `spec/REGISTRY.md:28-41`
(clear semantics, no overlap, publicly available spec) plus two AAC-specific
additions:

1. **Clear semantics** — would two independent implementations apply this
   value identically? (Direct restatement of `spec/REGISTRY.md`'s existing
   test 1.)
2. **No overlap** — does this value duplicate the meaning of an existing
   value in the *same* registry? (Direct restatement of test 2. Note this
   is scoped per-registry, not global — `deferred` is deliberately shared
   between `verdict_class` and `disposition.decision` today via the
   "token ownership" cross-reference convention already in
   `spec/REGISTRY.md:72-74` and `:81-83`; a new template must be able to
   express "this token is a cross-reference to registry X's existing
   value," not just reject it as a duplicate.)
3. **Publicly available spec** — is the value's meaning pinned in a
   specification any implementer can read? (Direct restatement of test 3.)
4. **Ordering position, where the registry is ordered.** Not every AAC
   registry is ordered (`chain.relation` is not), but the ones that are
   (`irreversibility_class`, `effect_attestation`'s grade floor,
   `provenance_mode.time_rung`) require a registration to state its
   position relative to the existing values — this is already normative
   text in `spec/REGISTRY.md` §4 ("MUST state its position in the
   consequence order") and §5 (grade-floor rule); the template makes it a
   required field only when the target registry is one of the ordered
   ones, `N/A` (not blank — see the schema below) otherwise.
5. **🔴 Verifier behaviour on the unknown value — the never-reject case.**
   AAC's registries are all governed by the never-reject invariant
   (`spec/REGISTRY.md:12-15`): a verifier MUST treat an unregistered value
   as informational and MUST NOT reject a record solely because it carries
   one. This is CPB's Gate A's actual AAC counterpart: mechanically
   checkable, and it tests the invariant that matters, not the invariant
   CPB happens to have. A registration ships a fixture (a minimal capsule
   or record carrying the *new* value against a verifier build that
   predates the registration) proving the verifier still accepts the
   record structurally. See the prototype below.

## Draft template

`entries/TEMPLATE.yaml` in this directory is the AAC-flavored equivalent of
CPB's `registry/entries/TEMPLATE.yaml` — same rung/status/owner/
disclosure/open_questions scaffolding, `seven_questions` replaced with
`five_questions`, and `fixtures.discriminating_vector` replaced with
`fixtures.never_reject_case`. It is a draft for review, not validated by any
CI job yet.

## Gate specification (design)

**Gate A′ (never-reject, AAC's analogue of CPB's Gate A).**
- [ ] The entry's `never_reject_case` field names a committed fixture in
  `vectors/registry/<registry>/<name>/` in the same PR (mirrors CPB's
  "in the same PR" branch — there is no third-party-vector-citation
  exemption needed here, since proving your own new value doesn't break an
  existing verifier is always something the registrant themselves can
  produce, unlike CPB's byte-construction vectors which may only exist in
  someone else's repo).
- [ ] The fixture's positive case: a record carrying the *new* value
  validates as structurally well-formed (schema-valid, digest-verifiable)
  against a verifier build that has no knowledge of the new value's
  semantics.
- [ ] The mutant case, run by CI, not by the registrant: inject a verifier
  mutant that rejects on any value outside its known set, and confirm the
  fixture *fails* against that mutant. If the fixture passes against the
  never-reject-violating mutant, the fixture is not discriminating (it
  wasn't testing the invariant) and the entry is rejected exactly the way
  CPB rejects a non-discriminating Gate A vector.

**Gate B′ (spec-revision-pinned consuming profile).** Unchanged from CPB's
Gate B, applied to AAC's own drafts: at least one named consumer, pinned by
Internet-Draft revision or commit hash, not the entry's own defining
document.

## Files in this directory

- `entries/TEMPLATE.yaml` — the draft AAC filing template.
- `prototype_never_reject_gate.py` — a small, runnable prototype: a toy
  verifier implementing the never-reject invariant correctly, a positive
  fixture, and a deliberately-broken mutant verifier that violates the
  invariant — proving the gate's check catches the mutant and passes the
  correct implementation. Run: `python3 prototype_never_reject_gate.py`.
- `test_prototype_never_reject_gate.py` — the R4-style test: asserts the
  correct verifier passes the fixture (positive) and the mutant verifier
  fails it (negative/mutant-caught), both halves shown.
