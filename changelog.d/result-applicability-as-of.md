- Spec: Evidence Result v0 gains an optional document member, `applicability_as_of`
  (`spec/evidence-result-v0.md` §4.3, AAC#369, the 2026-10-25 ruling): the calendar date "in
  force" is judged against, for an evaluation of past activity. Absent means the UTC date of
  `generated_at`, as before, so every Result that validated before validates and reads unchanged.
  It MUST be a calendar date no later than the UTC date of `generated_at`, and a reader shows both
  dates. The schema, the Python reference checker, Go `evidenceresult.Check` and the TypeScript
  reader (`asOfDate`, `ResultRoot.applicabilityAsOf`) enforce and expose it. Eight vectors in
  `vectors/evidence-result/`.
- Spec: §1 gains a non-normative note on how the 2026-09-22 ruled text and the binding rule on
  `not_evaluable` read together (AAC#358). The ruled text and the rule are unchanged:
  `not_evaluable` records that no judgment was made, and the claim's `sufficiency` carries the
  reason.
