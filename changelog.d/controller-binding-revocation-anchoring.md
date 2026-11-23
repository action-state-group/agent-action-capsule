- Spec: `spec/controller-binding-v0.md` §5.2 (evidencebook#780): for a record with an attested
  time (the earliest time a third party attests it existed by, for example a stamp), a revocation
  statement counts only when, besides `revoked_at` at or before the record's own time as before, its
  earliest anchor (a time a third party attests the statement existed by) is not later than the
  record's attested time. A statement first anchored after that, or not anchored at all, no longer
  removes the binding for that record, whatever its `revoked_at`; for a pair, both members need an
  attested time. Attestations by either bound key, from the presenter, or dated after the
  evaluation time do not count. The rule only adds a requirement, and results for a record with no
  attested time are unchanged. Adds §9.5, the times a verifier reports (§7 item 1), and open point
  CB-10 (no attestation format is registered). New vectors: `vectors/controller-binding-v0-anchoring/`
  (18 cases), checked by the specification's evaluator; no implementation in this repository
  applies §5.2 yet.
