<!-- changelog: rust/agent-action-capsule/CHANGELOG.md -->
- Check 8 reports a well-formed `references` entry whose `type` is not `agent-action-capsule` as
  the informational finding `reference_type_unresolved` (CPB Unresolved, cause `context`; never a
  rejection), matching draft-06 and the other verifiers (#412).
- Removed: the embedded `data/cpb_provisional.json`, `registries::provisional_values`,
  `registries::ProvisionalValues`, the check-8 `registry_snapshot_unavailable` warning and the
  check-8 `known_provisional_registry_value` finding (#418).
  The embedded snapshot listed no capsule field values, so no input produced that finding.
