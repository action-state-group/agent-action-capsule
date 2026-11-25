<!-- changelog: rust/agent-action-capsule/CHANGELOG.md -->
- `verify_store` and `verify` with a store enforce the deferral binding rule of the -06 in-tree
  draft (AAC#321). A `supersedes` over an open or `expired` parent carries the parent's
  `action_id`. An `executed` closure, and any Capsule in that chain that carries an Effect Record,
  carries the `effect.type` and `request_digest` of the first Effect Record up the chain of open
  and `expired` parents. Each Capsule on that chain is found by recomputed `capsule_id`. Codes `supersedes_action_mismatch`,
  `supersedes_effect_type_mismatch`, `supersedes_request_digest_mismatch` (check 6, error) and
  `deferral_binding_not_evaluated` (check 6, info); a violating closure is never the authoritative
  supersedes. Passes the new `vectors/capsule/` store cases.
