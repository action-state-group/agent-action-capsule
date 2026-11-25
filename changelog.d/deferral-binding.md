- Spec, -06 in-tree (AAC#321): the deferral binding rule. A Capsule chained `supersedes` to an
  open item (`deferred`, `needs_decision`, `hitl_dispatched`, `escalated`, `blocked`) or to an
  `expired` one carries the parent's `action_id`. An `executed` closure, and any Capsule in that
  chain that carries an Effect Record, also carries the `effect.type` and, when present, the
  `request_digest` of the first Effect Record up the chain of open and `expired` parents, so an
  escalation or expiry in between cannot change the effect a decider was asked to approve. Each Capsule on that chain is
  resolved by recomputing its `capsule_id`, never by a carried value alone. A violation fails Class 1 check 6;
  the spec also leaves a violating Capsule out of the open-items predicate and out of the
  earliest-authoritative choice among concurrent supersedes. When the parent, or an earlier
  Capsule on that chain, is in the store only as an identifier or does not recompute, the rule is
  reported as not evaluated (info). `action_id`
  is now shared by every Capsule that records the same action, and a `planned` effect MAY carry
  `request_digest` (the request the decider is asked to dispose). Breaking for a store in which a
  deferral was closed by a Capsule for another action or another effect, which verified before;
  `spec_version` is unchanged.
- Vectors: `pos-supersedes-chain` and `pos-concurrent-supersedes` now close their parent with its
  own `action_id` (new `capsule_id`s); twenty-three new store cases in `vectors/capsule/` (five
  `pos-supersedes-*`, eighteen `neg-supersedes-*`).
- Python, Go, TypeScript: verifying a store (`verify_store`, `VerifyStore`, `verifyStore`, or a
  single Capsule with a store) enforces the rule: codes `supersedes_action_mismatch`,
  `supersedes_effect_type_mismatch` and `supersedes_request_digest_mismatch` (check 6, error), and
  `deferral_binding_not_evaluated` (check 6, info). A violating supersedes is never chosen as the
  authoritative one, so a later bound closure carries no `concurrent_supersedes` finding. None of
  the implementations computes the open-items set. TypeScript's `verifyStore` passes the Capsules
  themselves, not an id `Set`, to `verifyClass1`. Python's `verify` reads a one-shot store iterable
  once, and `EffectRecord(status="planned")` accepts `request_digest`.
