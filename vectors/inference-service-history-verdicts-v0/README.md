# Inference-Service History v0: verdict counts vectors

These vectors exercise the optional `verdict_counts` member of
`spec/inference-service-history-profile-v0.md` (§4.3, §5.3, with the period rules of §6) on the
Standard History of `vectors/inference-service-history-v0/`: the same node stream, card and period
policy (floor 5, complementary suppression), with a third member counting the referee verdicts the
node holds about itself.

## The member (a format fixed for these vectors, SH-12)

`{"check": "referee_verdict", "signed_by": "checker", "policy": <policy digest>, "periods": [...]}`.
Each period (the same closed periods as `period_counts`) lists, for each result in the order
`corroborated`, `contradicted`, `inconclusive`, `not_comparable`, one cell per model hash in hash
order and then the result's total, `{"dimension": {"model_hash": ..., "result": ...}}` or
`{"dimension": {"result": ...}}`, in the unit `referee_verdicts`, labelled `self_reported`. Each
result is a table of its own, with the floor and complementary suppression of §6.2; no total across
results is listed (§5.1). Whether the node or the other party asked the referee is not in the
artifact.

## Cases

One positive (`verdict-counts-held`: all four results; a cell under the floor and its total withheld;
a withheld model beside a published total with another cell withheld with it) and twelve negatives,
each failing one History property: a published value under the floor, a missing complementary
suppression, a result's table dropped, another unit, a label stronger than the evidence, a count
signed by the node or of another kind of check, the results added together, models out of order,
another period policy, a period left out, and a member the artifact does not declare.

## Not covered

- The rule for two or more withheld models beside a published total (SH-8 stays open); the Rust
  library withholds the total there, which these cases do not state.
- Delivery of a verdict to a node, and the ask by digest that checks omission (SH-15): the host's.
- The envelope, the card and the other History properties: `vectors/inference-service-history-v0/`.
- Go, the capsule-engine admission evaluator and the Python library do not read this member yet.

## Derivation

`python/scripts/generate_inference_service_history_verdicts_v0_vectors.py` writes every file except
this README, on the generator of the base set. It states every expected status by hand from the
profile text. `python/tests/test_inference_service_history_verdicts_v0_vectors.py` evaluates every
case from its inputs alone with its own code, requires the result to equal the case's `expected`
block, and regenerates the directory byte for byte. The Rust test
`rust/agent-action-capsule/tests/inference_history_verdicts_vectors.rs` checks every case with
`agent_action_capsule::inference_history`.
