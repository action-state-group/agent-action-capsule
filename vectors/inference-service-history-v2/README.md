# Inference-Service History: `inference-service-history/2` vectors

These vectors exercise `inference-service-history/2` of
`spec/inference-service-history-profile-v0.md`: `/1` with one more complementary rule (§6.2 item 6,
SH-8). Take a table with exactly two dimension cells withheld: one `below_floor` (`x`) and item 3's
`complementary` partner. Let `r` be the total less its published cells, and `m` the smallest
published cell. Then `max(1, r − m) ≤ x ≤ min(floor − 1, r − floor)`, with no `r − m` term where
no cell is published. Where that range holds one value, the total is withheld `complementary` too.

They are built on the Standard History of `vectors/inference-service-history-v0-interop-v1/`
(`evidence-interop/1`): the same node stream, card, period policy (floor 5) and envelopes, with the
definitions `service_history_example/2` and `service_history_verdicts_example/2` naming
`inference-service-history/2`, and 2 October's cells replaced by the table each case is about. A
count carries no records (§4.2), so a table need not match the card's log sizes. The `/0` and `/1`
sets are unchanged.

## Cases

Twelve positives:

- `/1`'s five, under `/2`: the base History (one model withheld and its partner, holding 12 between
  them, which leaves 1 to 4); models 4 and 4, five models of 1, and models 1 and 1, each total
  withheld; models 3 and 4, total published.
- Item 6, with each total withheld: models 1, 5 and 9 (the least the pair can hold); models 4, 6
  and 6 (the most); models 3, 5 and 5 (the partner lies between the floor and a published 5); and
  models 1 and 5, with nothing else published.
- Item 6, with each total published: models 3, 6 and 6 (3 or 4) and models 3 and 7 (1 to 4).
- A total withheld `complementary` beside one model under the floor and its partner, where the
  bounds leave 1 to 4. It is accepted, because a verifier sees only the table's shape (SH-14).

Twelve negatives, each failing `period_floor`:

- `/1`'s five: the totals of 8 and 5 published; 10 published and 4 and 4 withheld under a published
  18; 10 published and three withheld under a published 12, less than one per model; and two
  withheld under a published 19, more than they can hold.
- Item 6's four withheld totals, each published.
- Models 1, 5 and 9 under published totals of 14 and 23, which no counts can match.
- A total withheld `complementary` beside one model under the floor with no partner.

Four cases add the verdict counts member of `vectors/inference-service-history-verdicts-v0/`. Its
2 October contradicted table holds either 4 and 4 (item 5) or 1 and 5 (item 6). Each comes with its
total withheld (accepted) and published (`period_floor` `FAIL`).

## Not covered

- A floor other than 5, so there is no case for a floor of 2, where every listed `below_floor`
  cell is 1.
- The limits §12 names: narrower bounds, and cells derived across definitions or counts members
  (agent-action-capsule#720).
- The envelope, the card, the Detailed level and the other History properties: see
  `vectors/inference-service-history-v2-base/`.
- Go does not read the verdict counts member; its test lists the four verdict cases by id.

## Derivation

`python/scripts/generate_inference_service_history_v2_vectors.py` writes every file except this
README and states every expected status by hand from the profile text.
`python/tests/test_inference_service_history_v2_vectors.py` evaluates every case from its inputs
alone with the evaluator of `test_inference_service_history_v0_vectors.py`. It requires each result
to equal the case's `expected` block, and regenerates the directory byte for byte. The Rust test
`rust/agent-action-capsule/tests/inference_history_vectors.rs` and the Go test
`go/inferencehistory/vectors_test.go` check the cases with their own libraries.
