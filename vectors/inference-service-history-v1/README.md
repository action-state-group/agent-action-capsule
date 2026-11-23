# Inference-Service History /1: conformance vectors

These are the cases of `vectors/inference-service-history-v0-interop-v1/` with every definition
naming the History profile `inference-service-history/1` (`spec/inference-service-history-profile-v1.md`,
ISH1) instead of `/0`, plus five more for the one rule ISH1 adds (ISH1 §6.2 item 3.2, SH-8): a
`period_counts` total that fixes two or more models withheld under the floor is withheld with them
as `complementary`. Every request and envelope names `evidence-interop/1`; ISH1 is not served over
`/0`. Because each definition names this README in its `spec` member, its digest differs from the
`/0` definition's; the test keys, the card, the period policy and every other count are the same.

The five cases, each in 2 October of the served-only History, under the floor of 5:

| Case | Counts | Expected |
|---|---|---|
| `standard-total-withheld-two-pinned` | two models of 4; total withheld `complementary` | accepted |
| `standard-total-withheld-ones-pinned` | five models of 1; total withheld `complementary` | accepted |
| `standard-total-published-not-pinned` | models of 4 and 3; total 7 published (7 is neither 2 nor 8) | accepted |
| `mutant-total-two-pinned-published` | two models of 4 withheld; total 8 published | `period_floor` `FAIL` |
| `mutant-total-ones-pinned-published` | five models of 1 withheld; total 5 published | `period_floor` `FAIL` |

Every other case expects what it expects in the `/0` sets: no period of theirs has two or more
cells suppressed `below_floor`.

`python/scripts/generate_inference_service_history_v0_vectors.py --profile 1 --history 1` writes
every file except this README. `python/tests/test_inference_service_history_v1_vectors.py` runs the
checks of `test_inference_service_history_v0_vectors.py` against this set, regenerates it and
requires it to be byte-identical to the committed files. Both `/0` sets are frozen.
