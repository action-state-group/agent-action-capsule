# Inference-Service History: the base cases under `inference-service-history/2`

Every case of `vectors/inference-service-history-v0-interop-v1/` (`evidence-interop/1`), with the
definitions `service_history_example/2` and `service_history_detail_example/2` naming
`inference-service-history/2` (ISH §9.6). These are the Standard and Detailed levels, the
envelopes, the card, refusals, pairs (`period_fixed`), and the negatives for alignment, anchor,
labels and units.

No table in them has a shape that §6.2 items 5 or 6 change. Every case therefore expects what it
expects in the `/0` set; only the definitions, and the digests and signatures that follow from them,
differ.

## Derivation

`python/scripts/generate_inference_service_history_v2_vectors.py --base` runs the generator of the
`/0` set with `/2` definitions and writes every file except this README.
`python/tests/test_inference_service_history_v2_vectors.py` evaluates every case with the evaluator
of `test_inference_service_history_v0_vectors.py`. It requires each expected status to equal the
`/0` set's for the same case id, and regenerates the directory byte for byte. The Rust and Go
vector tests check the cases with their own libraries.
