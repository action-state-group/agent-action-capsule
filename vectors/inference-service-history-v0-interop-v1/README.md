# Inference-Service History v0 over evidence-interop/1: conformance vectors

These are the cases of `vectors/inference-service-history-v0/` with every request and envelope
naming `evidence-interop/1` (`spec/interop-profile-v1.md`, ER -02) instead of `evidence-interop/0`,
plus one more: `refused-capacity-exceeded`, a History the node declines for its own load,
refused `capacity_exceeded` and mapped `UNKNOWN` (IP v1 §8.1). The profile serves a History under
either identifier, negotiated per request (IP §3.3); its "Interop profile revision" paragraph says
so. Definitions, Histories, their digests and the test keys are the same in both sets, so every
definition still names `vectors/inference-service-history-v0/README.md`, which describes the cases.

`python/scripts/generate_inference_service_history_v0_vectors.py --profile 1` writes every file
except this README. `python/tests/test_inference_service_history_v0_interop_v1_vectors.py` runs
the checks of `test_inference_service_history_v0_vectors.py` against this set, regenerates it and
requires it to be byte-identical to the committed files. The `evidence-interop/0` set is frozen.
