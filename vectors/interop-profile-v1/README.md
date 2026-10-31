# Minimum Evidence Interoperability Profile v1 conformance vectors

These vectors exercise `spec/interop-profile-v1.md` (identifier `evidence-interop/1`), a
pre-Internet-Draft profile. Its §11.5 describes this corpus. Every case cites the sections its
expected values come from.

## Derivation

`python/scripts/generate_interop_profile_v0_vectors.py --profile 1` writes every file except this
README, with the builders, test keys and logs that write `vectors/interop-profile-v0/`. Every
expected status is written by hand from the profile text.
`python/tests/test_interop_profile_v1_vectors.py` checks the corpus from the case inputs alone,
with the independent evaluator of `test_interop_profile_v0_vectors.py` run for v1, regenerates the
directory twice and requires both runs to be byte-identical to the committed files.

`vectors/interop-profile-v0/README.md` describes the pins, the fixture formats and how to read
the expected values; all of it holds here unchanged.

## What differs from the v0 corpus

- Every request, envelope, acceptance record, lifecycle statement and manifest names
  `evidence-interop/1`, so every signature over one differs. The manifest's `drafts` is
  `draft-mih-agent-evidence-request-02` (§11.4.2).
- The version cases swap the two identifiers: `unsupported-version-mismatch` asks for
  `evidence-interop/1` and receives an envelope naming `evidence-interop/0`, and
  `unsupported-version-unimplemented` sends `evidence-interop/0` to a verifier implementing only
  `evidence-interop/1`.
- Three cases are new (§6.3, §8.1, §9.1, P-65):
  - `capacity-exceeded`: a conforming `capacity_exceeded` refusal, `UNKNOWN`;
  - `request-unauthenticated`: a conforming `request_unauthenticated` refusal, `UNKNOWN`;
  - `capacity-exceeded-under-v0`: the same `capacity_exceeded` answering a request that asks for
    `evidence-interop/0`. Under v0 the token is unregistered, so `reason_registered` is `FAIL` and
    the reply is a response received and failed, `UNKNOWN`.

The key seed labels and log entry labels keep their `evidence-interop/0` text. They are labels,
not identifiers: keeping them keeps the test keys and the §10.1 log of both revisions the same.
