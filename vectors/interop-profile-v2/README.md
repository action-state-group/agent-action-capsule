# Minimum Evidence Interoperability Profile v2 conformance vectors

These vectors exercise `spec/interop-profile-v2.md` (identifier `evidence-interop/2`), a
pre-Internet-Draft profile. Its §11.5 describes this corpus. Every case cites the sections its
expected values come from.

## Derivation

`python/scripts/generate_interop_profile_v0_vectors.py --profile 2` writes every file except this
README, with the builders, test keys and logs that write `vectors/interop-profile-v1/`. Every
expected status is written by hand from the profile text.
`python/tests/test_interop_profile_v2_vectors.py` checks the corpus from the case inputs alone,
with the independent evaluator of `test_interop_profile_v0_vectors.py` run for v2, regenerates the
directory twice and requires both runs to be byte-identical to the committed files.

`vectors/interop-profile-v0/README.md` describes the pins, the fixture formats and how to read
the expected values, and `vectors/interop-profile-v1/README.md` what v1 adds; all of it holds
here unchanged.

## What differs from the v1 corpus

- Every request, envelope, acceptance record, lifecycle statement and manifest names
  `evidence-interop/2`, so every signature over one differs.
- The version cases use `evidence-interop/1` as the other identifier:
  `unsupported-version-mismatch` asks for `evidence-interop/2` and receives an envelope naming
  `evidence-interop/1`, and `unsupported-version-unimplemented` sends `evidence-interop/1` to a
  verifier implementing only `evidence-interop/2`. `capacity-exceeded-under-v0` is checked by a
  verifier that implements `evidence-interop/0` as well.
- Thirteen cases are new, on the refusal's `policy_digest` (§6.3, P-69). The policy digests are
  `SHA-256("evidence-interop/2 vectors: responder policy file")` and
  `SHA-256("evidence-interop/2 vectors: another policy file")`.
  - `refusal-policy-digest-signed`: present and signed, every property `PASS`;
  - `refusal-policy-digest-absent`: absent, every property `PASS`;
  - `refusal-policy-digest-tampered`, `refusal-policy-digest-stripped`: replaced or removed after
    signing, `refusal_signature` `FAIL`;
  - `refusal-policy-digest-unsigned`: present under `evidence-interop/2` but outside the
    signature, `refusal_signature` `FAIL`;
  - `refusal-policy-digest-not-a-digest`: signed, but not the §5.2 digest form,
    `refusal_signature` `FAIL`;
  - `refusal-under-v1-still-verifies`: a request for `evidence-interop/1` and the ERV A7 refusal
    a v1 responder signs, checked by a verifier implementing both identifiers, every property
    `PASS`;
  - `refusal-under-v1-policy-digest-unbound`: the same with a `policy_digest` outside the
    signature, every property `PASS`; the member binds nothing;
  - `refusal-unimplemented-identifier-policy-digest-unbound`: a request for `evidence-interop/9`
    answered by an A7 refusal with a `policy_digest` outside the signature, every property `PASS`;
    the signature verified over an input that excludes the member, so it binds nothing;
  - `refusal-unimplemented-identifier-policy-digest-signed` and `-not-a-digest`: the same request
    answered with the v2 signing input over a digest (`PASS`) and over uppercase hex
    (`refusal_signature` `FAIL`, the v2 rule applying to the input that verified);
  - `refusal-under-v1-policy-digest-signed`: a request for `evidence-interop/1` answered with the
    v2 signing input, `refusal_signature` `FAIL`;
  - `refusal-policy-digest-checked-by-v1-verifier`: the signed refusal checked by a verifier that
    implements only `evidence-interop/1`, `refusal_signature` `FAIL`.

- The manifest is also fetched over HTTP (v2 §11.4.2, P-70). `carriage-invariance` carries a third
  copy, `http_well_known`: a `GET` at `/.well-known/evidence-manifest` whose body is the JCS
  serialization of the manifest. `carriage-manifest-http-differs` is new: the body is another
  manifest, so `manifest_form` is `PASS` for each copy and `manifest_consistency` is `FAIL`.
  `carriage-manifest-http-not-jcs` is new too: the body is the same manifest pretty-printed, so
  the HTTP copy's `manifest_form` is `FAIL` and `manifest_consistency` is `PASS`.
  `carriage-manifest-http-wrong-media-type` serves the JCS body as `text/plain` (same results), and
  `carriage-manifest-http-duplicate-member` repeats `subject_forms` in the body, so it does not
  parse: the HTTP copy's `manifest_form` and `manifest_consistency` are both `FAIL`.

The key seed labels and log entry labels keep their `evidence-interop/0` text, as in v1.
