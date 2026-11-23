# Evidence Bundle `composed/v1` carried signature profile vectors

These vectors cover "Carried Signature Profiles" in
`draft-mih-zhang-agent-disclosure-bundle-03`. There are three opt-in profiles
in which a verifier checks the signature of a refusal or an artifact response
that a `composed/v1` member carries:

| Identifier | Signature | Signing input (UTF-8 of RFC 8785 JCS) |
|---|---|---|
| `three-member-refusal/v1` | `sig` under `key_id` | `{issued_at, reason, request_digest}` (the evidence-interop/0 and /1 refusal signing input) |
| `whole-refusal/v1` | `signature` under `key_id` | the refusal without `signature` |
| `digest-bound-artifact-response/v1` | `sig` under `key_id` | `{type: "evidence-artifact-response/v1", request_digest, anchor, artifact_kind, artifact_digest, issued_at}`, where `type` is supplied by the verifier |

The members present decide which profile applies, and a member that is JSON
`null` counts as present. A refusal that carries `sig` and no `signature` is in
`three-member-refusal/v1`, unless it also carries `policy_digest` (an
evidence-interop/2 refusal can sign it): such a refusal is in none of these
profiles and is `signature_unverified`. Any other refusal is in
`whole-refusal/v1`. A response that carries `responder` is in none of these
profiles and is `signature_unverified`.

The states are `verified`, `invalid` and `signature_unverified`. A signature is
`signature_unverified` only when the object carries nothing to check under these
profiles. `key_id` is 64 and a signature 128 lowercase hexadecimal characters.
Ed25519 is strict: a small-order key or R never verifies.

## Cases (`vectors.json`)

- `cases`: object cases. Each one has `kind` (`refusal` or `response`), the
  carried `object`, and `expect.profile` (`null` for an object in none of the
  profiles) and `expect.state`. A verified case also records
  `signing_input_hex`. The six forgery cases, a small-order key and an
  identity R in each profile, record `lenient_ed25519_verifies: true`: a
  lenient verifier accepts each of them, so they test strictness alone.
- `composed_cases`: a `composed/v1` container verified with both profile
  verifiers set. Each one pins the block's `status` and `findings`, and the
  member's `refusal_signature` or `response_signature`. Without the verifiers,
  every one of those member states is `signature_unverified`.

Keys are test-only seeds, listed in `keys`.

## Regenerating

```bash
python3 python/scripts/generate_bundle_composed_signature_profile_vectors.py
```

The run is deterministic and needs `cryptography`. Expected values are written
by hand from the draft text; the generator imports no implementation of the
profiles.
