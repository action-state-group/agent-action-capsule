# Evidence Bundle `composed/v1` vectors

These vectors cover the `composed/v1` Evidence Bundle extension ("The
composed/v1 Extension" in `draft-mih-zhang-agent-disclosure-bundle-01`,
registered in `spec/REGISTRY.md` §14). The -01 revision is held for
ratification; the text and the vectors are reviewed together.

A composition is an ordinary `evidence-bundle/v2` whose `extensions` carries
one `composed/v1` block. The block lists each responder's answer to an
Evidence Request as a member (an Evidence Bundle, a signed refusal or a
recorded absence), the observers that produced them, and the declared joins
between members. The composed digest is

    lowercase hex SHA-256( UTF-8( JCS( digest input ) ) )

(the CPB canonicalization algorithm `jcs`). The digest input is the object
`{kind, members, observers, joins, not_requested}`, with each array sorted
and reduced to its declared fields. Member bodies and `missing` are excluded,
so withholding a member's body never changes the digest a judgment cites.
Each case records the literal JCS preimage as `expect.canonical_preimage`.

## Cases (`vectors.json`)

| id | members | expected |
|---|---|---|
| `agree` | two artifacts, separate custody | join `agree`, derived; closure `pass`; `corroborating` (on declared custody) |
| `one-member-missing` | the same, with one Bundle not carried and listed in `missing` | same composed digest as `agree`; closure `withheld` (`declared_incomplete`); join `not_derivable`; no corroboration |
| `same-custody-redundant` | runtime and boundary observers, one custody domain | join `agree`; `redundant, not corroborating` |
| `artifact-response-bound` | `agree`, with responder-a carrying its `response` envelope | same composed digest as `agree`; the envelope's digests match the member's; signature `signature_unverified` (no deployment profile), so the block is `withheld` |
| `artifact-response-other-request` | the same, the envelope naming another request | block `fail` (`member_response_request_digest_mismatch`) |
| `agree-with-checkpoints` | `agree`, with the container and each member Bundle carrying a whole-log completeness certificate and a signed COSE checkpoint of its own log | block `pass`; every member claim `pass`; strict verdict `VALID` for the container and each member, so the full verdict is `VALID` |

An artifact member may carry `response`: the responder's signed response
envelope without the artifact bytes. Its `request_digest` must equal the
member's and its `artifact_digest` the member's digest. Its signature is
checked under the deployment's profile, as a refusal's is; a verifier with no
profile reports it `signature_unverified`. Like member bodies, the envelope is
outside the composed digest. Each case states the block's expected `status`.

Each member's three completeness claims (graph closure, interval coverage,
per-record membership) are reported per member and never merged into the
outer Bundle's claims or into composition closure.

Only `agree-with-checkpoints` reaches a full verdict of `VALID`. In the other
cases no Bundle carries a checkpoint, so a strict verifier
(`vectors/bundle/strict/README.md`) reads the container and each member as
`INCOMPLETE`. In `agree-with-checkpoints` the composer's log holds the
container's record and each responder's log holds that responder's record. Each
checkpoint is the log's first, signed as a COSE Signed Statement by that
party's key from `keys`. The case records `expect.strict` (the strict verdict of
the container and of each carried member Bundle) and `expect.verdict`. The full
verdict is `VALID` only when every strict verdict is `VALID` and the block's
`status` is `pass`. The member digests cover the certificates and checkpoints,
so its composed digest differs from `agree`'s.

## Regenerating

```bash
python3 python/scripts/generate_bundle_composed_vectors.py
```

The run is deterministic. All keys are test-only seeds derived from fixed
labels and listed in `vectors.json`; none is a production key. The generator
needs `agent-action-capsule[bundle,envelope]` (the CLL reference and
`scitt-cose`) for the checkpointed case.
