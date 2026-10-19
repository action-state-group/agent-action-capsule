# Evidence Layer UNDISCLOSED retention vectors

Conformance cases for the `UNDISCLOSED` retention state of
`draft-mih-agent-evidence-layer-01`, "Record/Payload Separation, Retention,
and Disclosure", "UNDISCLOSED and policy_uri".

## The rule

`UNDISCLOSED` states that the store does not say which other retention state
applies to a payload, under the policy `policy_uri` names. A record carrying
`retention_state` `UNDISCLOSED` MUST carry `policy_uri`: a URI (RFC 3986,
Section 3), not a relative reference. A reader treats an `UNDISCLOSED` state
with no `policy_uri`, or with a `policy_uri` that is not such a URI, as
malformed, and does not read it as any other state. `policy_uri` MAY
accompany any other retention state.

## The serialization these cases test

The draft fixes the header members but not a serialization. Each case's
`record` is a JSON object holding only the header members these rules read:
`retention_state`, `payload_commitments` (whose presence makes
`retention_state` REQUIRED) and, when present, `policy_uri`. The payload
digests are fixed values derived from a label, so a run is reproducible.

A string is taken to be a URI when it is a scheme (a letter, then letters,
digits, `+`, `-` or `.`), then `:`, then no whitespace. That is enough to
separate a URI from a relative reference and from an empty or non-string
value. It is not a full RFC 3986 parser, and these cases do not test one.

## Cases (`cases.json`)

A checker accepts every `positive` case and rejects every `negative` case.
`expected.reason` names the rule a negative case breaks, and `expected.member`
the member that breaks it (`policy_uri` in every case).

| Reason | Cases |
|---|---|
| (valid) | `pos-undisclosed-https`, `pos-undisclosed-urn`, `pos-undisclosed-fragment`, `pos-withheld-no-policy-uri`, `pos-withheld-with-policy-uri` |
| `missing_policy_uri` | `neg-undisclosed-missing-policy-uri` |
| `policy_uri_form` | `neg-undisclosed-policy-uri-empty`, `-relative-path`, `-network-path`, `-whitespace`, `-not-string`, `-null` |

The cases do not test the content of the policy a `policy_uri` names, or
whether it was applied; the draft defines neither. They do not test a
declaration of retention states per category of evidence, whose format the
draft does not define.

## Regenerating and checking

```bash
python3 python/scripts/generate_evidence_layer_retention_vectors.py
python -m pytest python/tests/test_evidence_layer_retention_vectors.py
```

The run is deterministic and uses no keys. The test applies the rule above to
every case, and checks that each negative case becomes valid when only its
`policy_uri` is replaced.
