# Evidence Bundle `composed/v1` vectors (proposed)

These vectors cover the proposed `composed/v1` Evidence Bundle extension
("The composed/v1 Extension", drafted for
`draft-mih-zhang-agent-disclosure-bundle-01`). The section is not yet in the
draft and the kind is not registered. The vectors are held with the
proposal so that the text and the vectors are reviewed together.

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

Each member's three completeness claims (graph closure, interval coverage,
per-record membership) are reported per member and never merged into the
outer Bundle's claims or into composition closure.

## Regenerating

```bash
python3 python/scripts/generate_bundle_composed_vectors.py
```

The run is deterministic. All keys are test-only seeds derived from fixed
labels and listed in `vectors.json`; none is a production key.
