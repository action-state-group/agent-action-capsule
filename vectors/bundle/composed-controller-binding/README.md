# Evidence Bundle `composed/v1`: `controller_binding` join vectors

These vectors cover the `controller_binding` join basis that
`draft-mih-zhang-agent-disclosure-bundle-02` defines in its `composed/v1`
section: "Controller Binding Records" (the binding record, its signing input
and binding digest, revocation statements, when a binding applies) and
"Joins" (the derivation). The -02 revision is held for ratification; the text
and these vectors are reviewed together.

A binding record is a JSON object in which the holders of two Ed25519 keys
both sign one statement about how the keys are related. Each case delivers
its binding records in `controller_bindings` and its revocation statements in
`binding_revocations`, beside the containing Bundle. Neither is part of the
Bundle: the block binds a record only through a join's `identifier_digest`,
the binding digest

    lowercase hex SHA-256( UTF-8( JCS( binding record without sigs ) ) )

Each join selects each root record's `key_id` with `pointer` (`/key_id`). The
members are linked when a delivered record with that digest applies: it is
well formed, both bound keys signed it in the order of `keys`, its two `keys`
are the two selected values, both root records' `timestamp` values fall in
`[not_before, not_after)`, and no delivered revocation statement that applies
to it has `revoked_at` at or before either time. The verifier then compares
as for any basis. A derived `agree` is always `redundant` with reason
`controller_binding`, never corroborating: the key holders have stated that
their keys are not independent issuers.

## Cases (`vectors.json`)

| id | delivered | declared | derived | block | corroboration |
|---|---|---|---|---|---|
| `controller-binding-linked` | the binding | `agree` | `agree` | `pass` | `redundant` (`controller_binding`) |
| `controller-binding-revoked-unjoined` | the binding, a revocation before both records | `unjoined` | `unjoined` | `pass` | not applicable |
| `controller-binding-not-derivable` | nothing | `agree` | not derivable | `withheld` | not applicable |
| `controller-binding-revoked-declared-agree` | the binding, a revocation before both records | `agree` | `unjoined` | `fail` (`join_state_mismatch`) | not applicable |
| `controller-binding-one-key-signs-both` | a binding whose two `sigs` are both by responder-a's key | `unjoined` | `unjoined` | `pass` | not applicable |
| `controller-binding-other-keys` | a binding over responder-a's key and another key | `unjoined` | `unjoined` | `pass` | not applicable |
| `controller-binding-outside-window` | a binding whose `not_after` falls between the two records' times | `unjoined` | `unjoined` | `pass` | not applicable |
| `controller-binding-method-not-implemented` | a binding whose `method` is `x-example-method/0` | `agree` | not derivable | `withheld` | not applicable |

The observers are in separate custody domains and the root records carry
different keys in every case, so in `controller-binding-linked` only the
binding makes the pair redundant. The members, each one record at closure
depth 0 with no certificate, report graph closure `pass` and the other two
claims `withheld`.

The Python test (`python/tests/test_bundle_composed_cb_vectors.py`) rederives
every expectation independently of the generator; the Go reference
(`go/bundle/composed_binding.go`) runs every case. TypeScript and Rust do not
yet implement the basis and read a block that carries it as malformed, as
-01 does.

## Regenerating

```bash
python3 python/scripts/generate_bundle_composed_cb_vectors.py
```

The run is deterministic. The keys are the test-only seeds of
`vectors/bundle/composed/`, listed in `vectors.json`.
