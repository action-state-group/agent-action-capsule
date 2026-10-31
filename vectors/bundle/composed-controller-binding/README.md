# Evidence Bundle `composed/v1`: `controller_binding` join vectors

These vectors cover the `controller_binding` join basis that
`draft-mih-zhang-agent-disclosure-bundle-02` defines in its `composed/v1`
section: "Controller Binding Records" (the binding record, its signing input
and binding digest, revocation statements, when a binding applies) and
"Joins" (the derivation), and a join with an empty-history member
("Empty-History Bundles"). The -02 revision is held for ratification; the
text and these vectors are reviewed together.

A binding record is a JSON object in which the holders of two keys both sign
one statement about how the keys are related. -02 defines one key type,
`ed25519`, which a record without `key_types` has for both keys. Each case delivers
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
| `controller-binding-key-types-ed25519` | the binding, with `key_types` `["ed25519", "ed25519"]` | `agree` | `agree` | `pass` | `redundant` (`controller_binding`) |
| `controller-binding-key-type-not-implemented` | a binding whose `key_types` names `x-example-type` for one key | `agree` | not derivable | `withheld` | not applicable |
| `controller-binding-empty-member-linked` | the binding; responder-b is an empty-history Bundle | `one_sided` | `one_sided` | `pass` | not applicable |
| `controller-binding-empty-member-revoked` | the binding, a revocation before both times; responder-b empty | `unjoined` | `unjoined` | `pass` | not applicable |
| `controller-binding-empty-member-declared-agree` | the binding; responder-b empty | `agree` | `one_sided` | `fail` (`join_state_mismatch`) | not applicable |
| `controller-binding-empty-member-no-checkpoint` | the binding; responder-b empty, with no checkpoint | `one_sided` | not derivable | `withheld` | not applicable |

The observers are in separate custody domains and the root records carry
different keys in every case, so in `controller-binding-linked` only the
binding makes the pair redundant. The members, each one record at closure
depth 0 with no certificate, report graph closure `pass` and the other two
claims `withheld`.

In the four `empty-member` cases responder-b's member is an empty-history
Bundle: no `records`, no `root`, `records_mode` `complete`, `payloads_mode`
`none`, and no certificate. In three of them it carries its stream's first
checkpoint (`log:composed-vectors/responder-b/2`), signed by responder-b's
key. CLL has no checkpoint of size 0, so that checkpoint covers one leaf that
is not a record. The member reports graph closure `pass`, the other two
claims `withheld` (`no_records`) and `history` `{"state": "none", "since":
<the checkpoint's timestamp>}`, with `since` `null` when it carries no
checkpoint. For the join, its key is the one that signed `checkpoint.cose`
and its time is that checkpoint's `timestamp`; a linked join derives
`one_sided`, never `agree`.

The Python test (`python/tests/test_bundle_composed_cb_vectors.py`) rederives
every expectation independently of the generator, with CLL's offline
checkpoint verifier for the empty members' checkpoints; the Go reference
(`go/bundle/composed_binding.go`) runs every case, and
`python/tests/test_bundle_empty_history.py` runs the empty members through
the Python `verify_bundle`. TypeScript and Rust do not yet implement the
basis and read a block that carries it as malformed, as -01 does; they also
read an empty-history Bundle as malformed (no `root`).

## Regenerating

```bash
python3 python/scripts/generate_bundle_composed_cb_vectors.py
```

The run is deterministic. The keys are the test-only seeds of
`vectors/bundle/composed/`, listed in `vectors.json`.
