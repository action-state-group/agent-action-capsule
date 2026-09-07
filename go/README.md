# AAC Go reference library

The Go packages implement AAC identity, Class 1 verification and detached
Producer Envelopes. The specification is in `../spec/`.

## Cross-record references

Draft-04 `references[]` uses CPB typed digest references. The registered AAC
artifact type is `agent-action-capsule`; it must not be confused with an
emitter's local composition-member token `capsule`.

Class 1 validates reference structure and rejects an AAC/SHA-256 citation of
the same target as `chain.parent_capsule_id`. A missing external target does
not break the chain. Unknown citation purposes remain informational; callers
can supply additional known values through the existing registry argument.
The CPB artifact definition owns foreign digest representations.

`log_coordinates`, if supplied, must be an object containing `log_id`,
`leaf_index` and `inclusion_proof` together. The coordinates and proof contents
are recorded, not independently verified. They do not upgrade assurance.
Vintage format-2 extension handling is unchanged.

## Provisional registry diagnostics

`registries/data/cpb_provisional.json` is copied byte-for-byte from
`../python/agent_action_capsule/data/cpb_provisional.json` (relative to this
directory). Keep both files synchronized when refreshing the source snapshot.
Its provenance identifies the CPB source commit and snapshot hash. Known
provisional values produce `known_provisional_registry_value`, an informational
finding. This classification never grants authority or increases assurance.

## Verification

```sh
go test ./...
go vet ./...
go test -race ./...
```

`verify/testdata/references.json` is available for downstream emitters to reuse.
Its identity and canonical bytes come from unmodified Python 0.2.0 primitives;
its structural outcomes come from draft-04 §5.5.5. Python 0.2.0 does not yet
enforce those reference checks. `verify/testdata/vocabulary.json` instead freezes
Python verifier outcomes, including diagnostics and derived assurance.
The adjacent generator scripts require that Python package and run locally
without network or signing side effects.
