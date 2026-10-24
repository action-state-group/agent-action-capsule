# Agent Action Capsule Go reference

These packages conform to the Python record-format authority in this
repository. They implement format-4 JCS and Capsule IDs, Class-1 and
`references[]` verification, the seven registries and disclosure eligibility
table, Producer Envelopes, and Disclosure Envelopes through DE-3.

The Go code does not own producer verbs, CLL, adapters, policy, or permalink
transport. It consumes the same-commit corpora under `../vectors/`; the
cross-language CI also verifies Python-, Go-, and TypeScript-sealed Capsules in
all three implementations.

`references[]` uses CPB typed digest references. For the registered
`agent-action-capsule`/`SHA-256` context, the digest is a Capsule ID and must
not duplicate `chain.parent_capsule_id`. Missing external targets are
informational and do not become chain failures. `log_coordinates` records a
location claim; Class 1 validates its shape but does not prove inclusion.

Run locally:

```sh
GOWORK=off gofmt -w .
GOWORK=off go mod tidy
GOWORK=off go vet ./...
GOWORK=off go test ./...
GOWORK=off go test -race ./...
GOWORK=off go run ./cmd/vector_runner/
```

## Presentation resolver

`presentation/` is the Go resolver of `spec/presentation-contract-v0.md`, the
twin of `ts/src/presentation-registry.ts`: `ParseManifest`, `Registry`
(`Register`, `List`, `Refused`, `Resolve`, `ResolveWith`), `Describe` and
`DescribeBundle` (the section 4.2 descriptor of a bundle, verified as the
TypeScript context verifies it: `bundle.VerifyBundle`, with a producer selection
the strict checks do not reject read through `bundle.VerifyStrict`; `Verified`
gives the TypeScript answer on the result `DescribeBundle` returns, not on a
plain `bundle.VerifyBundle` result), `RefusalRow` and `RefusalLine` (the section 3.2 wording),
`NewBuiltinRegistry` and `NewSectionRegistry`. Go has no module code, so
`Resolve` selects by the declarative match as if every module could render;
`ResolveWith` takes a `canRender` answer. The vectors under
`../vectors/presentation-resolution/` are normative for both implementations,
and both test suites run every case.

## Evidence Bundles

`bundle.VerifyBundle` checks a Bundle's claims and `bundle.VerifyStrict` gives
the strict verdict (`VALID`, `INCOMPLETE` or `INVALID`).
`bundle.BuildEvidenceBundle(ctx, source, opts)` builds a Bundle from a
`ProofSource`: the log's signed COSE checkpoint, its leaves, records by
Capsule ID, and inclusion and range proofs in the Bundle's wire shape. It
holds no key, and it checks the result with `VerifyStrict` before returning
it, refusing anything that verifier calls INVALID.
`bundle.ProofSourceFromCLL(backend, records)` makes a `ProofSource` from a CLL
backend (`ScanEntries`, `LoadCLL`) and a `RecordSource`.

- `IntervalFrom: N` carries every record from seq N to the checkpoint tip, and
  none below N, with a range proof: the Bundle can read VALID. `N = 1` is the
  whole log.
- `NoRange: true` carries only the chosen records, each with its own
  inclusion proof, and states `completeness.selection: "producer-selected"`:
  nothing is claimed about the records between them, so it reads INCOMPLETE.

One of the two is required, so a caller never hands over the whole log by
omission. `ClosureDepth` is a `*int` whose nil is the draft's 2. A range over
a leaf that is not a record, a carried record below N and a record past the
checkpoint are refused by name. A missing citation or an unsigned record is
stated, not refused, and reads INCOMPLETE. `bundle.BuildUnprovenBundle` is
the form with no log proof, for Capsules that belong to no log.
