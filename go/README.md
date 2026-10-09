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
`DescribeBundle` (the section 4.2 descriptor of a bundle `bundle.VerifyBundle`
checked), `RefusalRow` and `RefusalLine` (the section 3.2 wording),
`NewBuiltinRegistry` and `NewSectionRegistry`. Go has no module code, so
`Resolve` selects by the declarative match as if every module could render;
`ResolveWith` takes a `canRender` answer. The vectors under
`../vectors/presentation-resolution/` are normative for both implementations,
and both test suites run every case.
