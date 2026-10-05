# Agent Action Capsule Go reference

These packages conform to the Python record-format authority in this
repository. They implement format-4 JCS and Capsule IDs, Class-1 and
`references[]` verification, every registry in `spec/REGISTRY.md` and the
disclosure eligibility table, Producer Envelopes, and Disclosure Envelopes through DE-3.

The Go code does not own producer verbs, CLL, adapters, policy, or permalink
transport. It consumes the same-commit corpora under `../vectors/`; the
cross-language CI also verifies Python-, Go-, and TypeScript-sealed Capsules in
all three implementations.

`references[]` uses CPB typed digest references. For the registered
`agent-action-capsule`/`SHA-256` context, the digest is a Capsule ID and must
not duplicate `chain.parent_capsule_id`. Missing external targets are
informational and do not become chain failures. `log_coordinates` records a
location claim; Class 1 validates its shape but does not prove inclusion.

## Registry value sets

Every registry of record in `spec/REGISTRY.md` is importable from the
`registries` package, parsed from the copy embedded at build time:

```go
import "github.com/action-state-group/agent-action-capsule/go/registries"

registries.EpistemicTypes()   // REGISTRY.md §17, draft-mih-agent-evidence-layer-00 "Epistemic Type"
registries.LinkTypes()        // REGISTRY.md §18, draft-mih-agent-evidence-layer-00 "Typed Links"
registries.ChainRelations()   // REGISTRY.md §6, chain.relation
registries.CitationPurposes() // REGISTRY.md §11, citation_purpose
vals, err := registries.Values("epistemic_type") // any name in registries.AllRegistryNames
registries.JSON()             // the generated registries.json
```

Each accessor returns a fresh slice in REGISTRY.md order. `registries.Load(path)`
parses a pinned snapshot; a registry the snapshot predates is absent from the
map, not an empty set. `data/REGISTRY.md` and `data/registries.json` are copied
by `go generate ./registries` (the JSON is produced by
`python/scripts/generate_registries_json.py`); the tests fail if either drifts,
and check that the Go parser reads REGISTRY.md to exactly the tables in the
JSON.

Name the field, never the bare string: acceptance criteria and tests say
"`chain.relation` equals `supersedes` on the approval capsule", not "the bundle
contains `supersedes`". `supersedes` is registered in both §6 and §18.

`registries.CheckVendored(vendored, registry, registryRef, ref)` checks that a
vendored value-set file (evidencebook's format) still equals the named
REGISTRY.md section at a pinned ref, and `cmd/aac-check-vendored` runs it from
CI:

```sh
go run github.com/action-state-group/agent-action-capsule/go/cmd/aac-check-vendored@v0.7.0 \
  -ref v0.7.0 schemas/vendor/epistemic-types.json
```

Without `-registry` the embedded copy is used, only when the pin is this
module's version. A pass proves the copy equals the registry at the pinned ref,
not that the pin is current. See "Checking a vendored registry copy in CI" in
the Python README for the file format and the GitHub Actions steps; the shared
cases are in `vectors/vendored-registry/`.

Run locally:

```sh
GOWORK=off gofmt -w .
GOWORK=off go mod tidy
GOWORK=off go vet ./...
GOWORK=off go test ./...
GOWORK=off go test -race ./...
GOWORK=off go run ./cmd/vector_runner/
```
