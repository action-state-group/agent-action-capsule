# CLAUDE.md

Guidance for coding agents working in this repository: the Agent Action
Capsule Internet-Draft (`spec/`), its normative Python reference (`python/`),
the conforming Go (`go/`) and TypeScript (`ts/`) implementations, the Rust
bundle verifier (`rust/bundle/`) and the conformance vectors (`vectors/`).
Scope rules and review gates are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Commands

```bash
# python/  (Python 3.9 compatible)
pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q
python -m pytest -q ../.github/test_release.py     # release helper

# go/  (GOWORK=off)
test -z "$(gofmt -l .)" && go vet ./... && go test ./... && go test -race ./...

# ts/
npm ci && npm run check

# rust/bundle/
cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked

# repository root
scripts/cross-language-interlock.sh                 # Python, Go and TypeScript agree
```

`spec/` builds with `kramdown-rfc` and `xml2rfc`; CI fails when the built
`.xml`/`.txt` differ from the tracked artifacts. Vector directories carry
`SHA256SUMS` that CI checks.

## Rules

- The draft is the source of truth. When an implementation and the draft
  disagree, fix the implementation or raise an erratum; never let them
  silently diverge.
- `vectors/` are authoritative and shared by every implementation: a
  wire-facing change needs cross-checked evidence and negative (MUST-reject)
  vectors, and updates every implementation together.
- Keep the repository standard-only: no product, tenant or internal content.
  The leak and neutrality lints enforce this in CI.
- Commits use conventional commit messages and a DCO sign-off
  (`git commit -s`). Do not add AI attribution trailers; the `dco` check
  rejects them.

## Releases

Follow [RELEASING.md](RELEASING.md). In short: run **Prepare release**, merge
its pull request, and the Tag release workflow tags and publishes. Never
create `python/v*` or `ts/v*` tags by hand; `go/v*` tags are pushed by an
admin. Do not rename `publish-python.yml` or `publish-ts.yml`: the registries'
trusted publishers name them, so publishing breaks until the registry is
updated first. `.github/release.py` is an identical copy shared with the other
action-state-group repositories; change it in all of them together.
