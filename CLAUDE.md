# CLAUDE.md

Guidance for coding agents working in this repository: the Agent Action
Capsule Internet-Draft (`spec/`), its normative Python reference (`python/`),
the conforming Go (`go/`), TypeScript (`ts/`) and Rust
(`rust/agent-action-capsule/`) implementations, and the conformance vectors
(`vectors/`).
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

# rust/
cargo fmt --check && cargo clippy --locked --all-targets --all-features -- -D warnings && cargo test --locked --all-features

# repository root
scripts/cross-language-interlock.sh                 # Python, Go, TypeScript and Rust agree (Python needs the bundle extra)
```

`spec/` builds with `kramdown-rfc` and `xml2rfc`; CI fails when the built
`.xml`/`.txt` differ from the tracked artifacts. Vector directories carry
`SHA256SUMS` that CI checks.

## Rules

- PRs that modify `spec/` or `vectors/`, or are used to cut a release tag,
  must receive at least one review before merge. This requirement is
  additional to all existing CI, review and principal approval gates; it
  neither replaces nor lowers them and grants no release or tag authority.
- The draft is the source of truth. When an implementation and the draft
  disagree, fix the implementation or raise an erratum; never let them
  silently diverge.
- `vectors/` are authoritative and shared by every implementation: a
  wire-facing change needs cross-checked evidence and negative (MUST-reject)
  vectors, and updates every implementation together.
- One top-level directory per language: `python/` (one package), `go/` (one
  module), `ts/` (one npm package) and `rust/` (one Cargo workspace). In
  `rust/`, `Cargo.toml` is the workspace, each crate is `rust/<crate-name>/`,
  and all crates share `rust/Cargo.lock`. Add a Rust crate as another
  workspace member, never at `rust/` itself or outside it; its
  `.github/releases.json` entry names `rust/<crate-name>/Cargo.toml` and
  `rust/Cargo.lock`. The other action-state-group repositories use the same
  Rust layout.
- Keep the repository standard-only: no product, tenant or internal content.
  The leak and neutrality lints enforce this in CI.
- A user-visible change adds a fragment `changelog.d/<short-name>.md`, not an edit to a
  CHANGELOG, so parallel pull requests never conflict there; see
  [changelog.d/README.md](changelog.d/README.md).
- Commits use conventional commit messages and a DCO sign-off
  (`git commit -s`). Do not add AI attribution trailers; the `dco` check
  rejects them.

## Releases

Follow [RELEASING.md](RELEASING.md). In short: run **Release · Prepare**, merge
its pull request, and the Release · Tag workflow tags and publishes. Never
create `python/v*`, `ts/v*` or `crates/*-v*` tags by hand; `go/v*` tags are
pushed by an admin. Do not rename `publish-python.yml`, `publish-ts.yml` or
`publish-rust.yml`: the registries' trusted publishers name them, so
publishing breaks until the registry is updated first. `.github/release.py` is an identical copy shared with the other
action-state-group repositories; change it in all of them together.
