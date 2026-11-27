#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs locally what CI runs on pull requests and main, every workflow in
# full whatever its paths filter: python.yml, conformance.yml, vectors.yml,
# schemas.yml, spec.yml, vector-index.yml, adapter-erc8183.yml,
# evidence-commitment-carriers.yml, nostr-mailbox.yml,
# changelog-fragments.yml, publish-python.yml's build job, dco.yml (on the
# commits not yet on origin/main) and neutrality.yml's scanner self-test.
# The neutrality and leak-lint scans themselves read their term lists from
# repository secrets; they run here only when NEUTRALITY_TERMS and
# LEAK_LINT_TERMS are set in the environment. Not run: spec.yml's idnits
# (non-gating in CI). Needs uv (Python 3.9 and
# 3.12), Go, npm (Node 22 comes through npx), the current stable Rust with
# rustfmt and clippy, as CI installs (`rustup update stable` if older), and
# Ruby's gem (kramdown-rfc is installed into a temporary directory).
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"

# The vector generators and `go mod tidy` rewrite these paths and then compare
# them with HEAD, so uncommitted work there would be overwritten or reported
# as drift. Refuse to start until it is committed.
regenerated=(vectors provenance-mode-vectors go/go.mod go/go.sum)
if [ -n "$(git status --porcelain --untracked-files=all -- "${regenerated[@]}")" ]; then
  git status --short -- "${regenerated[@]}" >&2
  echo "check.sh rewrites ${regenerated[*]}: commit or stash these changes first" >&2
  exit 1
fi
tmp="$(mktemp -d)"
# Each parallel lane runs in its own process group (set -m below), so an
# interrupted or failed run stops every lane and its builds before the
# temporary directory goes away.
lane_pids=()
cleanup() {
  local pid
  for pid in ${lane_pids[@]+"${lane_pids[@]}"}; do
    kill -TERM -- "-$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# dco.yml, on this branch's commits that origin/main lacks.
if git rev-parse --verify -q origin/main > /dev/null; then
  .github/scripts/check_dco.sh "$(git merge-base origin/main HEAD)" HEAD
else
  echo "check.sh: no origin/main; DCO check skipped" >&2
fi

# CI runs Node 22. Use it here too, fetched through npx: Playwright's browser
# download in browser-conformance.mjs hangs while unpacking under Node 26.
node22="$(npx -y -p node@22 -c 'dirname "$(command -v node)"' < /dev/null)"
export PATH="$node22:$PATH"
node --version

venv() { # venv <name> <python> <uv pip install args...>
  local name="$1" py="$2"
  shift 2
  uv venv -q -p "$py" "$tmp/$name"
  VIRTUAL_ENV="$tmp/$name" uv pip install -q "$@"
}
unchanged() { # unchanged <path>: a regenerated corpus matches the committed one
  local status
  status="$(git status --porcelain -- "$1")"
  if [ -n "$status" ]; then
    echo "$status"
    git diff --stat -- "$1"
    echo "regeneration does not reproduce the committed $1" >&2
    exit 1
  fi
}

# Lanes run in parallel, each logging to its own file; a failed lane's log is
# printed at the end. Shared inputs are prepared first, serially: the
# editable installs all write python/*.egg-info, and `npm ci` replaces
# ts/node_modules, which later steps read. Steps that rewrite tracked files
# (vector regeneration) run last, alone, so no lane reads a corpus while it is
# rewritten.
lanes() { # lanes <name>...: run lane_<name> functions in parallel
  local name failed=()
  local -a names=() pids=() starts=()
  set -m
  for name in "$@"; do
    ( "lane_$name" ) > "$tmp/log.$name" 2>&1 &
    names+=("$name"); pids+=("$!"); starts+=("$SECONDS"); lane_pids+=("$!")
  done
  set +m
  local i
  for i in "${!pids[@]}"; do
    if wait "${pids[$i]}"; then
      echo "ok    ${names[$i]} ($((SECONDS - starts[i]))s)"
    else
      echo "FAIL  ${names[$i]} ($((SECONDS - starts[i]))s)"
      failed+=("${names[$i]}")
    fi
  done
  lane_pids=()
  if [ "${#failed[@]}" -gt 0 ]; then
    for name in "${failed[@]}"; do
      echo "===== lane $name log ====="
      cat "$tmp/log.$name"
    done
    exit 1
  fi
}

# Setup, serial.
for py in 3.9 3.12; do
  venv "py$py" "$py" -e "python[dev,transparent,anchor]"
  VIRTUAL_ENV="$tmp/py$py" uv pip install -q "checkpointed-local-log>=0.9,<0.10"
done
venv bundle 3.12 -e "python[dev,bundle]"
venv schemas 3.12 -e python jsonschema
venv spec 3.12 "xml2rfc==3.34.1"
venv index 3.12 pytest
venv drift 3.12 -e "python[dev]" jsonschema
venv build 3.12 build twine
gem install --no-document --silent --install-dir "$tmp/gems" kramdown-rfc
(cd ts && npm ci)

# python.yml, on Python 3.9 and 3.12.
lane_python() { # lane_python <version>
  local py="$tmp/py$1/bin/python"
  "$py" -c "import cll.checkpoint, cll.checkpoint.index"
  (cd python && "$py" -m ruff check . && "$py" -m pytest -q)
  "$py" -m pytest -q .github/test_leak_lint.py
  "$py" -m pytest -q .github/test_release.py
}
lane_py39() { lane_python 3.9; }
lane_py312() { lane_python 3.12; }

# conformance.yml conformance: the Python reference with the bundle extra.
lane_bundle() {
  (cd python && "$tmp/bundle/bin/python" -m ruff check . && "$tmp/bundle/bin/python" -m pytest -q)
}

# conformance.yml conformance: Go.
lane_go() {
  cd go
  export GOWORK=off
  test -z "$(gofmt -l .)"
  go mod tidy
  git diff --exit-code -- go.mod go.sum
  go vet ./...
  go test ./...
  go test -race ./...
  go run ./cmd/vector_runner/
}

# conformance.yml rust-conformance, and conformance's interlock adapter build.
lane_rust() {
  cd rust
  cargo build --locked --features agent-action-capsule/strict --example cross_language
  cargo fmt --check
  cargo clippy --locked --all-targets --all-features -- -D warnings
  cargo clippy --locked --all-targets -- -D warnings
  cargo test --locked --all-features
  cargo test --locked
  for features in "--no-default-features" "--no-default-features --features receipt" "--no-default-features --features cll" "--no-default-features --features acceptance"; do
    # shellcheck disable=SC2086
    cargo clippy --locked -p evidence-request --all-targets $features -- -D warnings
    # shellcheck disable=SC2086
    cargo test --locked -p evidence-request $features
  done
  if cargo tree --locked -p evidence-request --no-default-features -e normal | grep -q checkpointed-local-log; then
    echo "evidence-request's core depends on checkpointed-local-log" >&2; exit 1
  fi
  for features in "--no-default-features --features bundle" "--no-default-features --features strict" "--no-default-features --features settlement" "--no-default-features --features inference-history"; do
    # shellcheck disable=SC2086
    cargo clippy --locked -p agent-action-capsule --all-targets $features -- -D warnings
    # shellcheck disable=SC2086
    cargo test --locked -p agent-action-capsule $features
  done
  cargo test --locked --all-features --features serde_json/preserve_order
  "$tmp/bundle/bin/python" ../.github/scripts/check_crate_metadata.py agent-action-capsule/Cargo.toml evidence-request/Cargo.toml
  cargo package --locked -p agent-action-capsule
  cargo package --locked --list -p evidence-request
  cargo package --locked -p evidence-request
  cargo publish --locked --dry-run -p evidence-request
}

# conformance.yml conformance (TypeScript) and browser-conformance.
lane_ts() {
  (cd ts && npm run check && npm run build)
  scripts/browser-conformance.mjs
}

# conformance.yml pinned-legacy-format-2-verification, on a clean Python.
lane_legacy() {
  git clone -q "$root" "$tmp/legacy"
  git -C "$tmp/legacy" checkout -q legacy-verify/v0.1.0
  uv venv -q -p 3.12 "$tmp/bare"
  cd "$tmp/legacy"
  export PYTHONPATH="$tmp/legacy/python"
  "$tmp/bare/bin/python" -c 'from agent_action_capsule.cli import main; raise SystemExit(main(["verify", __import__("sys").argv[1], "--json"]))' \
    docs/interop/purchase-example/capsule.json > "$tmp/legacy-format-2-result.json"
  "$tmp/bare/bin/python" - "$tmp/legacy-format-2-result.json" <<'PY'
import json
import sys
from pathlib import Path

result = json.loads(Path(sys.argv[1]).read_text())
capsule = json.loads(Path("docs/interop/purchase-example/capsule.json").read_text())
vector = json.loads(Path("docs/interop/aac-aep-scitt-digest-binding-vector.json").read_text())
expected_id = vector["positive"]["capsule_id"]["hex"]
assert result["ok"] is True
assert result["capsule_id_recomputed"] == capsule["capsule_id"] == expected_id
PY
}

# spec.yml: rebuild the gating draft and compare with the tracked artifacts.
lane_spec() {
  cd spec
  export GEM_HOME="$tmp/gems" GEM_PATH="$tmp/gems" PATH="$tmp/gems/bin:$tmp/spec/bin:$PATH"
  # A copy of the committed reference cache with fresh times, as in CI's new
  # checkout: kramdown-rfc refetches entries older than an hour, and the
  # copy keeps it from rewriting the tracked files.
  cp -R .refcache "$tmp/refcache"
  export KRAMDOWN_REFCACHEDIR="$tmp/refcache"
  DRAFT=$(grep '^DRAFT[[:space:]]*=' Makefile | sed 's/^DRAFT[[:space:]]*=[[:space:]]*//')
  build="$tmp/spec-build"
  mkdir -p "$build"
  kramdown-rfc "$DRAFT.md" > "$build/.draft.v2.xml"
  xml2rfc --v2v3 "$build/.draft.v2.xml" -o "$build/$DRAFT.xml"
  xml2rfc --text --v3 "$build/$DRAFT.xml" -o "$build/$DRAFT.txt"
  strip_xml() {
    sed '/<!-- ##markdown-source:/,/-->/d' | \
    grep -v 'generated by.*kramdown-rfc' | \
    sed 's/<date year="[^"]*" month="[^"]*" day="[^"]*"\/>/<date\/>/g'
  }
  strip_txt() {
    sed \
      -e 's/^Expires: [0-9][0-9]* [A-Za-z][A-Za-z]* [0-9][0-9][0-9][0-9]/Expires: DATE_NORM/' \
      -e 's/expire on [0-9][0-9]* [A-Za-z][A-Za-z]* [0-9][0-9][0-9][0-9]/expire on DATE_NORM/' \
      -e 's/Expires [0-9][0-9]* [A-Za-z][A-Za-z]* [0-9][0-9][0-9][0-9]  *\[Page/Expires DATE_NORM [Page/' \
      -e 's/^\(Intended status:.*[A-Za-z]\)  *[0-9][0-9]* [A-Za-z][A-Za-z]* [0-9][0-9][0-9][0-9] *$/\1 DATE_NORM/' \
      -e '/^ *[0-9][0-9]* [A-Za-z][A-Za-z]* [0-9][0-9][0-9][0-9] *$/s/.*/DATE_NORM/' \
      -e '/DATE_NORM/s/  */ /g'
  }
  diff <(strip_xml < "$DRAFT.xml") <(strip_xml < "$build/$DRAFT.xml") \
    || { echo "STALE: $DRAFT.xml is out of date — run 'make' locally and commit"; exit 1; }
  diff <(strip_txt < "$DRAFT.txt") <(strip_txt < "$build/$DRAFT.txt") \
    || { echo "STALE: $DRAFT.txt is out of date — run 'make' locally and commit"; exit 1; }
  grep -q 'version="3"' "$build/$DRAFT.xml"
  "$tmp/spec/bin/python" check_verdict_class_refs.py
  "$tmp/spec/bin/python" check-verification-display-terms.py --self-test
  "$tmp/spec/bin/python" check-verification-display-terms.py
}

# schemas.yml, vector-index.yml, changelog-fragments.yml and neutrality.yml's
# scanner self-test: read-only checks.
lane_misc() {
  (cd vectors/evidence-result && shasum -a 256 -c SHA256SUMS)
  "$tmp/schemas/bin/python" schemas/check_evidence_result_examples.py
  "$tmp/schemas/bin/python" schemas/check_evidence_plan_ir_examples.py
  (cd vectors/evidence-dataset && shasum -a 256 -c SHA256SUMS)
  "$tmp/schemas/bin/python" schemas/check_evidence_dataset_examples.py
  "$tmp/schemas/bin/python" schemas/check_judge_record_examples.py
  "$tmp/schemas/bin/python" schemas/check_judgment_extension_examples.py
  "$tmp/schemas/bin/python" schemas/check_contract_report_examples.py
  "$tmp/schemas/bin/python" schemas/check_evidence_contract_examples.py
  "$tmp/index/bin/python" scripts/check_vector_index.py
  "$tmp/index/bin/python" -m pytest -q scripts/test_check_vector_index.py scripts/test_run_vectors.py
  "$tmp/index/bin/python" .github/changelog_fragments.py check
  (cd .github && "$tmp/index/bin/python" -m unittest -v test_changelog_fragments)
  "$tmp/index/bin/python" .github/neutrality_scan.py --self-test
  # neutrality.yml and leak-lint.yml scans, when their secret term lists are
  # in the environment.
  if [ -n "${NEUTRALITY_TERMS:-}" ]; then
    NEUTRALITY_REVEAL=1 "$tmp/index/bin/python" .github/neutrality_scan.py .
  fi
  if [ -n "${LEAK_LINT_TERMS:-}" ]; then
    LEAK_LINT_REVEAL=1 "$tmp/index/bin/python" .github/leak_lint.py .
  fi
}

lanes py39 py312 bundle go rust ts legacy spec misc

# The interlocks need the Go, TypeScript and Rust builds above. They run
# python3 from PATH.
PATH="$tmp/bundle/bin:$PATH" scripts/cross-language-interlock.sh
PATH="$tmp/bundle/bin:$PATH" scripts/evidence-request-interlock.sh
PATH="$tmp/bundle/bin:$PATH" AAC_INTERLOCK_INJECT_CANONICALIZATION_DIVERGENCE=1 scripts/cross-language-interlock.sh

# vectors.yml: regenerate and require the committed corpus.
"$tmp/bundle/bin/python" python/scripts/generate_all_vectors.py
unchanged vectors
unchanged provenance-mode-vectors

# adapter-erc8183.yml, evidence-commitment-carriers.yml, nostr-mailbox.yml.
"$tmp/drift/bin/python" python/scripts/generate_adapter_erc8183_vectors.py
unchanged vectors/adapters/erc-8183
(cd vectors/adapters/erc-8183 && shasum -a 256 -c SHA256SUMS)
(cd python && "$tmp/drift/bin/python" -m pytest -q tests/test_adapter_erc8183_vectors.py)
(cd examples/erc8183-base-sepolia && uv run erc8183_job.py check-vectors)
"$tmp/drift/bin/python" python/scripts/generate_evidence_commitment_carriers_vectors.py
unchanged vectors/adapters/evidence-commitment-carriers
(cd vectors/adapters/evidence-commitment-carriers && shasum -a 256 -c SHA256SUMS)
(cd python && "$tmp/drift/bin/python" -m pytest -q tests/test_evidence_commitment_carriers_vectors.py)
"$tmp/drift/bin/python" python/scripts/generate_nostr_mailbox_vectors.py
unchanged vectors/adapters/nostr-mailbox
(cd vectors/adapters/nostr-mailbox && shasum -a 256 -c SHA256SUMS)
(cd python && "$tmp/drift/bin/python" -m pytest -q tests/test_nostr_mailbox_vectors.py)

# publish-python.yml build. Last: it writes python/build and the egg-info.
(cd python && rm -rf "$tmp/dist" && "$tmp/build/bin/python" -m build --outdir "$tmp/dist" && "$tmp/build/bin/python" -m twine check "$tmp/dist"/*)
for terms in NEUTRALITY_TERMS LEAK_LINT_TERMS; do
  [ -n "${!terms:-}" ] || echo "check.sh: $terms unset, so its scan was not run here; CI runs it"
done
echo "check.sh: all checks passed (${SECONDS}s)"
