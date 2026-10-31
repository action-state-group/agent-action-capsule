#!/usr/bin/env bash
# Build a tarball that runs the conformance vectors in all four languages with
# no network. Needs a network once, here, to fetch dependencies.
#
#   scripts/build_offline_bundle.sh [--out DIR] [--repo PATH]...
#
# The bundle holds: a snapshot of this repository at HEAD (every vector set),
# Go and Rust dependencies vendored into it, a Python wheelhouse, an npm cache,
# and setup-offline.sh, which runs the one-time setup without a network.
# Each --repo PATH adds a snapshot of that repository's HEAD under its own name.
# Toolchains (python3, node, go, cargo) are not bundled; the target machine
# needs them. The npm cache covers macOS and Linux on x64 and arm64. The Python
# wheelhouse and the bundle are built for THIS machine's OS, CPU and Python
# minor version (compiled wheels are platform-specific); setup-offline.sh
# refuses to run elsewhere, so build one bundle per target platform.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
out="$repo/dist"
extra=()
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out=$2; shift 2 ;;
    --repo) extra+=("$(cd "$2" && pwd)"); shift 2 ;;
    *) echo "usage: $0 [--out DIR] [--repo PATH]..." >&2; exit 2 ;;
  esac
done

if ! git -C "$repo" diff --quiet HEAD -- . ; then
  echo "error: uncommitted changes; the bundle snapshots HEAD, so commit first" >&2
  exit 1
fi

mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root="$work/aac-offline-bundle"
mkdir -p "$root/deps"

echo "== snapshot: $(basename "$repo") at $(git -C "$repo" rev-parse --short HEAD)"
mkdir "$root/agent-action-capsule"
git -C "$repo" archive HEAD | tar -x -C "$root/agent-action-capsule"
for r in ${extra[@]+"${extra[@]}"}; do
  echo "== snapshot: $(basename "$r") at $(git -C "$r" rev-parse --short HEAD)"
  mkdir "$root/$(basename "$r")"
  git -C "$r" archive HEAD | tar -x -C "$root/$(basename "$r")"
done
snap="$root/agent-action-capsule"

echo "== go: vendor"
(cd "$snap/go" && GOWORK=off go mod vendor)

echo "== rust: vendor"
(cd "$snap/rust" && mkdir -p .cargo && cargo vendor --locked vendor > .cargo/config.toml)

echo "== python: wheelhouse"
py="$work/venv"
python3 -m venv "$py"
"$py/bin/pip" -q wheel --wheel-dir "$root/deps/wheelhouse" "$snap/python[dev,bundle]" jsonschema

echo "== ts: npm cache (macOS and Linux, x64 and arm64)"
for target in "darwin arm64" "darwin x64" "linux arm64" "linux x64"; do
  set -- $target
  d="$work/npm-$1-$2"; mkdir "$d"
  cp "$snap/ts/package.json" "$snap/ts/package-lock.json" "$d/"
  (cd "$d" && npm ci --ignore-scripts --no-audit --no-fund --os="$1" --cpu="$2" --cache "$root/deps/npm-cache" >/dev/null)
done

platform="$(uname -s)-$(uname -m)-py$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
echo "$platform" > "$root/PLATFORM"

cat > "$root/setup-offline.sh" <<'SETUP'
#!/usr/bin/env bash
# One-time setup, no network: Python virtualenv from the wheelhouse and the
# TypeScript dependencies from the npm cache. Go and Rust are already vendored.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
have="$(uname -s)-$(uname -m)-py$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
if [ "$have" != "$(cat "$here/PLATFORM")" ]; then
  echo "error: this bundle was built for $(cat "$here/PLATFORM") (OS-CPU-Python); this machine is $have. Build a bundle on a matching machine." >&2
  exit 1
fi
snap="$here/agent-action-capsule"
python3 -m venv "$snap/python/.venv"
"$snap/python/.venv/bin/pip" install -q --no-index --find-links "$here/deps/wheelhouse" \
  "agent-action-capsule[dev,bundle]" jsonschema
(cd "$snap/ts" && npm ci --offline --no-audit --no-fund --cache "$here/deps/npm-cache")
echo "setup done; run: python3 $snap/scripts/run_vectors.py <python|ts|go|rust>"
SETUP
chmod +x "$root/setup-offline.sh"

cat > "$root/OFFLINE.md" <<'DOC'
# Offline bundle

Needs python3, node and npm, go and cargo on the machine; no network. The bundle
is built for one OS, CPU and Python minor version (see PLATFORM); setup-offline.sh
stops on any other machine.

    ./setup-offline.sh                                                   # once
    python3 agent-action-capsule/scripts/run_vectors.py python           # or ts, go, rust
    python3 agent-action-capsule/scripts/run_vectors.py go --break-one-byte

Go and Rust run from the vendored sources in the snapshot. The first Rust run
compiles the crates, which takes a few minutes.
DOC

stamp=$(git -C "$repo" rev-parse --short HEAD)
tarball="$out/aac-offline-bundle-$stamp-$platform.tar.gz"
tar -C "$work" -czf "$tarball" aac-offline-bundle
(cd "$out" && shasum -a 256 "$(basename "$tarball")" > "$(basename "$tarball").sha256")
echo "== built $tarball ($(du -h "$tarball" | cut -f1))"
