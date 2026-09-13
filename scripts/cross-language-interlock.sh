#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
fixture="$repo/vectors/cross-language/seal-input.json"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

python_bin=python3
if test -x "$repo/python/.venv-review/bin/python"; then
  python_bin="$repo/python/.venv-review/bin/python"
fi

seal_python() { "$python_bin" "$repo/python/scripts/cross_language.py" seal; }
verify_python() { "$python_bin" "$repo/python/scripts/cross_language.py" verify; }
seal_go() { (cd "$repo/go" && GOWORK=off go run ./cmd/cross_language seal); }
verify_go() { (cd "$repo/go" && GOWORK=off go run ./cmd/cross_language verify); }
seal_ts() { node "$repo/ts/dist/cross-language.js" seal; }
verify_ts() { node "$repo/ts/dist/cross-language.js" verify; }

for producer in python go ts; do
  "seal_$producer" < "$fixture" > "$work/$producer.json"
done

python_id=$(verify_python < "$work/python.json")
for producer in python go ts; do
  for consumer in python go ts; do
    actual=$("verify_$consumer" < "$work/$producer.json")
    test "$actual" = "$python_id"
    printf '%s-sealed -> %s-verified: %s\n' "$producer" "$consumer" "$actual"
  done
done
