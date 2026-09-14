#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
fixture="$repo/vectors/cross-language/seal-input.json"
disclosure_fixture="$repo/vectors/disclosure-envelope/pos-disclosure-envelope-nested-input/input.json"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

python_bin=python3
if test -x "$repo/python/.venv-review/bin/python"; then
  python_bin="$repo/python/.venv-review/bin/python"
else
  # Prefer the checkout under test when the package has not been installed.
  export PYTHONPATH="$repo/python${PYTHONPATH:+:$PYTHONPATH}"
fi

seal_python() {
  "$python_bin" "$repo/python/scripts/cross_language.py" seal |
    if test "${AAC_INTERLOCK_INJECT_CANONICALIZATION_DIVERGENCE:-}" = 1; then
      "$python_bin" -c '
import json
import sys
from agent_action_capsule import compute_capsule_id

capsule = json.load(sys.stdin)

def defective_canonicalizer(value, depth=0):
    if isinstance(value, dict):
        # Model the historical failure mode: nested object keys disappear.
        return {} if depth else {key: defective_canonicalizer(item, 1) for key, item in value.items()}
    if isinstance(value, list):
        return [defective_canonicalizer(item, depth + 1) for item in value]
    return value

capsule["capsule_id"] = compute_capsule_id(defective_canonicalizer(capsule))
json.dump(capsule, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
'
    else
      cat
    fi
}
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

cat > "$work/disclosure-go.go" <<'EOF'
package main

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/action-state-group/agent-action-capsule/go/disclosure"
)

func main() {
  decoder := json.NewDecoder(os.Stdin)
  decoder.UseNumber()
  var value map[string]interface{}
  if err := decoder.Decode(&value); err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(2)
  }
  switch os.Args[1] {
  case "build":
    capsule, capsuleOK := value["capsule"].(map[string]interface{})
    disclosures, disclosuresOK := value["disclosures"].(map[string]interface{})
    if !capsuleOK || !disclosuresOK {
      fmt.Fprintln(os.Stderr, "fixture must contain capsule and disclosures objects")
      os.Exit(2)
    }
    envelope, err := disclosure.Build(capsule, disclosures)
    if err != nil {
      fmt.Fprintln(os.Stderr, err)
      os.Exit(1)
    }
    if err := json.NewEncoder(os.Stdout).Encode(envelope); err != nil {
      fmt.Fprintln(os.Stderr, err)
      os.Exit(2)
    }
  case "verify":
    result := disclosure.Verify(value, nil)
    if !result.OK() {
      fmt.Fprintln(os.Stderr, result.DisclosureFindings)
      os.Exit(1)
    }
  default:
    fmt.Fprintln(os.Stderr, "usage: disclosure-go build|verify")
    os.Exit(2)
  }
}
EOF

cat > "$work/disclosure-ts.mjs" <<'EOF'
import { readFileSync } from "node:fs";
const aac = await import(process.argv[2]);

const command = process.argv[3];
if (command === "has-builder") {
  process.exit(typeof aac.buildDisclosureEnvelope === "function" ? 0 : 3);
}
const value = aac.decodeStrictJson(readFileSync(0));
if (command === "build") {
  const wrapper = value;
  process.stdout.write(`${JSON.stringify(await aac.buildDisclosureEnvelope(wrapper.capsule, wrapper.disclosures))}\n`);
} else if (command === "verify") {
  const result = await aac.verifyDisclosureEnvelope(value);
  if (!result.ok) process.exit(1);
} else {
  process.exit(2);
}
EOF

build_disclosure_python() {
  "$python_bin" -c '
import json
import sys
from agent_action_capsule import build_disclosure_envelope

fixture = json.load(sys.stdin)
json.dump(build_disclosure_envelope(fixture["capsule"], fixture["disclosures"]), sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
'
}
verify_disclosure_python() {
  "$python_bin" -c '
import json
import sys
from agent_action_capsule import verify_disclosure_envelope

if not verify_disclosure_envelope(json.load(sys.stdin)).ok:
    raise SystemExit(1)
'
}
build_disclosure_go() { (cd "$repo/go" && GOWORK=off go run "$work/disclosure-go.go" build); }
verify_disclosure_go() { (cd "$repo/go" && GOWORK=off go run "$work/disclosure-go.go" verify); }
build_disclosure_ts() { node "$work/disclosure-ts.mjs" "$repo/ts/dist/index.js" build; }
verify_disclosure_ts() { node "$work/disclosure-ts.mjs" "$repo/ts/dist/index.js" verify; }

disclosure_producers=(python go)
if node "$work/disclosure-ts.mjs" "$repo/ts/dist/index.js" has-builder </dev/null; then
  disclosure_producers+=(ts)
  printf '%s\n' 'TypeScript Disclosure Envelope builder detected; including it in the producer matrix.'
else
  status=$?
  test "$status" = 3 || exit "$status"
  printf '%s\n' 'TypeScript Disclosure Envelope builder not exported yet; producer row is deferred.'
fi

for producer in "${disclosure_producers[@]}"; do
  "build_disclosure_$producer" < <("$python_bin" -c '
import json
import sys
print(json.dumps(json.load(open(sys.argv[1]))["envelope"], separators=(",", ":")))
' "$disclosure_fixture") > "$work/disclosure-$producer.json"
  for consumer in python go ts; do
    "verify_disclosure_$consumer" < "$work/disclosure-$producer.json"
    printf '%s-built Disclosure Envelope -> %s DE-3 verification: pass\n' "$producer" "$consumer"
  done
done
