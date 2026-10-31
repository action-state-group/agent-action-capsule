#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
# seal-input.json is the released -04 fixture; seal-input-v05.json is its -05 twin.
fixtures=("$repo/vectors/cross-language/seal-input.json" "$repo/vectors/cross-language/seal-input-v05.json")
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
rust_example() { cargo run --quiet --locked --manifest-path "$repo/rust/Cargo.toml" --features agent-action-capsule/strict --example cross_language -- "$@"; }
seal_rust() { rust_example seal; }
verify_rust() { rust_example verify; }
produce_bundle_python() { "$python_bin" "$repo/python/scripts/cross_language.py" bundle-produce "$1"; }
verify_bundle_python() { "$python_bin" "$repo/python/scripts/cross_language.py" bundle-verify; }
produce_bundle_go() { (cd "$repo/go" && GOWORK=off go run ./cmd/cross_language bundle-produce "$1"); }
verify_bundle_go() { (cd "$repo/go" && GOWORK=off go run ./cmd/cross_language bundle-verify); }
produce_bundle_ts() { node "$repo/ts/dist/cross-language.js" bundle-produce "$1"; }
verify_bundle_ts() { node "$repo/ts/dist/cross-language.js" bundle-verify; }
produce_bundle_rust() { rust_example bundle-produce "$1"; }
verify_bundle_rust() { rust_example bundle-verify; }

languages=(python go ts rust)

# With the injected divergence, Python seals a capsule whose capsule_id was
# computed by a defective canonicalizer. Every consumer must reject it as a
# capsule_id_mismatch, each asserted on its own, so one consumer that accepts
# it fails the probe even when the others reject it.
if test "${AAC_INTERLOCK_INJECT_CANONICALIZATION_DIVERGENCE:-}" = 1; then
  accepted=()
  for fixture in "${fixtures[@]}"; do
    seal_python < "$fixture" > "$work/divergent.json"
    for consumer in "${languages[@]}"; do
      if "verify_$consumer" < "$work/divergent.json" > /dev/null 2> "$work/$consumer.err"; then
        accepted+=("$consumer accepted $(basename "$fixture")")
      elif grep -q capsule_id_mismatch "$work/$consumer.err"; then
        printf '%s rejected the divergent %s: capsule_id_mismatch\n' "$consumer" "$(basename "$fixture")"
      else
        accepted+=("$consumer failed on $(basename "$fixture") without capsule_id_mismatch: $(cat "$work/$consumer.err")")
      fi
    done
  done
  if test "${#accepted[@]}" -gt 0; then
    printf '%s\n' "${accepted[@]}" >&2
    exit 1
  fi
  exit 0
fi

for fixture in "${fixtures[@]}"; do
  printf '%s\n' "$(basename "$fixture"):"
  for producer in "${languages[@]}"; do
    "seal_$producer" < "$fixture" > "$work/$producer.json"
  done

  python_id=$(verify_python < "$work/python.json")
  for producer in "${languages[@]}"; do
    for consumer in "${languages[@]}"; do
      actual=$("verify_$consumer" < "$work/$producer.json")
      test "$actual" = "$python_id"
      printf '%s-sealed -> %s-verified: %s\n' "$producer" "$consumer" "$actual"
    done
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

# Evidence Bundle producer: every implementation builds the same three Bundles
# from one checkpointed log of signed records, and a one-byte change of its
# whole-log Bundle; every implementation's strict verifier reads all of them.
# The three built Bundles must also be the same JCS bytes in every language.
# The same holds for a log whose range covers padding leaves (Bundle -02,
# non_record_leaves): its whole-log Bundle, and a one-byte change of a carried
# padding record that the range proof does not cover.
bundle_fixture="$repo/vectors/cross-language/bundle-producer-log.json"
padded_fixture="$repo/vectors/cross-language/bundle-producer-padded-log.json"
bundle_kinds=(whole-log suffix producer-selected tampered padded-whole-log padded-tampered)
built_kinds=(whole-log suffix producer-selected padded-whole-log)
expected_verdict() {
  case "$1" in
    whole-log | suffix | padded-whole-log) echo VALID ;;
    producer-selected) echo INCOMPLETE ;;
    tampered | padded-tampered) echo INVALID ;;
  esac
}
# flip_after <marker> <file>: flip the first hex digit after marker, one byte
# of the JSON text.
flip_after() {
  "$python_bin" -c '
import sys

marker, path = sys.argv[1].encode(), sys.argv[2]
text = open(path, "rb").read()
at = text.index(marker) + len(marker)
flipped = b"1" if text[at:at + 1] == b"0" else b"0"
sys.stdout.buffer.write(text[:at] + flipped + text[at + 1:])
' "$1" "$2"
}
for producer in "${languages[@]}"; do
  for kind in whole-log suffix producer-selected; do
    "produce_bundle_$producer" "$kind" < "$bundle_fixture" > "$work/bundle-$producer-$kind.json"
  done
  # Flip the first hex digit of the first body_digest: one byte of the JSON
  # text, which the range proof no longer covers.
  flip_after '"body_digests":["' "$work/bundle-$producer-whole-log.json" > "$work/bundle-$producer-tampered.json"
  "produce_bundle_$producer" padded-whole-log < "$padded_fixture" > "$work/bundle-$producer-padded-whole-log.json"
  # Flip the first hex digit of the first padding record's store_nonce: its
  # recomputed capsule_id no longer matches (non_record_leaf_mismatch).
  flip_after '"store_nonce":"' "$work/bundle-$producer-padded-whole-log.json" > "$work/bundle-$producer-padded-tampered.json"
done

mismatches=()
for kind in "${built_kinds[@]}"; do
  for producer in go ts rust; do
    if cmp -s "$work/bundle-python-$kind.json" "$work/bundle-$producer-$kind.json"; then
      printf '%s-built %s Bundle: JCS byte-identical to python-built\n' "$producer" "$kind"
    else
      mismatches+=("$producer-built $kind Bundle differs from python-built")
    fi
  done
done

for producer in "${languages[@]}"; do
  for kind in "${bundle_kinds[@]}"; do
    want=$(expected_verdict "$kind")
    for consumer in "${languages[@]}"; do
      got=$("verify_bundle_$consumer" < "$work/bundle-$producer-$kind.json")
      printf '%s-built %s -> %s strict: %s\n' "$producer" "$kind" "$consumer" "$got"
      if test "$got" != "$want"; then
        mismatches+=("$producer-built $kind -> $consumer strict: $got, expected $want")
      fi
    done
  done
done
if test "${#mismatches[@]}" -gt 0; then
  printf '%s\n' "${mismatches[@]}" >&2
  exit 1
fi

# Evidence Bundle -02 composed/v1 controller_binding block: every implementation
# derives each join of every vectors/bundle/composed-controller-binding case
# (the binding record verified through that language's one binding verifier)
# and prints the same JCS line.
composed_cases="$repo/vectors/bundle/composed-controller-binding/vectors.json"
composed_ids=$("$python_bin" -c '
import json
import sys

for case in json.load(open(sys.argv[1]))["cases"]:
    print(case["id"])
' "$composed_cases")
composed_input() {
  "$python_bin" -c '
import json
import sys

case = next(c for c in json.load(open(sys.argv[1]))["cases"] if c["id"] == sys.argv[2])
json.dump({k: case[k] for k in ("container", "controller_bindings", "binding_revocations")}, sys.stdout)
' "$composed_cases" "$1"
}
composed_python() { "$python_bin" "$repo/python/scripts/cross_language.py" composed-verify; }
composed_go() { (cd "$repo/go" && GOWORK=off go run ./cmd/cross_language composed-verify); }
composed_ts() { node "$repo/ts/dist/cross-language.js" composed-verify; }
composed_rust() { rust_example composed-verify; }
composed_mismatches=()
for id in $composed_ids; do
  composed_input "$id" > "$work/composed-input.json"
  composed_python < "$work/composed-input.json" > "$work/composed-python.out"
  for consumer in go ts rust; do
    "composed_$consumer" < "$work/composed-input.json" > "$work/composed-$consumer.out"
    if cmp -s "$work/composed-python.out" "$work/composed-$consumer.out"; then
      printf 'composed/v1 controller_binding %s: %s agrees with python\n' "$id" "$consumer"
    else
      composed_mismatches+=("composed/v1 controller_binding $id: $consumer differs from python")
    fi
  done
done
if test "${#composed_mismatches[@]}" -gt 0; then
  printf '%s\n' "${composed_mismatches[@]}" >&2
  exit 1
fi
