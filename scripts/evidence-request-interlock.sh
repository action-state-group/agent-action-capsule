#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Evidence Request cross-language interlock (draft-mih-agent-evidence-request-00).
#
# Every implementation runs the same three steps through its stdin/stdout
# adapter, and the outputs must agree:
#
# 1. classify: every request in vectors/evidence-request/request.json, in
#    both bindings, gives the same digest, well_formed and refusal reason in
#    every language (byte-identical output).
# 2. refuse: each language signs a refusal for every request with the same
#    Ed25519 seed; Ed25519 is deterministic, so the refusals are identical.
# 3. verify: every language authenticates every other language's refusals,
#    and rejects one whose signature was tampered with.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

python_bin=python3
if test -x "$repo/python/.venv-review/bin/python"; then
  python_bin="$repo/python/.venv-review/bin/python"
fi
export PYTHONPATH="$repo/python${PYTHONPATH:+:$PYTHONPATH}"

er_python() { "$python_bin" "$repo/python/scripts/evidence_request_interlock.py" "$1"; }
er_go() { (cd "$repo/go" && GOWORK=off go run ./cmd/evidencerequest_interlock "$1"); }
er_rust() {
  cargo run --quiet --locked --manifest-path "$repo/rust/Cargo.toml" \
    -p evidence-request --no-default-features --example interlock -- "$1"
}

languages=(python go rust)

# RFC 8032 section 7.1 test 1: a published seed and its public key.
seed=9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
public=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
issued_at=2026-10-15T00:00:00Z

"$python_bin" - "$repo/vectors/evidence-request/request.json" > "$work/classify-in.json" <<'EOF'
import json, sys
cases = []
for case in json.load(open(sys.argv[1]))["cases"]:
    if "request_json" in case:
        cases.append({"id": case["id"] + "/json", "binding": "json",
                      "request_hex": case["request_json"].encode().hex()})
    if "request_cbor_hex" in case:
        cases.append({"id": case["id"] + "/cbor", "binding": "cbor",
                      "request_hex": case["request_cbor_hex"]})
print(json.dumps(cases))
EOF

for lang in "${languages[@]}"; do
  "er_$lang" classify < "$work/classify-in.json" > "$work/classify-$lang.json"
done
for lang in "${languages[@]}"; do
  if ! cmp -s "$work/classify-rust.json" "$work/classify-$lang.json"; then
    echo "evidence request: $lang classifies requests differently from rust" >&2
    diff <("$python_bin" -m json.tool "$work/classify-rust.json") \
         <("$python_bin" -m json.tool "$work/classify-$lang.json") >&2 || true
    exit 1
  fi
done

# Refuse every request, malformed ones with their own reason, well-formed
# ones with no_such_subject.
"$python_bin" - "$work/classify-in.json" "$work/classify-rust.json" "$seed" "$issued_at" \
  > "$work/refuse-in.json" <<'EOF'
import json, sys
cases = json.load(open(sys.argv[1]))
classified = {c["id"]: c for c in json.load(open(sys.argv[2]))}
print(json.dumps({"seed_hex": sys.argv[3], "issued_at": sys.argv[4], "cases": [
    {"id": c["id"], "request_hex": c["request_hex"],
     "reason": classified[c["id"]]["reason"] or "no_such_subject"} for c in cases]}))
EOF

for lang in "${languages[@]}"; do
  "er_$lang" refuse < "$work/refuse-in.json" > "$work/refuse-$lang.json"
done
for lang in "${languages[@]}"; do
  if ! cmp -s "$work/refuse-rust.json" "$work/refuse-$lang.json"; then
    echo "evidence request: $lang signs refusals differently from rust" >&2
    exit 1
  fi
done

for producer in "${languages[@]}"; do
  "$python_bin" - "$work/refuse-$producer.json" "$work/classify-rust.json" "$public" \
    > "$work/verify-$producer.json" <<'EOF'
import json, sys
refusals = json.load(open(sys.argv[1]))
classified = {c["id"]: c for c in json.load(open(sys.argv[2]))}
print(json.dumps({"public_key_hex": sys.argv[3], "items": [
    {"id": r["id"], "request_digest": classified[r["id"]]["request_digest"],
     "refusal": r["refusal"]} for r in refusals]}))
EOF
  "$python_bin" - "$work/verify-$producer.json" > "$work/tampered-$producer.json" <<'EOF'
import json, sys
doc = json.load(open(sys.argv[1]))
doc["items"] = doc["items"][:1]
doc["items"][0]["refusal"]["sig"] = "00" * 64
print(json.dumps(doc))
EOF
  for consumer in "${languages[@]}"; do
    if ! "er_$consumer" verify < "$work/verify-$producer.json" > "$work/verified.json"; then
      echo "evidence request: $consumer rejected refusals signed by $producer" >&2
      exit 1
    fi
    if "er_$consumer" verify < "$work/tampered-$producer.json" > /dev/null 2>&1; then
      echo "evidence request: $consumer accepted a tampered refusal from $producer" >&2
      exit 1
    fi
  done
done

count=$("$python_bin" -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$work/classify-in.json")
echo "Evidence Request: ${languages[*]} agree on $count requests, sign identical refusals, verify each other's and reject a tampered one."
