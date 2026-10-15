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

# RFC 8032 section 7.1 test 1: a published seed and its public key. Test 2's
# seed signs the wrong-key probe.
seed=9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
public=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
other_seed=4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
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

# What every consumer must report for a batch: every id, in order, with the
# reason it was refused with. Written in the adapters' output format so it
# compares byte for byte.
expected_for() {
  "$python_bin" - "$1" > "$2" <<'EOF'
import json, sys
items = json.load(open(sys.argv[1]))["items"]
expected = [{"id": i["id"], "reason": i["refusal"]["reason"]} for i in items]
json.dump(expected, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
EOF
}

# A batch every consumer must accept in full.
accept_all() {
  local batch=$1 what=$2
  expected_for "$batch" "$work/expected.json"
  for consumer in "${languages[@]}"; do
    if ! "er_$consumer" verify < "$batch" > "$work/verified.json"; then
      echo "evidence request: $consumer rejected $what" >&2
      exit 1
    fi
    if ! cmp -s "$work/expected.json" "$work/verified.json"; then
      echo "evidence request: $consumer did not verify every refusal in $what" >&2
      exit 1
    fi
  done
}

# A batch every consumer must reject.
reject_all() {
  local batch=$1 what=$2
  for consumer in "${languages[@]}"; do
    if "er_$consumer" verify < "$batch" > /dev/null 2>&1; then
      echo "evidence request: $consumer accepted $what" >&2
      exit 1
    fi
  done
}

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
  accept_all "$work/verify-$producer.json" "refusals signed by $producer"
  reject_all "$work/tampered-$producer.json" "a tampered refusal from $producer"
done

# Edge probes on one refusal. The draft takes any RFC 3339 UTC issued_at, so a
# fractional-second one must be accepted everywhere. Every consumer must
# reject: a refusal whose reason member is spelled Reason (names match
# exactly); one validly signed under another key (wrong responder); and a
# correctly signed refusal checked against another request's digest.
"$python_bin" - "$work/refuse-in.json" > "$work/fraction-in.json" <<'EOF'
import json, sys
doc = json.load(open(sys.argv[1]))
doc["issued_at"] = "2026-10-15T00:00:00.123Z"
doc["cases"] = doc["cases"][:1]
print(json.dumps(doc))
EOF
er_rust refuse < "$work/fraction-in.json" > "$work/fraction.json"
"$python_bin" - "$work/fraction.json" "$work/classify-rust.json" "$public" \
  "$work/fraction-verify.json" "$work/renamed-verify.json" <<'EOF'
import json, sys
refusal = json.load(open(sys.argv[1]))[0]
digest = {c["id"]: c for c in json.load(open(sys.argv[2]))}[refusal["id"]]["request_digest"]
item = {"id": refusal["id"], "request_digest": digest, "refusal": refusal["refusal"]}
json.dump({"public_key_hex": sys.argv[3], "items": [item]}, open(sys.argv[4], "w"))
renamed = dict(refusal["refusal"])
renamed["Reason"] = renamed.pop("reason")
json.dump({"public_key_hex": sys.argv[3], "items": [dict(item, refusal=renamed)]}, open(sys.argv[5], "w"))
EOF
accept_all "$work/fraction-verify.json" "a refusal with a fractional-second issued_at"
reject_all "$work/renamed-verify.json" "a refusal whose reason member is spelled Reason"

"$python_bin" - "$work/refuse-in.json" "$other_seed" > "$work/other-key-in.json" <<'EOF'
import json, sys
doc = json.load(open(sys.argv[1]))
doc["seed_hex"] = sys.argv[2]
doc["cases"] = doc["cases"][:1]
print(json.dumps(doc))
EOF
er_rust refuse < "$work/other-key-in.json" > "$work/other-key.json"
"$python_bin" - "$work/other-key.json" "$work/verify-rust.json" \
  "$work/other-key-verify.json" "$work/other-digest-verify.json" <<'EOF'
import json, sys
foreign = json.load(open(sys.argv[1]))[0]
doc = json.load(open(sys.argv[2]))
first, second = doc["items"][0], doc["items"][1]
json.dump(dict(doc, items=[dict(first, refusal=foreign["refusal"])]), open(sys.argv[3], "w"))
json.dump(dict(doc, items=[dict(first, request_digest=second["request_digest"])]), open(sys.argv[4], "w"))
EOF
reject_all "$work/other-key-verify.json" "a refusal signed under another key"
reject_all "$work/other-digest-verify.json" "a refusal checked against another request's digest"

count=$("$python_bin" -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$work/classify-rust.json")
if [ "$count" -eq 0 ]; then
  echo "evidence request: no requests were classified" >&2
  exit 1
fi
echo "Evidence Request: ${languages[*]} agree on $count requests, sign identical refusals, verify all of each other's, accept a fractional-second issued_at, and reject a tampered signature, a misspelled member, a foreign key and a wrong request digest."
