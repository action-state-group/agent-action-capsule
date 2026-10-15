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
# 4. envelope: every language builds the interop profile's artifact envelope
#    (spec/interop-profile-v0.md §6.2) from the same inputs, byte-identical in
#    both bindings. Each verifies every producer's envelopes and rejects one
#    with an altered verification item for that item's digest.
# 5. cll: Python and Go check the profile's Checkpointed Local Log proofs
#    (§6.2.1) on the worked example's real bytes, and reject each proof
#    altered in a path node.
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
json.dump(expected, sys.stdout, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
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

# Step 4: the artifact envelope.
# Each case answers its own request: the envelope's subject, derivation and
# freshness are the request's (profile §6.2).
"$python_bin" - "$seed" "$issued_at" > "$work/envelope-in.json" <<'EOF'
import hashlib, json, sys
anchor = hashlib.sha256(b"anchor checkpoint statement").hexdigest()
record = hashlib.sha256(b"a record").hexdigest()
artifact = b'{"anchor":"' + anchor.encode() + b'","records":[]}'
material = [{"kind": "cll-checkpoint", "hex": b"checkpoint statement".hex()},
            {"kind": "cll-inclusion-proof", "hex": bytes([0x82, 0x01, 0x80]).hex()}]
pin = {"expected_pin": anchor}
specs = [
    ("record-json", "json", {"record": record}, pin, {"verification": material}),
    ("record-cbor", "cbor", {"record": record}, pin, {"verification": material}),
    ("checkpoints", "json", {"checkpoints": None}, pin, {}),
    ("history-card", "cbor", {"full_history": None}, {"min_freshness": 40},
     {"derivation": "history_card/1", "freshness": 42}),
    ("range-by-time", "json", {"range": [0, 3]}, {"min_freshness": "2026-10-13T00:00:00Z"},
     {"freshness": "2026-10-14T00:00:00Z"}),
    ("correlation", "cbor", {"correlation": "deal-7"}, pin, {}),
]
def request(subject, coverage, extra):
    body = {"subject": subject, "coverage": coverage, "nonce": "interlock"}
    if "derivation" in extra:
        body["derivation"] = extra["derivation"]
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
print(json.dumps({"seed_hex": sys.argv[1], "issued_at": sys.argv[2], "cases": [
    dict(id=i, binding=b, subject=s, request_hex=request(s, c, extra).hex(), anchor_digest=anchor,
         artifact_hex=artifact.hex(), **extra) for i, b, s, c, extra in specs]}))
EOF
envelope_languages=(python go rust)
envelope_verifiers=(python go rust)
for lang in "${envelope_languages[@]}"; do
  "er_$lang" envelope < "$work/envelope-in.json" > "$work/envelope-$lang.json"
done
for lang in "${envelope_languages[@]}"; do
  if ! cmp -s "$work/envelope-python.json" "$work/envelope-$lang.json"; then
    echo "evidence request: python and $lang build different artifact envelopes" >&2
    diff <("$python_bin" -m json.tool "$work/envelope-python.json") \
         <("$python_bin" -m json.tool "$work/envelope-$lang.json") >&2 || true
    exit 1
  fi
done
# Every verifier checks every producer's envelopes, and the same envelopes
# with one verification item altered in each binding.
for producer in "${envelope_languages[@]}"; do
  "$python_bin" - "$work/envelope-in.json" "$work/envelope-$producer.json" \
    "$work/envelope-check-$producer.json" "$work/envelope-tampered-$producer.json" <<'EOF'
import base64, json, sys
from agent_action_capsule.canonical import jcs
from agent_action_capsule.interop_profile import _cbor
bindings = {c["id"]: c["binding"] for c in json.load(open(sys.argv[1]))["cases"]}
replies = {r["id"]: dict(r, binding=bindings[r["id"]]) for r in json.load(open(sys.argv[2]))}
json.dump(list(replies.values()), open(sys.argv[3], "w"))
# The frame is re-encoded so it stays well formed: only the item's signed
# digest can catch the change.
def b64(octets):
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode()
def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
tampered = []
for rid in ("record-json", "record-cbor"):
    reply = replies[rid]
    octets = bytes.fromhex(reply["reply_hex"])
    if reply["binding"] == "json":
        frame = json.loads(octets)
        frame["verification_content"][1] = b64(unb64(frame["verification_content"][1]) + b"\x00")
        octets = jcs(frame)
    else:
        frame = _cbor.decode(octets).value
        frame["verification_content"][1] += b"\x00"
        octets = _cbor.encode(frame)
    tampered.append(dict(reply, reply_hex=octets.hex()))
json.dump(tampered, open(sys.argv[4], "w"))
EOF
  for lang in "${envelope_verifiers[@]}"; do
    if ! "er_$lang" check-envelope < "$work/envelope-check-$producer.json" > /dev/null; then
      echo "evidence request: $lang rejected an envelope $producer built" >&2
      exit 1
    fi
    err="$work/envelope-tampered-$producer-$lang.err"
    if "er_$lang" check-envelope < "$work/envelope-tampered-$producer.json" > /dev/null 2> "$err"; then
      echo "evidence request: $lang accepted a tampered envelope from $producer" >&2
      exit 1
    fi
    for rid in record-json record-cbor; do
      if ! grep -q "^$rid: .*verification item 1 does not hash to its signed digest" "$err"; then
        echo "evidence request: $lang rejected $producer's tampered $rid envelope for another reason:" >&2
        cat "$err" >&2
        exit 1
      fi
    done
  done
done

# Step 5: the CLL material (profile §6.2.1 steps 12 and 13), on the real bytes
# of the profile's worked example (§10.1, vectors/interop-profile-v0
# valid-exchange). Every verifier accepts its inclusion and consistency
# proofs, and rejects each one altered in a path node, which leaves the proof
# well formed so only the proof check can catch it. Rust checks CLL material
# per envelope (cll_material::check_anchor_inclusion, feature cll), so it
# joins when its interlock adapter gains check-cll.
cll_verifiers=(python go)
"$python_bin" - "$repo/vectors/interop-profile-v0/vectors.json" "$work/cll-in.json" "$work/cll-expected.json" <<'EOF'
import json, sys
from agent_action_capsule import evidence_request as er
from agent_action_capsule.interop_profile import _cbor
from agent_action_capsule.interop_profile.cll import _decode_checkpoint
case = next(c for c in json.load(open(sys.argv[1]))["cases"] if c["id"] == "valid-exchange")
envelope = er.parse_reply(case["inputs"]["replies"][0]["octets_text"].encode())
envelope.verify()
items = dict(envelope.verification)
checkpoint = _decode_checkpoint(items["cll-checkpoint"])
peaks = [p.hex() for p in checkpoint.commitment]
old_peaks = [p.hex() for p in checkpoint.prev_commitment]
entry = envelope.signed_members()["artifact_digest"]
inclusion, consistency = items["cll-inclusion-proof"], items["cll-consistency-proof"]
def altered(octets, path_of):
    proof = _cbor.decode(octets).value
    node = path_of(proof)
    node[0] = node[0][:-1] + bytes([node[0][-1] ^ 1])
    return _cbor.encode(proof)
assert _cbor.decode(inclusion).value[1], "the example's inclusion path is empty"
assert any(_cbor.decode(consistency).value[2]), "the example's consistency paths are empty"
proofs = [
    dict(id="inclusion", kind="inclusion", peaks_hex=peaks, entry_hex=entry, proof_hex=inclusion.hex()),
    dict(id="inclusion-altered", kind="inclusion", peaks_hex=peaks, entry_hex=entry,
         proof_hex=altered(inclusion, lambda p: p[1]).hex()),
    dict(id="consistency", kind="consistency", old_peaks_hex=old_peaks, peaks_hex=peaks,
         proof_hex=consistency.hex()),
    dict(id="consistency-altered", kind="consistency", old_peaks_hex=old_peaks, peaks_hex=peaks,
         proof_hex=altered(consistency, lambda p: next(path for path in p[2] if path)).hex()),
]
json.dump(proofs, open(sys.argv[2], "w"))
expected = [{"id": p["id"], "verified": not p["id"].endswith("-altered")} for p in proofs]
with open(sys.argv[3], "w") as out:
    json.dump(expected, out, sort_keys=True, separators=(",", ":"))
    out.write("\n")
EOF
for lang in "${cll_verifiers[@]}"; do
  "er_$lang" check-cll < "$work/cll-in.json" > "$work/cll-$lang.json"
  if ! cmp -s "$work/cll-expected.json" "$work/cll-$lang.json"; then
    echo "evidence request: $lang does not accept exactly the unaltered CLL proofs" >&2
    diff "$work/cll-expected.json" "$work/cll-$lang.json" >&2 || true
    exit 1
  fi
done

count=$("$python_bin" -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$work/classify-rust.json")
if [ "$count" -eq 0 ]; then
  echo "evidence request: no requests were classified" >&2
  exit 1
fi
echo "Evidence Request: ${languages[*]} agree on $count requests, sign identical refusals, verify all of each other's, accept a fractional-second issued_at, and reject a tampered signature, a misspelled member, a foreign key and a wrong request digest; python, go and rust build identical artifact envelopes, each verifies all three and rejects an altered verification item in either binding; python and go accept the worked example's CLL inclusion and consistency proofs and reject each altered."
