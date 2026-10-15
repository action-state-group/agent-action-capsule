#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Python stdin/stdout adapter for scripts/evidence-request-interlock.sh.

Each command reads one JSON document and writes one compact, key-sorted JSON
document, so its output compares byte for byte with the Go and Rust adapters.

- ``classify``: ``[{id, binding, request_hex}]`` to
  ``[{id, reason, request_digest, well_formed}]``.
- ``refuse``: ``{seed_hex, issued_at, cases: [{id, request_hex, reason}]}``
  to ``[{id, refusal}]``.
- ``verify``: ``{public_key_hex, items: [{id, request_digest, refusal}]}`` to
  ``[{id, reason}]``; exits 1, listing each failure on stderr, if any refusal
  does not authenticate.
- ``envelope``: ``{seed_hex, issued_at, cases: [{id, binding, request_hex,
  subject, anchor_digest, artifact_hex, derivation?, freshness?,
  verification: [{kind, hex}]}]}`` to ``[{id, reply_hex}]``: the interop
  profile's artifact envelope (§6.2), signed.
"""
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agent_action_capsule import evidence_request as er


class _SeedSigner:
    def __init__(self, seed: bytes):
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.key_id = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def sign(self, body: bytes):
        return self._key.sign(body).hex(), self.key_id


def classify(cases):
    out = []
    for case in cases:
        request = bytes.fromhex(case["request_hex"])
        try:
            er.parse_request(request, binding=case["binding"])
            reason = None
        except er.RequestError as e:
            reason = e.reason
        out.append({"id": case["id"], "request_digest": er.request_digest(request),
                    "well_formed": reason is None, "reason": reason})
    return out


def refuse(doc):
    signer = _SeedSigner(bytes.fromhex(doc["seed_hex"]))
    out = []
    for case in doc["cases"]:
        digest = er.request_digest(bytes.fromhex(case["request_hex"]))
        refusal = er.sign_refusal(digest, case["reason"], signer=signer, issued_at=doc["issued_at"])
        out.append({"id": case["id"], "refusal": refusal.to_dict()})
    return out


def verify(doc):
    """A refusal authenticates as the responder's answer to a request when it
    conforms, names the responder's key, verifies under it, and names the
    request's digest."""
    out, failures = [], []
    for item in doc["items"]:
        obj = item["refusal"]
        check = er.check_refusal(obj)
        ok = (check.conformant and obj.get("key_id") == doc["public_key_hex"]
              and obj.get("request_digest") == item["request_digest"])
        if ok:
            out.append({"id": item["id"], "reason": obj["reason"]})
        else:
            failures.append(f"{item['id']}: refusal does not authenticate")
    if failures:
        raise SystemExit("\n".join(failures))
    return out


def _subject(wire):
    ((form, content),) = wire.items()
    return er.Subject(form, tuple(content) if isinstance(content, list) else content)


def envelope(doc):
    signer = _SeedSigner(bytes.fromhex(doc["seed_hex"]))
    out = []
    for case in doc["cases"]:
        env = er.sign_envelope(
            bytes.fromhex(case["request_hex"]),
            _subject(case["subject"]),
            case["anchor_digest"],
            bytes.fromhex(case["artifact_hex"]),
            signer=signer,
            issued_at=doc["issued_at"],
            derivation=case.get("derivation"),
            freshness=case.get("freshness"),
            verification=[(v["kind"], bytes.fromhex(v["hex"])) for v in case.get("verification", [])],
        )
        out.append({"id": case["id"], "reply_hex": env.encode(case["binding"]).hex()})
    return out


def main() -> int:
    commands = {"classify": classify, "refuse": refuse, "verify": verify, "envelope": envelope}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        print("usage: evidence_request_interlock.py classify|refuse|verify|envelope", file=sys.stderr)
        return 2
    result = commands[sys.argv[1]](json.load(sys.stdin))
    json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
