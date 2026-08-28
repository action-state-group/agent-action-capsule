#!/usr/bin/env python3
"""Composition verifier — the WHAT side of an AAC x EP-RECEIPT-v1 composition.

Composition, NOT format merger: an Agent Action Capsule (WHAT) and an
EP-RECEIPT-v1 (WHO) are produced independently and joined only by a shared
subject_digest = SHA-256(JCS(action)) plus a human_authorization_ref. This
harness verifies one composition bundle through documented stages and prints a
JSON verdict. Exit 0 = accept; 2 = reject (naming the stage that failed).

A bundle (input.json) is:
  { "subject_digest": <hex>, "action": {...}, "what": <AAC capsule>, "who": <EP receipt> }

The WHO profile (EP-RECEIPT-v1 signatures/quorum) verifies independently with
EP's own tooling; this harness checks the WHAT capsule and the composition join,
which is our side of the interop.
"""
from __future__ import annotations

import json
import os
import sys

try:
    from agent_action_capsule.canonical import json_digest
    from agent_action_capsule import verify as aac_verify
except Exception:  # running from the repo tree without an install
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "python"))
    from agent_action_capsule.canonical import json_digest
    from agent_action_capsule import verify as aac_verify

STAGES = [
    "subject_digest_recompute",   # action -> SHA-256(JCS(action)) == declared subject_digest
    "what_class1",                # the AAC capsule passes Class-1 verification
    "what_binds_subject",         # capsule.compute_attestation.subject_digest == subject_digest
    "digest_agreement",           # WHO.action_hash (strip "sha256:") == subject_digest
    "who_authorization_present",  # WHO carries a signoff/signature (not an empty/unsigned ref)
    "ref_binds",                  # capsule.human_authorization_ref.digest == SHA-256(JCS(WHO))
]


def check(bundle: dict):
    action, what, who = bundle["action"], bundle["what"], bundle["who"]
    sd = bundle["subject_digest"]
    r: dict[str, bool] = {}

    r["subject_digest_recompute"] = json_digest(action) == sd
    if not r["subject_digest_recompute"]:
        return "subject_digest_recompute", r

    r["what_class1"] = bool(aac_verify(what).ok)
    if not r["what_class1"]:
        return "what_class1", r

    ca = what.get("model_attestation", {}).get("compute_attestation", {}) or {}
    r["what_binds_subject"] = ca.get("subject_digest") == sd
    if not r["what_binds_subject"]:
        return "what_binds_subject", r

    who_hash = str(who.get("action_hash", "")).split(":")[-1]
    r["digest_agreement"] = who_hash == sd
    if not r["digest_agreement"]:
        return "digest_agreement", r

    r["who_authorization_present"] = bool(who.get("signoffs") or who.get("signature"))
    if not r["who_authorization_present"]:
        return "who_authorization_present", r

    ref = ca.get("human_authorization_ref", {}) or {}
    # The ref binds the WHO document by CONTENT: human_authorization_ref.digest
    # must equal SHA-256 over JCS of the WHO receipt. The receipt_id
    # (ref.receipt_id vs who.receipt_id) is a human-readable label only, NOT the
    # binding — the digest is, so a tampered WHO or a ref pointing elsewhere fails
    # here even if the receipt_id string still matches.
    r["ref_binds"] = ref.get("digest") == json_digest(who)
    if not r["ref_binds"]:
        return "ref_binds", r

    return None, r


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: verify_composition.py <bundle.json>"}))
        return 64
    bundle = json.load(open(sys.argv[1]))
    if bundle.get("stub"):
        print(json.dumps({"verified": None, "failed_stage": None, "note": "reserved stub — not runnable"}))
        return 0
    failed, results = check(bundle)
    print(json.dumps({"verified": failed is None, "failed_stage": failed, "stages": results}, indent=2))
    return 0 if failed is None else 2


if __name__ == "__main__":
    sys.exit(main())
