#!/usr/bin/env python3
"""Provenance-binding verifier — B9 IETF 126 Hackathon vector harness.

Verifies an AAC provenance-binding bundle through documented stages.
Exit 0 = accept; 2 = reject (naming the stage that failed).

A bundle (input.json) is:
  {
    "action":    { ... the action being attested to ... },
    "grant_doc": { ... the companion delegation-grant document ... },
    "capsule":   { ... an AAC capsule with a provenance_binding extension ... }
  }

The provenance_binding extension MUST be part of the capsule body so it enters
the capsule_id preimage. This harness confirms that invariant via
capsule_id_integrity.

Stages (in order):
  1. subject_digest_recompute   json_digest(action) == capsule.provenance_binding.subject_digest
  2. provenance_ref_binds       declared ref digest == json_digest(grant_doc)
  3. capsule_id_integrity       compute_capsule_id(capsule) == capsule["capsule_id"]
  4. capsule_class1             AAC Class-1 verification passes (structural + id-integrity)

NOTE: All data in the bundled vectors is SYNTHETIC; identities are fictional.
"""
from __future__ import annotations

import json
import os
import sys

try:
    from agent_action_capsule.canonical import json_digest, compute_capsule_id
    from agent_action_capsule import verify as aac_verify
except Exception:  # running from the repo tree without an install
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "python"))
    from agent_action_capsule.canonical import json_digest, compute_capsule_id
    from agent_action_capsule import verify as aac_verify

STAGES = [
    "subject_digest_recompute",  # json_digest(action) == provenance_binding.subject_digest
    "provenance_ref_binds",      # ref.digest == json_digest(grant_doc)
    "capsule_id_integrity",      # compute_capsule_id(capsule) == capsule["capsule_id"]
    "capsule_class1",            # AAC Class-1 structural + id-integrity
]


def check(bundle: dict):
    action = bundle["action"]
    grant_doc = bundle.get("grant_doc", {})
    capsule = bundle["capsule"]
    prov = capsule.get("provenance_binding", {})
    results: dict[str, bool] = {}
    reasons: dict[str, str] = {}

    # Stage 1: action -> subject_digest must match provenance_binding.subject_digest
    action_digest = json_digest(action)
    declared_subject = prov.get("subject_digest")
    ok1 = action_digest == declared_subject
    results["subject_digest_recompute"] = ok1
    if not ok1:
        reasons["subject_digest_recompute"] = (
            f"json_digest(action)={action_digest!r} != "
            f"provenance_binding.subject_digest={declared_subject!r}"
        )
        return "subject_digest_recompute", results, reasons

    # Stage 2: each provenance ref digest must match json_digest of the named artifact.
    # We check the first ref against grant_doc (the bundle carries it as "grant_doc").
    refs = prov.get("refs", [])
    if not refs:
        ok2 = False
        reasons["provenance_ref_binds"] = "provenance_binding.refs is empty; no refs to verify"
    else:
        ref = refs[0]
        declared_ref_digest = ref.get("digest")
        computed_grant_digest = json_digest(grant_doc)
        ok2 = declared_ref_digest == computed_grant_digest
        if not ok2:
            reasons["provenance_ref_binds"] = (
                f"refs[0].digest={declared_ref_digest!r} != "
                f"json_digest(grant_doc)={computed_grant_digest!r}; "
                "the provenance ref does not bind to the carried grant document "
                "(possible splice: this grant was issued for a different action)"
            )
    results["provenance_ref_binds"] = ok2
    if not ok2:
        return "provenance_ref_binds", results, reasons

    # Stage 3: capsule_id integrity — provenance_binding is part of the capsule body
    # and therefore MUST be committed into capsule_id.
    carried_id = capsule.get("capsule_id")
    recomputed_id = compute_capsule_id(capsule)
    ok3 = carried_id == recomputed_id
    results["capsule_id_integrity"] = ok3
    if not ok3:
        reasons["capsule_id_integrity"] = (
            f"carried capsule_id={carried_id!r} != recomputed={recomputed_id!r}; "
            "provenance_binding or another field was tampered after sealing"
        )
        return "capsule_id_integrity", results, reasons

    # Stage 4: AAC Class-1 structural verification
    vr = aac_verify(capsule)
    ok4 = bool(vr.ok)
    results["capsule_class1"] = ok4
    if not ok4:
        errors = [f.detail for f in vr.findings if f.severity == "error"]
        reasons["capsule_class1"] = "; ".join(errors) or "Class-1 verification failed"
        return "capsule_class1", results, reasons

    return None, results, reasons


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: verify_provenance.py <bundle.json>"}))
        return 64

    with open(sys.argv[1]) as f:
        bundle = json.load(f)

    failed, stage_results, reasons = check(bundle)
    out: dict = {
        "verified": failed is None,
        "failed_stage": failed,
        "stages": stage_results,
    }
    if failed is not None and failed in reasons:
        out["reason"] = reasons[failed]

    print(json.dumps(out, indent=2))
    return 0 if failed is None else 2


if __name__ == "__main__":
    sys.exit(main())
