#!/usr/bin/env python3
"""ran_under verifier — the citing side of an AAC Capsule x runtime-attestation
citation, staged the way `verify_composition.py` stages a WHAT x WHO join.

A `ran_under` reference is a Capsule citing a record that states the runtime
environment and authority its action executed under (e.g. a hardware-rooted
trust record from a mesh attestor). That cited record's own format owns its
grading; this harness never re-derives it. It takes the cited format's
verifier result as an INPUT — `cited_verifier_result` in the bundle — the way
a real consumer would after running the cited format's own tooling. It never
parses attestation bytes, evaluates a measurement, or derives a grade; the
one thing it does with the cited record's raw bytes is recompute a content
digest, which is generic hashing, not attestation verification.

A bundle (input.json) is:
  {
    "capsule": <AAC capsule with a `references` entry, citation_purpose=ran_under>,
    "cited_record": {...the cited artifact's raw content, digested for the binding check...},
    "relied_claim": {"field": <str>, "expected_value": <any>},
        -- the specific fact this Capsule's ran_under citation depends on.
    "cited_verifier_result": {
        "grade": <str> | null,
        "signer_trusted": <bool>,
        "attested_fields": {...fields the cited format's OWN verifier actually attests...},
        "self_reported_fields": {...fields present in the record's content but NOT covered
                                    by its attestation grade...}
    }
  }

Exit 0 = lift (the citation resolves and the grade may be reported for what it
covers). Exit 2 = no lift, naming the stage and a `verdict` distinguishing WHY:
"invalid" (a binding actually broke), "not_established" (no grade to begin
with), "untrusted_signer" (good grade, wrong signer), or "unattested_claim"
(good grade, but the relied-on fact is self-reported inside the cited record,
not attested — SS6.1 non-propagation). A passing grade is not a passing
citation; only "accepted" lifts.
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
    "citation_present",    # capsule carries a well-formed references[] entry, citation_purpose=ran_under
    "digest_binds",        # SHA-256(JCS(cited_record)) == the reference's declared digest
    "capsule_class1",      # the citing Capsule itself passes Class-1 verification
    "grade_established",   # cited_verifier_result carries a grade at all
    "claim_is_attested",   # the field the Capsule relies on is in attested_fields, not just self-reported
    "claim_value_binds",   # attested_fields[field] == the Capsule's declared expected_value
    "signer_trusted",      # cited_verifier_result reports the signer within configured roots
]


def _ran_under_reference(capsule: dict):
    for ref in capsule.get("references") or []:
        if isinstance(ref, dict) and ref.get("citation_purpose") == "ran_under":
            return ref
    return None


def check(bundle: dict):
    """Returns (failed_stage_or_None, stage_results, verdict)."""
    capsule = bundle["capsule"]
    cited_record = bundle["cited_record"]
    relied = bundle["relied_claim"]
    result = bundle["cited_verifier_result"]
    r: dict[str, bool] = {}

    ref = _ran_under_reference(capsule)
    r["citation_present"] = bool(
        ref
        and isinstance(ref.get("type"), str) and ref.get("type")
        and isinstance(ref.get("digest_alg"), str) and ref.get("digest_alg")
        and isinstance(ref.get("digest"), str) and ref.get("digest")
    )
    if not r["citation_present"]:
        return "citation_present", r, "invalid"

    r["digest_binds"] = json_digest(cited_record) == ref.get("digest")
    if not r["digest_binds"]:
        return "digest_binds", r, "invalid"

    r["capsule_class1"] = bool(aac_verify(capsule).ok)
    if not r["capsule_class1"]:
        return "capsule_class1", r, "invalid"

    grade = result.get("grade")
    r["grade_established"] = grade is not None
    if not r["grade_established"]:
        return "grade_established", r, "not_established"

    attested = result.get("attested_fields") or {}
    field = relied.get("field")

    r["claim_is_attested"] = field in attested
    if not r["claim_is_attested"]:
        return "claim_is_attested", r, "unattested_claim"

    r["claim_value_binds"] = attested.get(field) == relied.get("expected_value")
    if not r["claim_value_binds"]:
        return "claim_value_binds", r, "invalid"

    r["signer_trusted"] = bool(result.get("signer_trusted"))
    if not r["signer_trusted"]:
        return "signer_trusted", r, "untrusted_signer"

    return None, r, "accepted"


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: verify_ran_under.py <bundle.json>"}))
        return 64
    bundle = json.load(open(sys.argv[1]))
    failed, stages, verdict = check(bundle)
    lifted = failed is None
    print(json.dumps({
        "verified": lifted,
        "lift": lifted,
        "verdict": verdict,
        "failed_stage": failed,
        "stages": stages,
    }, indent=2))
    return 0 if lifted else 2


if __name__ == "__main__":
    sys.exit(main())
