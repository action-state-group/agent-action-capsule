#!/usr/bin/env python3
"""Generator for B9 provenance-binding test vectors.

Run once from this directory to (re)produce input.json files and print digests.
Not shipped as a runnable verifier — that is verify_provenance.py.

NOTE: This is a synthetic-data generator. All identities are fictional.
"""
from __future__ import annotations

import json
import os
import sys

# Allow running from repo tree without an install
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "python"))

from agent_action_capsule.canonical import json_digest, compute_capsule_id
from agent_action_capsule.emit import emit
from agent_action_capsule.contracts import EffectRecord, Disposition

# ---------------------------------------------------------------------------
# The canonical action — the thing being attested to.
# A synthetic cross-org delegation: agent A delegates an API call to agent B.
# ---------------------------------------------------------------------------
ACTION = {
    "action_type": "delegation.api_call",
    "delegator": "org:alpha-corp:agent-A@v2",
    "delegatee": "org:beta-systems:agent-B@v1",
    "parameters": {
        "api_endpoint": "https://api.beta-systems.example/v1/data-export",
        "grant_id": "grant:alpha-corp:2026-Q3-0042",
        "scope": ["read:records", "export:csv"],
        "not_after": "2026-07-18T23:59:59Z",
        "max_records": "5000",
    },
    "policy_ref": "policy:alpha-corp:cross-org-delegation@v1",
    "requested_at": "2026-07-18T10:00:00Z",
}

# The companion provenance artifact — the delegation grant document.
GRANT_DOC = {
    "grant_id": "grant:alpha-corp:2026-Q3-0042",
    "issued_by": "org:alpha-corp:authority@v1",
    "issued_to": "org:beta-systems:agent-B@v1",
    "scope": ["read:records", "export:csv"],
    "valid_from": "2026-07-01T00:00:00Z",
    "valid_until": "2026-09-30T23:59:59Z",
    "terms": "https://alpha-corp.example/legal/cross-org-data-sharing-v1",
}

# A DIFFERENT action used in the splice vector (different parameters/scope)
SPLICED_ACTION = {
    "action_type": "delegation.api_call",
    "delegator": "org:alpha-corp:agent-A@v2",
    "delegatee": "org:beta-systems:agent-B@v1",
    "parameters": {
        "api_endpoint": "https://api.beta-systems.example/v1/data-export",
        "grant_id": "grant:alpha-corp:2026-Q3-0042",
        "scope": ["read:records", "export:csv", "delete:records"],  # EXTRA scope — attacker inserted
        "not_after": "2026-07-18T23:59:59Z",
        "max_records": "50000",  # inflated
    },
    "policy_ref": "policy:alpha-corp:cross-org-delegation@v1",
    "requested_at": "2026-07-18T10:00:00Z",
}


def build_positive_bundle() -> dict:
    """Build the positive provenance-binding bundle."""
    action_digest = json_digest(ACTION)
    grant_digest = json_digest(GRANT_DOC)

    # Emit a sealed AAC capsule that commits the action subject_digest and
    # provenance references into its capsule_id preimage via compute_attestation
    # and a namespaced effect.authorization extension.
    effect = EffectRecord(
        status="dispatched",
        type="api_delegation",
        request_digest=action_digest,
        effect_attestation="runtime_claimed",
    )
    disposition = Disposition(
        decision="accept",
        approver="policy",
        human_disposed=False,
        verdict_class="executed",
        authority="policy:alpha-corp:cross-org-delegation@v1",
    )

    capsule = emit(
        action_id="aac-prov-binding-b9-0001",
        action_type="decide",
        operator="alpha-corp",
        developer="alpha-corp:agent-A@v2",
        model_id="claude-sonnet-4-6",
        provider="anthropic",
        timestamp="2026-07-18T10:05:00Z",
        compute_attestation={
            "subject_digest": action_digest,
            "runtime": "alpha-corp-delegation-engine@v2",
        },
        effect=effect,
        disposition=disposition,
        # provenance_binding is a namespaced payload extension; it enters the
        # capsule_id preimage automatically because it is part of the capsule body
        # passed to emit() via extra fields. Since emit() uses the Capsule dataclass
        # which only serialises known fields, we post-insert the extension BEFORE
        # recomputing capsule_id.
    )

    # Post-insert the provenance_binding extension (namespaced, public-safe).
    # Then recompute capsule_id to include the extension in the preimage.
    # This follows the §5.1 rule: capsule_id = SHA-256(JCS(capsule_body \ {capsule_id, chain}))
    capsule["provenance_binding"] = {
        "version": "1",
        "refs": [
            {
                "ref_id": "grant:alpha-corp:2026-Q3-0042",
                "ref_type": "delegation_grant",
                "digest_alg": "SHA-256/JCS",
                "digest": grant_digest,
            }
        ],
        "subject_digest": action_digest,
    }
    # Recompute capsule_id now that provenance_binding is in the body
    capsule["capsule_id"] = compute_capsule_id(capsule)

    return {
        "_note": "SYNTHETIC DATA — all identities are fictional; generated for IETF 126 Hackathon B9",
        "action": ACTION,
        "grant_doc": GRANT_DOC,
        "capsule": capsule,
    }


def build_splice_bundle(pos_bundle: dict) -> dict:
    """Build the splice negative bundle.

    The splice attack: an attacker takes a LEGITIMATELY SIGNED capsule (built
    around the original action with a valid grant) and swaps in a TAMPERED
    grant_doc that inflates the scope. The capsule's provenance_binding.refs[0].digest
    still commits to the ORIGINAL (narrow-scope) grant's digest. The bundle's
    "grant_doc" field carries the TAMPERED version.

    Failure stage: provenance_ref_binds
      json_digest(tampered_grant_doc) != refs[0].digest (original grant digest)

    Stage subject_digest_recompute still passes because the capsule was built
    around SPLICED_ACTION and provenance_binding.subject_digest matches it.
    """
    spliced_action_digest = json_digest(SPLICED_ACTION)
    original_grant_digest = json_digest(GRANT_DOC)

    # The tampered grant document: attacker inflated the scope and record limit
    tampered_grant_doc = {
        "grant_id": "grant:alpha-corp:2026-Q3-0042",
        "issued_by": "org:alpha-corp:authority@v1",
        "issued_to": "org:beta-systems:agent-B@v1",
        # TAMPERED: scope extended with delete:records
        "scope": ["read:records", "export:csv", "delete:records"],
        "valid_from": "2026-07-01T00:00:00Z",
        "valid_until": "2026-09-30T23:59:59Z",
        "terms": "https://alpha-corp.example/legal/cross-org-data-sharing-v1",
    }

    effect = EffectRecord(
        status="dispatched",
        type="api_delegation",
        request_digest=spliced_action_digest,
        effect_attestation="runtime_claimed",
    )
    disposition = Disposition(
        decision="accept",
        approver="policy",
        human_disposed=False,
        verdict_class="executed",
        authority="policy:alpha-corp:cross-org-delegation@v1",
    )

    capsule = emit(
        action_id="aac-prov-binding-b9-splice-0001",
        action_type="decide",
        operator="alpha-corp",
        developer="alpha-corp:agent-A@v2",
        model_id="claude-sonnet-4-6",
        provider="anthropic",
        timestamp="2026-07-18T10:05:00Z",
        compute_attestation={
            "subject_digest": spliced_action_digest,
            "runtime": "alpha-corp-delegation-engine@v2",
        },
        effect=effect,
        disposition=disposition,
    )

    # The capsule's provenance_binding commits to the ORIGINAL (narrow-scope) grant
    # digest — the one actually issued and signed by alpha-corp authority.
    # The attacker presents a TAMPERED grant_doc that json_digest() won't match.
    capsule["provenance_binding"] = {
        "version": "1",
        "refs": [
            {
                "ref_id": "grant:alpha-corp:2026-Q3-0042",
                "ref_type": "delegation_grant",
                "digest_alg": "SHA-256/JCS",
                # This digest binds the ORIGINAL narrow-scope grant
                "digest": original_grant_digest,
            }
        ],
        "subject_digest": spliced_action_digest,
    }
    capsule["capsule_id"] = compute_capsule_id(capsule)

    return {
        "_note": (
            "SYNTHETIC DATA — splice negative vector. The grant_doc in this bundle has been "
            "tampered (scope inflated to include delete:records). The capsule's "
            "provenance_binding.refs[0].digest commits to the ORIGINAL narrow-scope grant. "
            "json_digest(tampered_grant_doc) != refs[0].digest. "
            "Failure stage: provenance_ref_binds."
        ),
        "action": SPLICED_ACTION,
        "grant_doc": tampered_grant_doc,
        "capsule": capsule,
    }


def main():
    os.makedirs("pos-provenance-binding", exist_ok=True)
    os.makedirs("neg-provenance-splice", exist_ok=True)

    pos = build_positive_bundle()
    neg = build_splice_bundle(pos)

    with open("pos-provenance-binding/input.json", "w") as f:
        json.dump(pos, f, indent=2)
    print("Wrote pos-provenance-binding/input.json")
    print(f"  subject_digest = {pos['capsule']['provenance_binding']['subject_digest']}")
    print(f"  capsule_id     = {pos['capsule']['capsule_id']}")
    print(f"  grant_digest   = {pos['capsule']['provenance_binding']['refs'][0]['digest']}")

    with open("neg-provenance-splice/input.json", "w") as f:
        json.dump(neg, f, indent=2)
    print("\nWrote neg-provenance-splice/input.json")
    print(f"  spliced_action_digest = {json_digest(SPLICED_ACTION)}")
    print(f"  provenance.subject_digest (wrong) = {neg['capsule']['provenance_binding']['subject_digest']}")
    print(f"  capsule_id            = {neg['capsule']['capsule_id']}")


if __name__ == "__main__":
    main()
