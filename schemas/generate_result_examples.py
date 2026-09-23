#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
generate_result_examples.py

Generates the Evidence Result v0 example fixtures under
vectors/evidence-result/, using this repository's own canonicalization
(agent_action_capsule.canonical.json_digest -- lowercase-hex SHA-256 of
UTF8(JCS(value)), the same convention the Evidence Bundle draft and the
Evidence Plan IR v0 fixtures use) to compute every digest in the fixtures.
No digest in the committed output is hand-typed placeholder hex.

One positive fixture (three claims, one per verdict bucket, exercising both
the sufficiency/verdict rule -- spec/evidence-result-v0.md section 1 -- and
the disclosure-policy gate -- section 2 -- in a single fixture) and five
negative fixtures, each a byte-for-byte copy of the positive with exactly one
field changed, each spec/evidence-result-v0.md rule this document requires
MUST reject.

Regenerate with:
    python3 schemas/generate_result_examples.py
Then check with:
    python3 schemas/check_evidence_result_examples.py
"""
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_action_capsule.canonical import json_digest  # noqa: E402
from _result_types import (  # noqa: E402
    AggregateDoc,
    ClaimDoc,
    DigestRefDoc,
    EvidenceResultDoc,
    ProofRefDoc,
)

OUT_DIR = REPO_ROOT / "vectors" / "evidence-result"

CONTRACT_REF = "ec:oo-claims-eval:2026-09-22@1"
GENERATED_AT = "2026-09-22T00:00:00Z"


def digest_ref(value: object) -> DigestRefDoc:
    return {"digest_alg": "SHA-256", "digest": json_digest(value)}


def proof_ref(kind: str, value: object) -> ProofRefDoc:
    ref = digest_ref(value)
    return {"kind": kind, "digest_alg": ref["digest_alg"], "digest": ref["digest"]}


def write(name: str, obj: object) -> None:
    path = OUT_DIR / f"{name}.json"
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(REPO_ROOT)}")


# ---------------------------------------------------------------------------
# claim-1 -- met bucket, fully disclosed
# ---------------------------------------------------------------------------

claim1_evidence_content = {"note": "OO claim-1 outcome evidence artifact, v0 placeholder"}
claim1_proof_content = {"note": "OO claim-1 inclusion proof, v0 placeholder"}

claim_1: ClaimDoc = {
    "id": "claim-1",
    "contract_ref": CONTRACT_REF,
    "requirement_ref": "req-claim-1",
    "tier": "recomputed",
    "grade": "witnessed",
    "sufficiency": "SATISFIED",
    "verdict": "met",
    "evidence": [digest_ref(claim1_evidence_content)],
    "proofs": [proof_ref("inclusion_proof", claim1_proof_content)],
    "presentation": {
        "kind": "disclosure",
        "status": "SATISFIED",
        "evidence": [digest_ref(claim1_evidence_content)],
    },
}

# ---------------------------------------------------------------------------
# claim-2 -- not_met bucket, fully disclosed (a disclosed failure)
# ---------------------------------------------------------------------------

claim2_evidence_content = {"note": "OO claim-2 outcome evidence artifact, v0 placeholder"}
claim2_proof_content = {"note": "OO claim-2 receipt, v0 placeholder"}

claim_2: ClaimDoc = {
    "id": "claim-2",
    "contract_ref": CONTRACT_REF,
    "requirement_ref": "req-claim-2",
    "tier": "judged",
    "grade": "self-attested",
    "sufficiency": "SATISFIED",
    "verdict": "not_met",
    "evidence": [digest_ref(claim2_evidence_content)],
    "proofs": [proof_ref("receipt", claim2_proof_content)],
    "presentation": {
        "kind": "disclosure",
        "status": "SATISFIED",
        "evidence": [digest_ref(claim2_evidence_content)],
    },
}

# ---------------------------------------------------------------------------
# claim-3 -- not_evaluable bucket, evidence WITHHELD: the disclosure-gate case
# ---------------------------------------------------------------------------

claim3_evidence_content = {"note": "OO claim-3 withheld evidence handle, v0 placeholder"}
claim3_proof_content = {"note": "OO claim-3 inclusion proof over the withheld handle, v0 placeholder"}

claim_3: ClaimDoc = {
    "id": "claim-3",
    "contract_ref": CONTRACT_REF,
    "requirement_ref": "req-claim-3",
    "tier": "recomputed",
    "grade": "countersigned",
    "sufficiency": "GAP",
    "verdict": "not_evaluable",
    "evidence": [digest_ref(claim3_evidence_content)],
    "proofs": [proof_ref("inclusion_proof", claim3_proof_content)],
    "presentation": {
        "kind": "analysis",
        "status": "WITHHELD",
        "summary": "OO counterparty confirmed the evidence exists but declined disclosure "
        "under its own policy; adjudicator could not verify the underlying content.",
    },
}

aggregate: AggregateDoc = {
    "coverage": {
        "evaluated_population": 3,
        "excluded_not_applicable": 1,
        "unknown_count": 0,
    },
    "buckets": {
        "met": ["claim-1"],
        "not_met": ["claim-2"],
        "not_evaluable": ["claim-3"],
    },
}

pos_oo_claims_result: EvidenceResultDoc = {
    "result_version": "evidence-result-v0",
    "generated_at": GENERATED_AT,
    "claims": [claim_1, claim_2, claim_3],
    "aggregate": aggregate,
    "view": {
        "spec_version": "presentation/v1",
        "producer_name": "OO",
        "title": "OO Claims Result -- Round 0",
    },
}


def _mutated(base: EvidenceResultDoc) -> EvidenceResultDoc:
    return json.loads(json.dumps(base))


# --- neg-untiered-claim -- claim-1 missing `tier` -------------------------
neg_untiered_claim = _mutated(pos_oo_claims_result)
del neg_untiered_claim["claims"][0]["tier"]

# --- neg-met-with-sufficiency-gap -- claim-1 keeps verdict `met`, --------
#     sufficiency changed SATISFIED -> GAP (spec section 1's binding rule)
neg_met_with_sufficiency_gap = _mutated(pos_oo_claims_result)
neg_met_with_sufficiency_gap["claims"][0]["sufficiency"] = "GAP"

# --- neg-aggregate-without-coverage -- aggregate.coverage removed --------
neg_aggregate_without_coverage = _mutated(pos_oo_claims_result)
del neg_aggregate_without_coverage["aggregate"]["coverage"]

# --- neg-contract-ref-missing -- claim-1 missing `contract_ref` ----------
neg_contract_ref_missing = _mutated(pos_oo_claims_result)
del neg_contract_ref_missing["claims"][0]["contract_ref"]

# --- neg-disclosure-carrier-under-withheld -- claim-3's presentation -----
#     changed from `analysis` to `disclosure` while status stays WITHHELD
#     (spec section 2's gate)
neg_disclosure_carrier_under_withheld = _mutated(pos_oo_claims_result)
neg_disclosure_carrier_under_withheld["claims"][2]["presentation"] = {
    "kind": "disclosure",
    "status": "WITHHELD",
    "evidence": [digest_ref(claim3_evidence_content)],
}


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write("pos-oo-claims-result", pos_oo_claims_result)
    write("neg-untiered-claim", neg_untiered_claim)
    write("neg-met-with-sufficiency-gap", neg_met_with_sufficiency_gap)
    write("neg-aggregate-without-coverage", neg_aggregate_without_coverage)
    write("neg-contract-ref-missing", neg_contract_ref_missing)
    write("neg-disclosure-carrier-under-withheld", neg_disclosure_carrier_under_withheld)
    return 0


if __name__ == "__main__":
    sys.exit(main())
