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

PROPOSED claim types (Steven's ruling, 2026-09-25): four more positives --
one reconcile Result, one AGREED close, one UNILATERAL close, one CONTESTED
close (the Evidence Layer's third Close state, draft-mih-agent-evidence-
layer-00 'Reconcile and Close'), each pairing the untouched requirement
claim-1 with one typed claim -- and four more negatives (AGREED close
without `peer`; CONTESTED close without `peer_close_ref`; reconcile tallies
missing a state; a claim `type` outside the closed enum), each again one
field away from its positive. Reconcile tallies are keyed as
schemas/judge/close-v1.json keys them (lowercase).

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
    PeriodDoc,
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

# ===========================================================================
# PROPOSED claim types (Steven's ruling, 2026-09-25: "close + reconcile as
# claim types in result v0, so they feed the same result"). Each positive
# below pairs the untouched requirement claim-1 with ONE typed claim, so a
# fixture pins one type in isolation and the pre-existing shape is proven
# to coexist with it in the same claims[] array.
# ===========================================================================

RECONCILE_CONTRACT_REF = "ec:oo-outcomes-reconcile:2026-09-25@1"
MONTH: PeriodDoc = {"start": "2026-09-01T00:00:00Z", "end": "2026-10-01T00:00:00Z"}
DAY_1: PeriodDoc = {"start": "2026-09-01T00:00:00Z", "end": "2026-09-02T00:00:00Z"}

# --- reconcile-1 -- refund-lands, all six states populated, no gap: ------
#     sufficiency SATISFIED (INSUFFICIENT = UNRESOLVED = 0); the contract
#     clause's verdict is not_met because rows exist outside MATCHED.
#     A_ONLY / B_ONLY are "one side missing", CONFLICTING is "both sides
#     disagree" -- the fixture carries all three so a renderer can be
#     tested for never conflating them (ruling 2026-09-25).
reconcile1_evidence_content = {"note": "OO reconcile refund-lands September fold output, v0 placeholder"}
reconcile1_proof_content = {"note": "OO reconcile refund-lands inclusion proof, v0 placeholder"}

reconcile_1: ClaimDoc = {
    "id": "reconcile-1",
    "type": "reconcile",
    "contract_ref": RECONCILE_CONTRACT_REF,
    "requirement_ref": "refund-lands",
    "tier": "recomputed",
    "grade": "self-attested",
    "sufficiency": "SATISFIED",
    "verdict": "not_met",
    "evidence": [digest_ref(reconcile1_evidence_content)],
    "proofs": [proof_ref("inclusion_proof", reconcile1_proof_content)],
    "presentation": {
        "kind": "disclosure",
        "status": "SATISFIED",
        "evidence": [digest_ref(reconcile1_evidence_content)],
    },
    "reconcile": {
        "join_key": "reservation_id",
        "peer": "oo-sor",
        "period": MONTH,
        "tallies": {
            "matched": 408,
            "a_only": 2,
            "b_only": 1,
            "conflicting": 1,
            "insufficient": 0,
            "unresolved": 0,
        },
        "state_of_record": "B",
    },
}

# --- reconcile-2 -- change-lands, connector gap: INSUFFICIENT = 3 => -----
#     sufficiency GAP => verdict not_evaluable (the design's own monthly
#     example). presentation is analysis/INSUFFICIENT: characterizes the
#     gap without repairing it.
reconcile2_evidence_content = {"note": "OO reconcile change-lands September fold output, v0 placeholder"}
reconcile2_proof_content = {"note": "OO reconcile change-lands inclusion proof, v0 placeholder"}

reconcile_2: ClaimDoc = {
    "id": "reconcile-2",
    "type": "reconcile",
    "contract_ref": RECONCILE_CONTRACT_REF,
    "requirement_ref": "change-lands",
    "tier": "recomputed",
    "grade": "self-attested",
    "sufficiency": "GAP",
    "verdict": "not_evaluable",
    "evidence": [digest_ref(reconcile2_evidence_content)],
    "proofs": [proof_ref("inclusion_proof", reconcile2_proof_content)],
    "presentation": {
        "kind": "analysis",
        "status": "INSUFFICIENT",
        "summary": "OO peer connector produced no system_of_record_fact rows on three days of "
        "the period; the join could not be evaluated for those days.",
    },
    "reconcile": {
        "join_key": "reservation_id",
        "peer": "oo-sor",
        "period": MONTH,
        "tallies": {
            "matched": 380,
            "a_only": 0,
            "b_only": 0,
            "conflicting": 0,
            "insufficient": 3,
            "unresolved": 0,
        },
        "state_of_record": "B",
    },
}

pos_oo_reconcile_result: EvidenceResultDoc = {
    "result_version": "evidence-result-v0",
    "generated_at": GENERATED_AT,
    "claims": [claim_1, reconcile_1, reconcile_2],
    "aggregate": {
        "coverage": {
            "evaluated_population": 3,
            "excluded_not_applicable": 0,
            "unknown_count": 0,
        },
        "buckets": {
            "met": ["claim-1"],
            "not_met": ["reconcile-1"],
            "not_evaluable": ["reconcile-2"],
        },
    },
    "view": {
        "spec_version": "presentation/v1",
        "producer_name": "OO",
        "title": "OO Outcomes Reconcile -- September",
    },
}

# --- close-1 (AGREED) -- the peer's Close cites ours back ----------------
own_close_content = {"note": "OO own Close record for 2026-09-01, v0 placeholder"}
peer_close_content = {"note": "OO peer (oo-sor) Close record for 2026-09-01 citing OO's, v0 placeholder"}
close_proof_content = {"note": "OO Close inclusion proof, v0 placeholder"}

close_agreed: ClaimDoc = {
    "id": "close-1",
    "type": "close",
    "contract_ref": RECONCILE_CONTRACT_REF,
    "requirement_ref": "close",
    "tier": "recomputed",
    "grade": "self-attested",
    "sufficiency": "SATISFIED",
    "verdict": "met",
    "evidence": [digest_ref(own_close_content), digest_ref(peer_close_content)],
    "proofs": [proof_ref("inclusion_proof", close_proof_content)],
    "presentation": {
        "kind": "disclosure",
        "status": "SATISFIED",
        "evidence": [digest_ref(own_close_content), digest_ref(peer_close_content)],
    },
    "close": {
        "period": DAY_1,
        "close_state": "AGREED",
        "peer": "oo-sor",
        "peer_close_ref": digest_ref(peer_close_content),
    },
}

# --- close-1 (CONTESTED) -- a peer record carries a `rebuts` link to ------
#     ours (draft-mih-agent-evidence-layer-00, 'Reconcile and Close'). The
#     state is what the Result builder READ from the Close's inbound links,
#     never a field the Close set. Base axes stay as on the AGREED /
#     UNILATERAL fixtures (the Close itself was sealed: `met`); the
#     agreement axis lives in close_state alone. peer_close_ref cites the
#     rebutting record by digest, exactly as AGREED cites the acknowledging
#     Close.
peer_rebuttal_content = {"note": "OO peer (oo-sor) record for 2026-09-01 rebutting OO's Close, v0 placeholder"}

close_contested: ClaimDoc = {
    "id": "close-1",
    "type": "close",
    "contract_ref": RECONCILE_CONTRACT_REF,
    "requirement_ref": "close",
    "tier": "recomputed",
    "grade": "self-attested",
    "sufficiency": "SATISFIED",
    "verdict": "met",
    "evidence": [digest_ref(own_close_content), digest_ref(peer_rebuttal_content)],
    "proofs": [proof_ref("inclusion_proof", close_proof_content)],
    "presentation": {
        "kind": "disclosure",
        "status": "SATISFIED",
        "evidence": [digest_ref(own_close_content), digest_ref(peer_rebuttal_content)],
    },
    "close": {
        "period": DAY_1,
        "close_state": "CONTESTED",
        "peer": "oo-sor",
        "peer_close_ref": digest_ref(peer_rebuttal_content),
    },
}

# --- close-1 (UNILATERAL) -- no peer record acknowledges or rebuts ours; --
#     no peer named
close_unilateral: ClaimDoc = {
    "id": "close-1",
    "type": "close",
    "contract_ref": RECONCILE_CONTRACT_REF,
    "requirement_ref": "close",
    "tier": "recomputed",
    "grade": "self-attested",
    "sufficiency": "SATISFIED",
    "verdict": "met",
    "evidence": [digest_ref(own_close_content)],
    "proofs": [proof_ref("inclusion_proof", close_proof_content)],
    "presentation": {
        "kind": "disclosure",
        "status": "SATISFIED",
        "evidence": [digest_ref(own_close_content)],
    },
    "close": {
        "period": DAY_1,
        "close_state": "UNILATERAL",
    },
}


def _close_result(close_claim: ClaimDoc, title: str) -> EvidenceResultDoc:
    return {
        "result_version": "evidence-result-v0",
        "generated_at": GENERATED_AT,
        "claims": [claim_1, close_claim],
        "aggregate": {
            "coverage": {
                "evaluated_population": 2,
                "excluded_not_applicable": 0,
                "unknown_count": 0,
            },
            "buckets": {
                "met": ["claim-1", "close-1"],
                "not_met": [],
                "not_evaluable": [],
            },
        },
        "view": {
            "spec_version": "presentation/v1",
            "producer_name": "OO",
            "title": title,
        },
    }


pos_oo_close_agreed_result = _close_result(close_agreed, "OO Close -- 2026-09-01 (agreed)")
pos_oo_close_unilateral_result = _close_result(close_unilateral, "OO Close -- 2026-09-01 (unilateral)")
pos_oo_close_contested_result = _close_result(close_contested, "OO Close -- 2026-09-01 (contested)")

# --- neg-close-agreed-without-peer -- close-1 AGREED, `peer` removed -----
#     (CloseClaim's AGREED rule: peer + peer_close_ref required)
neg_close_agreed_without_peer = _mutated(pos_oo_close_agreed_result)
del neg_close_agreed_without_peer["claims"][1]["close"]["peer"]

# --- neg-close-contested-without-peer-close-ref -- close-1 CONTESTED, ----
#     `peer_close_ref` removed (CloseClaim's AGREED-or-CONTESTED rule: a
#     contested close must cite the rebutting record)
neg_close_contested_without_peer_close_ref = _mutated(pos_oo_close_contested_result)
del neg_close_contested_without_peer_close_ref["claims"][1]["close"]["peer_close_ref"]

# --- neg-reconcile-tallies-missing-state -- reconcile-1 tallies.unresolved
#     removed (ReconcileTallies requires all six; absent is never zero)
neg_reconcile_tallies_missing_state = _mutated(pos_oo_reconcile_result)
del neg_reconcile_tallies_missing_state["claims"][1]["reconcile"]["tallies"]["unresolved"]

# --- neg-unrecognized-claim-type -- claim-1 given a type outside ----------
#     ClaimType's closed enum. Fails HERE (schema is closed-world); the
#     viewer renders this same fixture as an "unrecognized" row, never
#     dropped (ruling 2026-09-25) -- that half lives in capsule-viewer.
neg_unrecognized_claim_type = _mutated(pos_oo_claims_result)
neg_unrecognized_claim_type["claims"][0]["type"] = "adjudication"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write("pos-oo-claims-result", pos_oo_claims_result)
    write("neg-untiered-claim", neg_untiered_claim)
    write("neg-met-with-sufficiency-gap", neg_met_with_sufficiency_gap)
    write("neg-aggregate-without-coverage", neg_aggregate_without_coverage)
    write("neg-contract-ref-missing", neg_contract_ref_missing)
    write("neg-disclosure-carrier-under-withheld", neg_disclosure_carrier_under_withheld)
    write("pos-oo-reconcile-result", pos_oo_reconcile_result)
    write("pos-oo-close-agreed-result", pos_oo_close_agreed_result)
    write("pos-oo-close-unilateral-result", pos_oo_close_unilateral_result)
    write("pos-oo-close-contested-result", pos_oo_close_contested_result)
    write("neg-close-agreed-without-peer", neg_close_agreed_without_peer)
    write("neg-close-contested-without-peer-close-ref", neg_close_contested_without_peer_close_ref)
    write("neg-reconcile-tallies-missing-state", neg_reconcile_tallies_missing_state)
    write("neg-unrecognized-claim-type", neg_unrecognized_claim_type)
    return 0


if __name__ == "__main__":
    sys.exit(main())
