#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
generate_judge_examples.py

Generates the judge-record-family-v1 example fixtures under vectors/judge/,
using this repository's own canonicalization
(agent_action_capsule.canonical.json_digest -- lowercase-hex SHA-256 of
UTF8(JCS(value))) to compute every digest in the fixtures. No digest in the
committed output is hand-typed placeholder hex.

One positive fixture per schema (schemas/judge/*.json) and one negative
fixture per schema, each a byte-for-byte copy of its positive with exactly
one field changed to violate exactly one documented rule -- see
spec/judge-record-family-v1.md and vectors/judge/README.md.

The evaluation-report/v1 positive fixture's case-1 act citation is content-
shaped like a tau2 airline benchmark conversation turn (sim_id/task_id/trial/
messages -- capsule-compiler's examples/data/tau2_airline/ fixture family);
case-1's verdict is the one-line rewrite of that family's hand_labels.json
row shape ({sim_id, hand_label: bool, predicted: bool}) onto this schema's
{case_id, verdict}: hand_label True -> "met", False -> "not_met" -- the
DONE-criterion rewrite, made concrete rather than asserted.

Regenerate with:
    python3 schemas/generate_judge_examples.py
Then check with:
    python3 schemas/check_judge_record_examples.py
"""
import copy
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_action_capsule.canonical import json_digest  # noqa: E402
from _judge_types import (  # noqa: E402
    AdjudicationDoc,
    AdjudicationResponseDoc,
    CalibrationSummaryDoc,
    CaseDoc,
    CitationDoc,
    ClauseTallyDoc,
    CloseDoc,
    ContractCompileDoc,
    DigestRefDoc,
    EvaluationReportDoc,
    HumanRatingDoc,
    ReconcileDoc,
    SampleManifestDoc,
)

OUT_DIR = REPO_ROOT / "vectors" / "judge"
GENERATED_AT = "2026-09-25T00:00:00Z"


def digest_ref(value: object) -> DigestRefDoc:
    return {"digest_alg": "SHA-256", "digest": json_digest(value)}


def citation(kind: str, purpose: str, value: object) -> CitationDoc:
    ref = digest_ref(value)
    return {
        "type": kind,
        "digest_alg": ref["digest_alg"],
        "digest": ref["digest"],
        "citation_purpose": purpose,
    }


def write(subdir: str, name: str, obj: object) -> None:
    out_dir = OUT_DIR / subdir
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.json"
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(REPO_ROOT)}")


# ---------------------------------------------------------------------------
# contract-compile/v1
# ---------------------------------------------------------------------------

_contract_content = {"note": "OO evidence contract, v1 placeholder"}
_compiled_skill_content = {"note": "OO compiled skill artifact, v1 placeholder"}
_human_approval_content = {"note": "OO human approval record, v1 placeholder"}

contract_compile_pos: ContractCompileDoc = {
    "record_version": "contract-compile/v1",
    "record_id": "cc-oo-1",
    "epistemic_type": "producer_claim",
    "compiled_at": GENERATED_AT,
    "contract_ref": "ec:oo-claims-eval:2026-09-22@1",
    "contract": citation("evidence-contract", "compiles_contract", _contract_content),
    "compiled_skill": [citation("compiled-skill", "compiled_skill", _compiled_skill_content)],
    "human_approval": citation("human-approval-record", "approves", _human_approval_content),
}
write("contract-compile", "pos-oo-contract-compile", contract_compile_pos)

contract_compile_neg = copy.deepcopy(contract_compile_pos)
del contract_compile_neg["human_approval"]
write("contract-compile", "neg-missing-human-approval", contract_compile_neg)


# ---------------------------------------------------------------------------
# adjudication/v1
# ---------------------------------------------------------------------------

_half_a_content = {"note": "OO twin half A output, v1 placeholder"}
_half_b_content = {"note": "OO twin half B output, v1 placeholder"}

adjudication_pos: AdjudicationDoc = {
    "record_version": "adjudication/v1",
    "record_id": "adj-oo-1",
    "epistemic_type": "adjudication",
    "adjudicated_at": GENERATED_AT,
    "verdict": "contradicted",
    "contradicted_party": "half-b",
    "margin": "0.42",
    "margin_tau": "0.05",
    "divergence_index": "0.37",
    "basis": {
        "model_id": "oo-referee-v1",
        "prompt_digest": digest_ref({"note": "OO referee prompt, v1 placeholder"}),
        "weights_digest": digest_ref({"note": "OO referee weights, v1 placeholder"}),
        "sampling": {"temperature_micros": 0, "seed": 7},
    },
    "parties": [
        citation("twin-half", "adjudicated_party", _half_a_content),
        citation("twin-half", "adjudicated_party", _half_b_content),
    ],
}
write("adjudication", "pos-oo-twin-adjudication", adjudication_pos)

adjudication_neg = copy.deepcopy(adjudication_pos)
del adjudication_neg["contradicted_party"]
write("adjudication", "neg-contradicted-missing-party", adjudication_neg)


# ---------------------------------------------------------------------------
# adjudication-response/v1
# ---------------------------------------------------------------------------

_adjudication_ref_content = {"note": "OO twin adjudication record adj-oo-1, v1 placeholder"}

adjudication_response_pos: AdjudicationResponseDoc = {
    "record_version": "adjudication-response/v1",
    "record_id": "adjr-oo-1",
    "epistemic_type": "producer_claim",
    "responded_at": GENERATED_AT,
    "kind": "delivery_receipt",
    "adjudication": citation("adjudication", "responds_to", _adjudication_ref_content),
}
write("adjudication-response", "pos-oo-delivery-receipt", adjudication_response_pos)

adjudication_response_neg = copy.deepcopy(adjudication_response_pos)
adjudication_response_neg["verdict"] = "contradicted"
write("adjudication-response", "neg-delivery-receipt-with-verdict", adjudication_response_neg)


# ---------------------------------------------------------------------------
# evaluation-report/v1 -- case-1's act citation is tau2-conversation-shaped;
# case-1's verdict is the hand_labels.json rewrite documented above.
# ---------------------------------------------------------------------------

_tau2_case1_conversation = {
    "sim_id": "oo-sim-001",
    "task_id": "oo-task-airline-001",
    "trial": 0,
    "termination_reason": "user_stop",
    "messages": [
        {"role": "user", "content": "OO placeholder user turn"},
        {"role": "assistant", "content": "OO placeholder assistant turn", "tool_call_names": ["book_flight"]},
    ],
}
# tau2 hand_labels.json row: {"sim_id": "oo-sim-001", "hand_label": true, "predicted": true}
# one-line rewrite onto this schema: hand_label True -> verdict "met".
_tau2_case1_hand_label = True

_method_content = {"note": "OO axis A1 grounding rubric, v1 placeholder"}

evaluation_report_pos: EvaluationReportDoc = {
    "record_version": "evaluation-report/v1",
    "record_id": "er-oo-1",
    "epistemic_type": "semantic_judgment",
    "generated_at": GENERATED_AT,
    "contract_ref": "ec:oo-claims-eval:2026-09-22@1",
    "judge_pin": {
        "model_id": "oo-judge-v1",
        "prompt_digest": digest_ref({"note": "OO judge prompt, v1 placeholder"}),
        "axes_digest": digest_ref({"note": "OO axes A1/A3/A5/A7, v1 placeholder"}),
        "sampling": {"temperature_micros": 0, "seed": 1},
    },
    "cases": [
        {
            "case_id": "oo-sim-001",
            "verdict": "met" if _tau2_case1_hand_label else "not_met",
            "acts": [citation("tau2-conversation", "grounds", _tau2_case1_conversation)],
            "method": citation("rubric", "method", _method_content),
        }
    ],
}
write("evaluation-report", "pos-oo-evaluation-report", evaluation_report_pos)

evaluation_report_neg = copy.deepcopy(evaluation_report_pos)
del evaluation_report_neg["cases"][0]["method"]
write("evaluation-report", "neg-case-without-method", evaluation_report_neg)


# ---------------------------------------------------------------------------
# close/v1
# ---------------------------------------------------------------------------

_peer_close_content = {"note": "OO peer store's Close record, v1 placeholder"}

close_pos: CloseDoc = {
    "record_version": "close/v1",
    "record_id": "close-oo-1",
    "epistemic_type": "producer_claim",
    "closed_at": GENERATED_AT,
    "period": {"start": "2026-09-01T00:00:00Z", "end": "2026-09-25T00:00:00Z"},
    "counts_by_kind": {"observation": 12, "evaluation-report": 1},
    "head": digest_ref({"note": "OO store head at close, v1 placeholder"}),
    "reconcile": {
        "tallies": {
            "matched": 10,
            "a_only": 1,
            "b_only": 0,
            "conflicting": 0,
            "insufficient": 1,
            "unresolved": 0,
        },
        "peer_close": citation("close", "reconciles_with", _peer_close_content),
        "status": "AGREED",
    },
}
write("close", "pos-oo-close", close_pos)

close_neg = copy.deepcopy(close_pos)
del close_neg["reconcile"]["peer_close"]
write("close", "neg-reconcile-without-peer-close", close_neg)


# ---------------------------------------------------------------------------
# sample-manifest/v1
# ---------------------------------------------------------------------------

_policy_content = {"note": "OO stratified sampling policy, v1 placeholder"}

sample_manifest_pos: SampleManifestDoc = {
    "record_version": "sample-manifest/v1",
    "record_id": "sm-oo-1",
    "epistemic_type": "producer_claim",
    "generated_at": GENERATED_AT,
    "policy": citation("sampling-policy", "sampling_policy", _policy_content),
    "stratification": {"held_out": 40, "regression": 10},
    "cases": ["oo-sim-001", "oo-sim-002"],
}
write("sample-manifest", "pos-oo-sample-manifest", sample_manifest_pos)

sample_manifest_neg = copy.deepcopy(sample_manifest_pos)
sample_manifest_neg["cases"] = []
write("sample-manifest", "neg-cases-empty", sample_manifest_neg)


# ---------------------------------------------------------------------------
# human-rating/v1
# ---------------------------------------------------------------------------

_rated_case_content = {"note": "OO rated case, v1 placeholder"}

human_rating_pos: HumanRatingDoc = {
    "record_version": "human-rating/v1",
    "record_id": "hr-oo-1",
    "epistemic_type": "human_report",
    "rated_at": GENERATED_AT,
    "blind": True,
    "rater_ref": "principal:oo-rater-7f3c",
    "case": citation("rated-case", "rated_case", _rated_case_content),
    "label": "met",
}
write("human-rating", "pos-oo-human-rating", human_rating_pos)

human_rating_neg = copy.deepcopy(human_rating_pos)
human_rating_neg["blind"] = False
write("human-rating", "neg-blind-false", human_rating_neg)


# ---------------------------------------------------------------------------
# calibration-summary/v1
# ---------------------------------------------------------------------------

_judge_pin_content = {"note": "OO judge pin, v1 placeholder"}

calibration_summary_pos: CalibrationSummaryDoc = {
    "record_version": "calibration-summary/v1",
    "record_id": "cal-oo-1",
    "epistemic_type": "derived_metric",
    "computed_at": GENERATED_AT,
    "judge_pin": citation("judge-pin", "calibrates", _judge_pin_content),
    "clauses": [
        {
            "clause_ref": "req-claim-1",
            "agreement": {"k": 17, "n": 20},
            "drift": {"k": 1, "n": 20},
        }
    ],
}
write("calibration-summary", "pos-oo-calibration-summary", calibration_summary_pos)

calibration_summary_neg = copy.deepcopy(calibration_summary_pos)
calibration_summary_neg["clauses"][0]["agreement"]["rate"] = 0.85
write("calibration-summary", "neg-clause-with-rate-field", calibration_summary_neg)

print("done")
