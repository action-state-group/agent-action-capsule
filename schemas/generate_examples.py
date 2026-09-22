#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
generate_examples.py

Generates the Evidence Plan IR v0 example fixtures under
schemas/examples/evidence-plan-ir-v0/, using this repository's own
canonicalization (agent_action_capsule.canonical.json_digest — lowercase-hex
SHA-256 of UTF8(JCS(value)), the same convention the Evidence Bundle draft
uses) to compute every digest in the fixtures. No digest in the committed
output is hand-typed placeholder hex.

Three positive plans (one per Evidence Contract profile: outcome, obligation,
process), one matching plan-result per plan, one attestation-record per
judged node, and one deliberately nonconforming plan (a LOCAL_ONLY node
serialized into a plan whose planner_id is not local:) that spec
evidence-plan-ir-v0.md section 4.1 requires to fail schema validation.

Regenerate with:
    python3 schemas/generate_examples.py
Then check with:
    python3 schemas/check_evidence_plan_ir_examples.py
"""
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_action_capsule.canonical import json_digest  # noqa: E402
from _ir_types import (  # noqa: E402
    AdjudicatorDoc,
    AttestationRecordDoc,
    DigestRefDoc,
    IRDocument,
    InputByDigestDoc,
    InputByNodeDoc,
    PlanResultDoc,
    ResultEnvelopeDoc,
)

OUT_DIR = Path(__file__).resolve().parent / "examples" / "evidence-plan-ir-v0"


def digest_ref(value: object) -> DigestRefDoc:
    return {"digest_alg": "SHA-256", "digest": json_digest(value)}


def input_by_digest(value: object) -> InputByDigestDoc:
    ref = digest_ref(value)
    return {"by": "digest", "digest_alg": ref["digest_alg"], "digest": ref["digest"]}


def input_by_node(node_id: str) -> InputByNodeDoc:
    return {"by": "node", "node_id": node_id}


def build_result(
    status: str, output_value: object, attestation_record: AttestationRecordDoc
) -> ResultEnvelopeDoc:
    return {
        "status": status,
        "outputs": [digest_ref(output_value)],
        "attestation_ref": digest_ref(attestation_record),
    }


def build_plan_result(plan: IRDocument, results: Dict[str, ResultEnvelopeDoc]) -> PlanResultDoc:
    return {"plan_ref": digest_ref(plan), "results": results}


def build_attestation(
    *,
    adjudicator_id: str,
    operator: str,
    inputs: List[object],
    policy: object,
    contract_version: str,
    model: Optional[str] = None,
    model_version: Optional[str] = None,
) -> AttestationRecordDoc:
    adjudicator: AdjudicatorDoc = {"id": adjudicator_id}
    if model is not None:
        adjudicator["model"] = model
        adjudicator["model_version"] = model_version
    return {
        "adjudicator": adjudicator,
        "operator": operator,
        "inputs": [digest_ref(v) for v in inputs],
        "policy_digest": digest_ref(policy),
        "contract_version": contract_version,
    }


def write(name: str, obj: IRDocument) -> None:
    path = OUT_DIR / f"{name}.json"
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(REPO_ROOT)}")


# ---------------------------------------------------------------------------
# Plan 1 — outcome profile
# ---------------------------------------------------------------------------

OUTCOME_CONTRACT = "ec:oo-outcome-eval:2026-09-22@1"
outcome_evidence_content = {"note": "OO outcome eligibility evidence artifact, v0 placeholder"}
outcome_policy = {"note": "OO outcome eligibility policy manifest, v0 placeholder"}

outcome_node1_result_output = {"note": "OO outcome answer artifact recomputed", "requirement": "req-outcome-1"}
outcome_node1_attestation = build_attestation(
    adjudicator_id="oo-evidence-responder-v0",
    operator="evidence.request_answer",
    inputs=[outcome_evidence_content],
    policy=outcome_policy,
    contract_version=OUTCOME_CONTRACT,
)

outcome_node2_result_output = {"note": "OO outcome verified binding+inclusion, v0 placeholder"}
outcome_node2_attestation = build_attestation(
    adjudicator_id="oo-assurance-verifier-v0",
    operator="assurance.verify",
    inputs=[outcome_node1_result_output],
    policy=outcome_policy,
    contract_version=OUTCOME_CONTRACT,
)

outcome_node3_result_output = {"verdict": "met"}
outcome_node3_attestation = build_attestation(
    adjudicator_id="oo-decision-resolver-v0",
    operator="decision.resolve_verdict",
    inputs=[outcome_node2_result_output],
    policy=outcome_policy,
    contract_version=OUTCOME_CONTRACT,
)

plan_outcome = {
    "header": {
        "contract_version": OUTCOME_CONTRACT,
        "ir_version": "evidence-plan-ir-v0",
        "planner_id": "remote:oo-cloud-planner-v1",
        "created_at": "2026-09-22T00:00:00Z",
        "replay_seed": "oo-outcome-eval-seed-1",
    },
    "nodes": [
        {
            "id": "node-1",
            "family": "evidence",
            "operator": "evidence.request_answer",
            "inputs": [input_by_digest(outcome_evidence_content)],
            "classification": "CLOUD_SAFE",
            "tier": "recomputed",
            "contract_ref": OUTCOME_CONTRACT,
            "requirement_ref": "req-outcome-1",
        },
        {
            "id": "node-2",
            "family": "assurance",
            "operator": "assurance.verify",
            "inputs": [input_by_node("node-1")],
            "classification": "CLOUD_SAFE",
            "tier": "recomputed",
            "contract_ref": OUTCOME_CONTRACT,
            "requirement_ref": "req-outcome-1",
        },
        {
            "id": "node-3",
            "family": "decision",
            "operator": "decision.resolve_verdict",
            "inputs": [input_by_node("node-2")],
            "classification": "PUBLIC",
            "tier": "recomputed",
            "contract_ref": OUTCOME_CONTRACT,
            "requirement_ref": "req-outcome-1",
        },
    ],
}

plan_outcome_result = build_plan_result(
    plan_outcome,
    {
        "node-1": build_result("SATISFIED", outcome_node1_result_output, outcome_node1_attestation),
        "node-2": build_result("SATISFIED", outcome_node2_result_output, outcome_node2_attestation),
        "node-3": build_result("SATISFIED", outcome_node3_result_output, outcome_node3_attestation),
    },
)

# ---------------------------------------------------------------------------
# Plan 2 — obligation profile (exercises traditional + semantic + LOCAL_ONLY
# under a local: planner — the positive counterpart to the negative fixture)
# ---------------------------------------------------------------------------

OBLIGATION_CONTRACT = "ec:oo-obligation-review:2026-09-22@1"
obligation_ledger_content = {"note": "OO retention-control ledger replay input, v0 placeholder"}
obligation_policy = {"note": "OO obligation review policy manifest, v0 placeholder"}

obligation_node1_result_output = {"note": "OO retention evidence replay result, v0 placeholder"}
obligation_node1_attestation = build_attestation(
    adjudicator_id="oo-fold-engine-v0",
    operator="traditional.fold_replay",
    inputs=[obligation_ledger_content],
    policy=obligation_policy,
    contract_version=OBLIGATION_CONTRACT,
)

obligation_node2_result_output = {"note": "OO exception qualitative review, judged", "requirement": "req-obligation-1"}
obligation_node2_attestation = build_attestation(
    adjudicator_id="oo-judge-harness-v0",
    operator="semantic.judge_adjudicate",
    inputs=[obligation_node1_result_output],
    policy=obligation_policy,
    contract_version=OBLIGATION_CONTRACT,
    model="oo-synthetic-judge-model",
    model_version="2026-09-22",
)

obligation_node3_result_output = {"verdict": "met"}
obligation_node3_attestation = build_attestation(
    adjudicator_id="oo-decision-resolver-v0",
    operator="decision.resolve_verdict",
    inputs=[obligation_node2_result_output],
    policy=obligation_policy,
    contract_version=OBLIGATION_CONTRACT,
)

plan_obligation = {
    "header": {
        "contract_version": OBLIGATION_CONTRACT,
        "ir_version": "evidence-plan-ir-v0",
        "planner_id": "local:oo-onprem-planner-v1",
        "created_at": "2026-09-22T00:00:00Z",
        "replay_seed": "oo-obligation-review-seed-1",
    },
    "nodes": [
        {
            "id": "node-1",
            "family": "traditional",
            "operator": "traditional.fold_replay",
            "inputs": [input_by_digest(obligation_ledger_content)],
            "classification": "LOCAL_ONLY",
            "tier": "recomputed",
            "contract_ref": OBLIGATION_CONTRACT,
            "requirement_ref": "req-obligation-1",
        },
        {
            "id": "node-2",
            "family": "semantic",
            "operator": "semantic.judge_adjudicate",
            "inputs": [input_by_node("node-1")],
            "classification": "ABSTRACTABLE",
            "tier": "judged",
            "contract_ref": OBLIGATION_CONTRACT,
            "requirement_ref": "req-obligation-1",
        },
        {
            "id": "node-3",
            "family": "decision",
            "operator": "decision.resolve_verdict",
            "inputs": [input_by_node("node-2")],
            "classification": "PUBLIC",
            "tier": "recomputed",
            "contract_ref": OBLIGATION_CONTRACT,
            "requirement_ref": "req-obligation-1",
        },
    ],
}

plan_obligation_result = build_plan_result(
    plan_obligation,
    {
        "node-1": build_result("SATISFIED", obligation_node1_result_output, obligation_node1_attestation),
        "node-2": build_result("SATISFIED", obligation_node2_result_output, obligation_node2_attestation),
        "node-3": build_result("SATISFIED", obligation_node3_result_output, obligation_node3_attestation),
    },
)

# ---------------------------------------------------------------------------
# Plan 3 — process profile (traditional + assurance.bundle, remote: planner,
# no LOCAL_ONLY node — the base this file's negative fixture mutates)
# ---------------------------------------------------------------------------

PROCESS_CONTRACT = "ec:oo-process-review:2026-09-22@1"
process_vcs_content = {"note": "OO review-before-merge vcs event replay input, v0 placeholder"}
process_policy = {"note": "OO process review policy manifest, v0 placeholder"}

process_node1_result_output = {"note": "OO process sequence replay result, v0 placeholder"}
process_node1_attestation = build_attestation(
    adjudicator_id="oo-fold-engine-v0",
    operator="traditional.fold_replay",
    inputs=[process_vcs_content],
    policy=process_policy,
    contract_version=PROCESS_CONTRACT,
)

process_node2_result_output = {"note": "OO process proof bundle, v0 placeholder"}
process_node2_attestation = build_attestation(
    adjudicator_id="oo-bundle-assembler-v0",
    operator="assurance.bundle",
    inputs=[process_node1_result_output],
    policy=process_policy,
    contract_version=PROCESS_CONTRACT,
)

process_node3_result_output = {"verdict": "met"}
process_node3_attestation = build_attestation(
    adjudicator_id="oo-decision-resolver-v0",
    operator="decision.resolve_verdict",
    inputs=[process_node2_result_output],
    policy=process_policy,
    contract_version=PROCESS_CONTRACT,
)

plan_process = {
    "header": {
        "contract_version": PROCESS_CONTRACT,
        "ir_version": "evidence-plan-ir-v0",
        "planner_id": "remote:oo-cloud-planner-v1",
        "created_at": "2026-09-22T00:00:00Z",
        "replay_seed": "oo-process-review-seed-1",
    },
    "nodes": [
        {
            "id": "node-1",
            "family": "traditional",
            "operator": "traditional.fold_replay",
            "inputs": [input_by_digest(process_vcs_content)],
            "classification": "CLOUD_SAFE",
            "tier": "recomputed",
            "contract_ref": PROCESS_CONTRACT,
            "requirement_ref": "req-process-1",
        },
        {
            "id": "node-2",
            "family": "assurance",
            "operator": "assurance.bundle",
            "inputs": [input_by_node("node-1")],
            "classification": "CLOUD_SAFE",
            "tier": "recomputed",
            "contract_ref": PROCESS_CONTRACT,
            "requirement_ref": "req-process-1",
        },
        {
            "id": "node-3",
            "family": "decision",
            "operator": "decision.resolve_verdict",
            "inputs": [input_by_node("node-2")],
            "classification": "PUBLIC",
            "tier": "recomputed",
            "contract_ref": PROCESS_CONTRACT,
            "requirement_ref": "req-process-1",
        },
    ],
}

plan_process_result = build_plan_result(
    plan_process,
    {
        "node-1": build_result("SATISFIED", process_node1_result_output, process_node1_attestation),
        "node-2": build_result("SATISFIED", process_node2_result_output, process_node2_attestation),
        "node-3": build_result("SATISFIED", process_node3_result_output, process_node3_attestation),
    },
)

# ---------------------------------------------------------------------------
# Negative fixture — a LOCAL_ONLY node serialized into a plan whose
# planner_id is remote: (spec 4.1). Mutated from plan_process: node-1's
# classification changes from CLOUD_SAFE to LOCAL_ONLY; the header keeps its
# remote: planner_id. MUST fail schema validation.
# ---------------------------------------------------------------------------

plan_invalid_local_only_under_remote_planner = json.loads(json.dumps(plan_process))
plan_invalid_local_only_under_remote_planner["nodes"][0]["classification"] = "LOCAL_ONLY"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write("plan-outcome", plan_outcome)
    write("plan-outcome-result", plan_outcome_result)
    write("plan-obligation", plan_obligation)
    write("plan-obligation-result", plan_obligation_result)
    write("plan-process", plan_process)
    write("plan-process-result", plan_process_result)
    write("attestation-record-example", obligation_node2_attestation)
    write("invalid-local-only-under-remote-planner", plan_invalid_local_only_under_remote_planner)
    return 0


if __name__ == "__main__":
    sys.exit(main())
