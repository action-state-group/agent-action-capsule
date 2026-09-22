# SPDX-License-Identifier: BSD-3-Clause
"""
Named document shapes for the Evidence Plan IR v0 example generator and
checker (generate_examples.py, check_evidence_plan_ir_examples.py).

These TypedDicts mirror schemas/evidence-plan-ir-v0.json's $defs field-for-
field; they exist so the generator's own signatures carry the same shape the
schema validates, rather than passing bare dicts between functions that build
and check the same fixtures. This module is not part of the
agent_action_capsule package and is not installed or imported by it.
"""
from typing import Dict, List, Literal, TypedDict, Union


class DigestRefDoc(TypedDict):
    digest_alg: Literal["SHA-256"]
    digest: str


class InputByDigestDoc(TypedDict):
    by: Literal["digest"]
    digest_alg: Literal["SHA-256"]
    digest: str


class InputByNodeDoc(TypedDict):
    by: Literal["node"]
    node_id: str


InputRefDoc = Union[InputByDigestDoc, InputByNodeDoc]


class PlanHeaderDoc(TypedDict):
    contract_version: str
    ir_version: Literal["evidence-plan-ir-v0"]
    planner_id: str
    created_at: str
    replay_seed: str


class PlanNodeDoc(TypedDict):
    id: str
    family: str
    operator: str
    inputs: List[InputRefDoc]
    classification: str
    tier: str
    contract_ref: str
    requirement_ref: str


class EvidencePlanDoc(TypedDict):
    header: PlanHeaderDoc
    nodes: List[PlanNodeDoc]


class ResultEnvelopeDoc(TypedDict):
    status: str
    outputs: List[DigestRefDoc]
    attestation_ref: DigestRefDoc


class PlanResultDoc(TypedDict):
    plan_ref: DigestRefDoc
    results: Dict[str, ResultEnvelopeDoc]


class AdjudicatorDoc(TypedDict, total=False):
    id: str
    model: str
    model_version: str


class AttestationRecordDoc(TypedDict):
    adjudicator: AdjudicatorDoc
    operator: str
    inputs: List[DigestRefDoc]
    policy_digest: DigestRefDoc
    contract_version: str


# The only three document kinds this fixture set ever loads or writes.
IRDocument = Union[EvidencePlanDoc, PlanResultDoc, AttestationRecordDoc]
