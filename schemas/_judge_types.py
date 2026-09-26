# SPDX-License-Identifier: BSD-3-Clause
"""
Named document shapes for the judge-record-family-v1 example generator and
checker (generate_judge_examples.py, check_judge_record_examples.py).

These TypedDicts mirror schemas/judge/*.json's $defs field-for-field, the
same discipline schemas/_result_types.py applies for Evidence Result v0.
This module is not part of the agent_action_capsule package and is not
installed or imported by it.
"""
from typing import Dict, List, Literal, TypedDict, Union


class DigestRefDoc(TypedDict):
    digest_alg: Literal["SHA-256"]
    digest: str


class CitationDoc(TypedDict):
    type: str
    digest_alg: Literal["SHA-256"]
    digest: str
    citation_purpose: str


class SamplingParamsDoc(TypedDict, total=False):
    temperature_micros: int
    top_p_micros: int
    seed: int


class BasisDoc(TypedDict, total=False):
    model_id: str
    prompt_digest: DigestRefDoc
    axes_digest: DigestRefDoc
    weights_digest: DigestRefDoc
    sampling: SamplingParamsDoc


# --- contract-compile/v1 ----------------------------------------------------

class ContractCompileDoc(TypedDict):
    record_version: Literal["contract-compile/v1"]
    record_id: str
    epistemic_type: Literal["producer_claim"]
    compiled_at: str
    contract_ref: str
    contract: CitationDoc
    compiled_skill: List[CitationDoc]
    human_approval: CitationDoc


# --- adjudication/v1 ---------------------------------------------------------

class AdjudicationDoc(TypedDict, total=False):
    record_version: Literal["adjudication/v1"]
    record_id: str
    epistemic_type: Literal["adjudication"]
    adjudicated_at: str
    verdict: str
    contradicted_party: str
    margin: str
    margin_tau: str
    divergence_index: str
    basis: BasisDoc
    parties: List[CitationDoc]
    referee: CitationDoc


# --- adjudication-response/v1 -----------------------------------------------

class AdjudicationResponseDoc(TypedDict, total=False):
    record_version: Literal["adjudication-response/v1"]
    record_id: str
    epistemic_type: Literal["producer_claim"]
    responded_at: str
    kind: str
    adjudication: CitationDoc
    verdict: str
    basis: str


# --- evaluation-report/v1 ----------------------------------------------------

class CaseDoc(TypedDict):
    case_id: str
    verdict: str
    acts: List[CitationDoc]
    method: CitationDoc


class EvaluationReportDoc(TypedDict):
    record_version: Literal["evaluation-report/v1"]
    record_id: str
    epistemic_type: Literal["semantic_judgment"]
    generated_at: str
    contract_ref: str
    judge_pin: BasisDoc
    cases: List[CaseDoc]


# --- close/v1 -----------------------------------------------------------------

class PeriodDoc(TypedDict):
    start: str
    end: str


class ReconcileTalliesDoc(TypedDict):
    matched: int
    a_only: int
    b_only: int
    conflicting: int
    insufficient: int
    unresolved: int


class ReconcileDoc(TypedDict):
    tallies: ReconcileTalliesDoc
    peer_close: CitationDoc
    status: str


class CloseDoc(TypedDict, total=False):
    record_version: Literal["close/v1"]
    record_id: str
    epistemic_type: Literal["producer_claim"]
    closed_at: str
    period: PeriodDoc
    counts_by_kind: Dict[str, int]
    head: DigestRefDoc
    reconcile: ReconcileDoc


# --- sample-manifest/v1 -------------------------------------------------------

class SampleManifestDoc(TypedDict):
    record_version: Literal["sample-manifest/v1"]
    record_id: str
    epistemic_type: Literal["producer_claim"]
    generated_at: str
    policy: CitationDoc
    stratification: Dict[str, int]
    cases: List[str]


# --- human-rating/v1 -----------------------------------------------------------

class HumanRatingDoc(TypedDict):
    record_version: Literal["human-rating/v1"]
    record_id: str
    epistemic_type: Literal["human_report"]
    rated_at: str
    blind: bool
    rater_ref: str
    case: CitationDoc
    label: str


# --- calibration-summary/v1 -----------------------------------------------------

class KOfNDoc(TypedDict):
    k: int
    n: int


class ClauseTallyDoc(TypedDict):
    clause_ref: str
    agreement: KOfNDoc
    drift: KOfNDoc


class CalibrationSummaryDoc(TypedDict):
    record_version: Literal["calibration-summary/v1"]
    record_id: str
    epistemic_type: Literal["derived_metric"]
    computed_at: str
    judge_pin: CitationDoc
    clauses: List[ClauseTallyDoc]


JudgeRecordDoc = Union[
    ContractCompileDoc,
    AdjudicationDoc,
    AdjudicationResponseDoc,
    EvaluationReportDoc,
    CloseDoc,
    SampleManifestDoc,
    HumanRatingDoc,
    CalibrationSummaryDoc,
]
