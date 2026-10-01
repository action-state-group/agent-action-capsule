# SPDX-License-Identifier: BSD-3-Clause
"""
Named document shapes for the Evidence Result v0 example generator and
checker (generate_result_examples.py, check_evidence_result_examples.py).

These TypedDicts mirror schemas/evidence-result-v0.json's $defs field-for-
field; they exist so the generator's own signatures carry the same shape the
schema validates, rather than passing bare dicts between functions that build
and check the same fixtures. This module is not part of the
agent_action_capsule package and is not installed or imported by it.
"""
from typing import List, Literal, TypedDict, Union


class DigestRefDoc(TypedDict):
    digest_alg: Literal["SHA-256"]
    digest: str


class ProofRefDoc(TypedDict):
    kind: Literal["inclusion_proof", "receipt"]
    digest_alg: Literal["SHA-256"]
    digest: str


class DisclosureCarrierDoc(TypedDict):
    kind: Literal["disclosure"]
    status: str
    evidence: List[DigestRefDoc]


class AnalysisCarrierDoc(TypedDict):
    kind: Literal["analysis"]
    status: str
    summary: str


class StoryCarrierDoc(TypedDict):
    kind: Literal["story"]
    status: str
    narrative: str


PresentationDoc = Union[DisclosureCarrierDoc, AnalysisCarrierDoc, StoryCarrierDoc]


class PeriodDoc(TypedDict):
    start: str
    end: str


class ReconcileTalliesDoc(TypedDict):
    # Keyed as schemas/judge/close-v1.json's ReconcileTallies keys them.
    matched: int
    a_only: int
    b_only: int
    conflicting: int
    insufficient: int
    unresolved: int


class ReconcileClaimDoc(TypedDict):
    join_key: str
    peer: str
    period: PeriodDoc
    tallies: ReconcileTalliesDoc
    state_of_record: Literal["A", "B", "none"]


class CloseClaimDoc(TypedDict, total=False):
    period: PeriodDoc
    close_state: Literal["UNILATERAL", "AGREED", "CONTESTED"]
    close_ref: DigestRefDoc  # the Close this claim reports on; its inbound links derive close_state
    peer: str
    peer_close_ref: DigestRefDoc


class LinkDoc(TypedDict):
    # draft-mih-agent-evidence-layer-00 "Typed Links": a typed, directed
    # reference to a target record by digest.
    type: Literal["cites", "adjudicates", "supersedes", "acknowledges", "rebuts", "closes"]
    target: str


class RecordDoc(TypedDict, total=False):
    # The evidence-book record header shape a bundle discloses for a
    # record (evidencebook HeaderMember). Only the members the close-state
    # link walk reads are named here; a record may carry more.
    v: int
    book_id: str
    seq: int
    record_type: str
    epistemic_type: str
    committed_at: str
    event_time_claim: str
    links: list[LinkDoc]
    subject_ref: str
    statement: dict


class _ClaimTypedBodyDoc(TypedDict, total=False):
    # PROPOSED (2026-09-25 ruling): absent `type` means `requirement`; the
    # body key present must match `type` (schema's type<->body binding).
    type: Literal["requirement", "reconcile", "close"]
    reconcile: ReconcileClaimDoc
    close: CloseClaimDoc


class ClaimDoc(_ClaimTypedBodyDoc):
    id: str
    contract_ref: str
    requirement_ref: str
    tier: str
    grade: str
    sufficiency: str
    verdict: str
    evidence: List[DigestRefDoc]
    proofs: List[ProofRefDoc]
    presentation: PresentationDoc


class CoverageDoc(TypedDict):
    evaluated_population: int
    excluded_not_applicable: int
    unknown_count: int


class BucketsDoc(TypedDict):
    met: List[str]
    not_met: List[str]
    not_evaluable: List[str]


class AggregateDoc(TypedDict):
    coverage: CoverageDoc
    buckets: BucketsDoc


class ViewDoc(TypedDict, total=False):
    spec_version: Literal["presentation/v1"]
    producer_name: str
    logo_data_url: str
    title: str


class RemedyDoc(TypedDict):
    connector: str
    raises_to: str


class _SourceCoverageOptionalDoc(TypedDict, total=False):
    epistemic_type: str


class SourceCoverageDoc(_SourceCoverageOptionalDoc):
    source: str
    status: str
    record_count: int
    contemporaneous_count: int
    backfilled_count: int
    duplicates_collapsed: int
    producer_count: int
    evidence: List[DigestRefDoc]


class IndependenceDoc(TypedDict):
    required_producers: int
    independent_producers: int
    correlated_records: int
    unattributed_records: int
    producer_basis: str
    met: bool


class CoverageGapDoc(TypedDict, total=False):
    kind: str
    source: str
    detail: str
    remedy: Union[RemedyDoc, None]


class RequirementCoverageDoc(TypedDict):
    requirement_ref: str
    obligation_refs: List[str]
    status: str
    sufficiency: str
    claim_ids: List[str]
    sources: List[SourceCoverageDoc]
    independence: IndependenceDoc
    gaps: List[CoverageGapDoc]


class CoverageSummaryDoc(TypedDict):
    requirements: int
    satisfied: int
    with_gaps: int
    gaps: int
    gaps_without_remedy: int


class CoverageReportDoc(TypedDict):
    spec_version: Literal["coverage-report/v0"]
    contract_ref: str
    requirements: List[RequirementCoverageDoc]
    summary: CoverageSummaryDoc


class EvidenceResultDoc(TypedDict, total=False):
    result_version: Literal["evidence-result-v0"]
    generated_at: str
    claims: List[ClaimDoc]
    aggregate: AggregateDoc
    view: ViewDoc
    coverage_report: CoverageReportDoc
