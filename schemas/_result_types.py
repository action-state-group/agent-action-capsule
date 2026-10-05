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


class CodeDigestDoc(TypedDict):
    # git-commit / git-tree with 40 or 64 lowercase hex, or the explicit
    # {"alg": "unknown", "value": "unknown"}. Never a version string.
    alg: Literal["git-commit", "git-tree", "unknown"]
    value: str


class ImplementationDoc(TypedDict):
    # Code identity, kept apart from any policy/configuration digest.
    name: str
    code_digest: CodeDigestDoc
    # Grade vocabulary: self-attested = comparable; witnessed/countersigned
    # = checkable. An unknown code_digest is self-attested only.
    grade: Literal["self-attested", "witnessed", "countersigned"]
    captured_at: str


class _ClaimTypedBodyDoc(TypedDict, total=False):
    # PROPOSED (2026-09-25 ruling): absent `type` means `requirement`; the
    # body key present must match `type` (schema's type<->body binding).
    type: Literal["requirement", "reconcile", "close"]
    reconcile: ReconcileClaimDoc
    close: CloseClaimDoc
    # REQUIRED (known digest) when tier is `recomputed`; optional otherwise.
    implementation: ImplementationDoc


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


class ProducerDefectsDoc(TypedDict):
    # PROPOSED (spec section 3.1): withheld unreproducible recomputed rows.
    count: int
    denominator: int
    as_of: str


class _CoverageOptionalDoc(TypedDict, total=False):
    producer_defects: ProducerDefectsDoc


class CoverageDoc(_CoverageOptionalDoc):
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


class EvidenceResultDoc(TypedDict, total=False):
    result_version: Literal["evidence-result-v0"]
    generated_at: str
    claims: List[ClaimDoc]
    aggregate: AggregateDoc
    view: ViewDoc
