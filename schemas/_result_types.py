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


class ClaimDoc(TypedDict):
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


class EvidenceResultDoc(TypedDict, total=False):
    result_version: Literal["evidence-result-v0"]
    generated_at: str
    claims: List[ClaimDoc]
    aggregate: AggregateDoc
    view: ViewDoc
