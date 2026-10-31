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

Claim types (the 2026-09-25 ruling; reconcile and close both normative):
five more positives --
one reconcile Result, one AGREED close, one UNILATERAL close (no peer
named), one UNILATERAL close that names the peer it closed against, one
CONTESTED close (the Evidence Layer's third Close state, draft-mih-agent-
evidence-layer-00 'Reconcile and Close'). Four of the five pair the
untouched requirement claim-1 with one typed claim; the reconcile positive
carries two (reconcile-1 SATISFIED, reconcile-2 GAP). And four more
negatives (AGREED close without `peer`; CONTESTED close without
`peer_close_ref`; reconcile tallies missing a state; a claim `type` outside
the closed enum), each again one field away from its positive. Reconcile
tallies are keyed as schemas/judge/close-v1.json keys them (lowercase).

close_state is DERIVABLE: every close claim cites its Close (`close_ref`), the cited Close
and peer records are real record headers shipped beside each close fixture
as `<name>.records.json`, and one more negative --
neg-close-agreed-relabelled-contested -- is the CONTESTED positive with
close_state relabelled AGREED. It validates against the schema (that is the
hole) and is rejected by the checker's link walk, which recomputes the state
from the `rebuts` link in the sidecar.

Four negatives pin the further Close rules:
  - neg-close-contested-verdict-met: the CONTESTED positive with verdict
    `met`. A contested Close never counts as met (the positive now carries
    `not_met`); the schema's Claim rule rejects it.
  - neg-close-agreed-self-acknowledged: an AGREED close whose acknowledging
    record is from the producer's OWN book (`book_id` "example-org", seq 42). An
    `acknowledges` / `rebuts` link counts only from a counterparty -- a
    record whose `book_id` differs from the Close's -- so the walk reads
    UNILATERAL and rejects the claim. Schema-valid.
  - neg-close-ref-not-in-evidence / neg-close-peer-ref-not-in-evidence: the
    AGREED positive with `close_ref` (resp. `peer_close_ref`) dropped from
    the claim's `evidence[]`. Both refs MUST resolve inside `evidence[]`;
    the checker rejects each. Schema-valid.

Neither book_id nor signer alone is enough, since a producer can mint a
second book or a second key equally easily, so the counterparty rule is
three-part: (1) a different
`book_id`, (2) the linking book equals the claim's named `peer`, (3) a
different signer key (enforced where the signer is visible: the emitter
and the CLI; the record header here carries none). Two more negatives:
  - neg-close-agreed-third-book: the acknowledging record is from a third
    book (`example-org-audit`, seq 7) that is not the named peer `example-org-sor`. A
    different book, but not the peer: the walk reads UNILATERAL.
  - neg-close-agreed-bookless-close: the cited Close carries no `book_id`;
    the named peer's record acknowledges it. A Close that names no book
    has no counterparty: the walk reads UNILATERAL. (The Close record
    differs, so every digest in this fixture is its own.)

Regenerate with:
    python3 schemas/generate_result_examples.py
Then check with:
    python3 schemas/check_evidence_result_examples.py
"""
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_action_capsule.canonical import json_digest  # noqa: E402
from generate_dataset_examples import DATASET, PLAN  # noqa: E402
from _result_types import (  # noqa: E402
    AggregateDoc,
    ClaimDoc,
    CoverageReportDoc,
    DigestRefDoc,
    EvidenceResultDoc,
    PeriodDoc,
    ProofRefDoc,
    RecordDoc,
)

OUT_DIR = REPO_ROOT / "vectors" / "evidence-result"

CONTRACT_REF = "ec:example-org-claims-eval:2026-09-22@1"
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

claim1_evidence_content = {"note": "EXAMPLE-ORG claim-1 outcome evidence artifact, v0 placeholder"}
claim1_proof_content = {"note": "EXAMPLE-ORG claim-1 inclusion proof, v0 placeholder"}

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

claim2_evidence_content = {"note": "EXAMPLE-ORG claim-2 outcome evidence artifact, v0 placeholder"}
claim2_proof_content = {"note": "EXAMPLE-ORG claim-2 receipt, v0 placeholder"}

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

claim3_evidence_content = {"note": "EXAMPLE-ORG claim-3 withheld evidence handle, v0 placeholder"}
claim3_proof_content = {"note": "EXAMPLE-ORG claim-3 inclusion proof over the withheld handle, v0 placeholder"}

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
        "summary": "EXAMPLE-ORG counterparty confirmed the evidence exists but declined disclosure "
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

pos_example_org_claims_result: EvidenceResultDoc = {
    "result_version": "evidence-result-v0",
    "generated_at": GENERATED_AT,
    "claims": [claim_1, claim_2, claim_3],
    "aggregate": aggregate,
    "view": {
        "spec_version": "presentation/v1",
        "producer_name": "EXAMPLE-ORG",
        "title": "EXAMPLE-ORG Claims Result -- Round 0",
    },
}


def _mutated(base: EvidenceResultDoc) -> EvidenceResultDoc:
    return json.loads(json.dumps(base))


# --- neg-untiered-claim -- claim-1 missing `tier` -------------------------
neg_untiered_claim = _mutated(pos_example_org_claims_result)
del neg_untiered_claim["claims"][0]["tier"]

# --- neg-met-with-sufficiency-gap -- claim-1 keeps verdict `met`, --------
#     sufficiency changed SATISFIED -> GAP (spec section 1's binding rule)
neg_met_with_sufficiency_gap = _mutated(pos_example_org_claims_result)
neg_met_with_sufficiency_gap["claims"][0]["sufficiency"] = "GAP"

# --- neg-aggregate-without-coverage -- aggregate.coverage removed --------
neg_aggregate_without_coverage = _mutated(pos_example_org_claims_result)
del neg_aggregate_without_coverage["aggregate"]["coverage"]

# --- neg-contract-ref-missing -- claim-1 missing `contract_ref` ----------
neg_contract_ref_missing = _mutated(pos_example_org_claims_result)
del neg_contract_ref_missing["claims"][0]["contract_ref"]

# --- neg-disclosure-carrier-under-withheld -- claim-3's presentation -----
#     changed from `analysis` to `disclosure` while status stays WITHHELD
#     (spec section 2's gate)
neg_disclosure_carrier_under_withheld = _mutated(pos_example_org_claims_result)
neg_disclosure_carrier_under_withheld["claims"][2]["presentation"] = {
    "kind": "disclosure",
    "status": "WITHHELD",
    "evidence": [digest_ref(claim3_evidence_content)],
}

# ===========================================================================
# Claim types, reconcile and close both normative (the 2026-09-25
# ruling: "close + reconcile as claim types in result v0, so they feed
# the same result"). Each positive
# below keeps the untouched requirement claim-1 beside its typed claims, so
# the pre-existing shape is proven to coexist with each type in the same
# claims[] array: the three close positives pair claim-1 with ONE typed
# claim; the reconcile positive carries TWO (reconcile-1 SATISFIED,
# reconcile-2 GAP), because the sufficiency-derivation rule needs both
# branches on one document.
# ===========================================================================

RECONCILE_CONTRACT_REF = "ec:example-org-outcomes-reconcile:2026-09-25@1"
MONTH: PeriodDoc = {"start": "2026-09-01T00:00:00Z", "end": "2026-10-01T00:00:00Z"}
DAY_1: PeriodDoc = {"start": "2026-09-01T00:00:00Z", "end": "2026-09-02T00:00:00Z"}

# --- reconcile-1 -- refund-lands, all six states populated, no gap: ------
#     sufficiency SATISFIED (INSUFFICIENT = UNRESOLVED = 0); the contract
#     clause's verdict is not_met because rows exist outside MATCHED.
#     A_ONLY / B_ONLY are "one side missing", CONFLICTING is "both sides
#     disagree" -- the fixture carries all three so a renderer can be
#     tested for never conflating them (ruling 2026-09-25).
reconcile1_evidence_content = {"note": "EXAMPLE-ORG reconcile refund-lands September fold output, v0 placeholder"}
reconcile1_proof_content = {"note": "EXAMPLE-ORG reconcile refund-lands inclusion proof, v0 placeholder"}

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
        "peer": "example-org-sor",
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
reconcile2_evidence_content = {"note": "EXAMPLE-ORG reconcile change-lands September fold output, v0 placeholder"}
reconcile2_proof_content = {"note": "EXAMPLE-ORG reconcile change-lands inclusion proof, v0 placeholder"}

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
        "summary": "EXAMPLE-ORG peer connector produced no system_of_record_fact rows on three days of "
        "the period; the join could not be evaluated for those days.",
    },
    "reconcile": {
        "join_key": "reservation_id",
        "peer": "example-org-sor",
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

pos_example_org_reconcile_result: EvidenceResultDoc = {
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
        "producer_name": "EXAMPLE-ORG",
        "title": "EXAMPLE-ORG Outcomes Reconcile -- September",
    },
}

# --- The Close records themselves (2026-09-28: close_state is DERIVABLE) --
#     A close claim's close_state is never asserted: it MUST equal the state
#     read from the cited Close's inbound links (spec section 4.1), so the
#     cited records here are real record headers -- the evidence-book shape a
#     bundle discloses (v, book_id, seq, record_type, epistemic_type,
#     committed_at, event_time_claim, links[{type, target}], subject_ref,
#     statement) -- and each close fixture ships them beside it as
#     `<name>.records.json`, a JSON array, so the checker can walk the links
#     and recompute the state. Every digest a claim cites is json_digest of
#     the record object exactly as written in the sidecar. Every
#     `record_type: close` record's statement is a close/v1 body
#     (schemas/judge/close-v1.json, spec section 4.1), counts only.
close_bound_set_content = {"note": "EXAMPLE-ORG 2026-09-01 record set bound by the Close, v0 placeholder"}


def _close_v1_body(book_id: str, seq: int, closed_at: str, bound_set_note: str) -> dict:
    """A counts-only close/v1 body for the 2026-09-01 period. `head` is the
    last record of the range the Close covers and `counts_by_kind` counts
    that range (judge-record-family-v1 section 3); both are placeholders here."""
    return {
        "record_version": "close/v1",
        "record_id": f"{book_id}#{seq}",
        "epistemic_type": "producer_claim",
        "closed_at": closed_at,
        "period": DAY_1,
        "counts_by_kind": {"observation": 3},
        "head": digest_ref({"note": f"last record of {bound_set_note}, v0 placeholder"}),
    }


own_close_content: RecordDoc = {
    "v": 1,
    "book_id": "example-org",
    "seq": 41,
    "record_type": "close",
    "epistemic_type": "producer_claim",
    "committed_at": "2026-09-02T00:05:00Z",
    "event_time_claim": "2026-09-02T00:00:00Z",
    "links": [{"type": "closes", "target": json_digest(close_bound_set_content)}],
    "subject_ref": RECONCILE_CONTRACT_REF,
    "statement": _close_v1_body("example-org", 41, "2026-09-02T00:05:00Z", "the EXAMPLE-ORG 2026-09-01 record set"),
}
OWN_CLOSE_DIGEST = json_digest(own_close_content)


def _peer_record(seq: int, link_type: str | None) -> RecordDoc:
    """The peer's (example-org-sor) record for the same period: acknowledging ours
    (AGREED), rebutting ours (CONTESTED), or carrying no link back at all
    (the peer's own Close we reconciled with, which leaves ours UNILATERAL)."""
    links: list = [{"type": "closes", "target": json_digest({"note": "example-org-sor 2026-09-01 record set, v0 placeholder"})}]
    if link_type is not None:
        links.append({"type": link_type, "target": OWN_CLOSE_DIGEST})
    return {
        "v": 1,
        "book_id": "example-org-sor",
        "seq": seq,
        "record_type": "close",
        "epistemic_type": "producer_claim",
        "committed_at": "2026-09-02T01:00:00Z",
        "event_time_claim": "2026-09-02T00:00:00Z",
        "links": links,
        "subject_ref": RECONCILE_CONTRACT_REF,
        "statement": _close_v1_body("example-org-sor", seq, "2026-09-02T01:00:00Z", "the example-org-sor 2026-09-01 record set"),
    }


# The peer's Close that `acknowledges` ours -- AGREED is read from this link.
peer_close_content = _peer_record(17, "acknowledges")
# The peer's record that `rebuts` ours -- CONTESTED is read from this link.
peer_rebuttal_content = _peer_record(18, "rebuts")
# The peer's Close for the period that links to nothing of ours: reconciled
# with, never answered. Its presence in a bundle changes nothing -- the
# state is read from links TO our Close, and this record carries none.
peer_silent_close_content = _peer_record(19, None)
# A record from EXAMPLE-ORG's OWN book that `acknowledges` EXAMPLE-ORG's own Close
# (an `acknowledges` link has to come from the counterparty). Same `book_id` as the Close, so the link makes no state:
# a producer cannot agree with itself. The walk ignores it and reads
# UNILATERAL.
own_ack_content: RecordDoc = {
    "v": 1,
    "book_id": "example-org",
    "seq": 42,
    "record_type": "close",
    "epistemic_type": "producer_claim",
    "committed_at": "2026-09-02T00:10:00Z",
    "event_time_claim": "2026-09-02T00:00:00Z",
    "links": [{"type": "acknowledges", "target": OWN_CLOSE_DIGEST}],
    "subject_ref": RECONCILE_CONTRACT_REF,
    "statement": _close_v1_body("example-org", 42, "2026-09-02T00:10:00Z", "the EXAMPLE-ORG 2026-09-01 record set"),
}
# A record from a THIRD book -- `example-org-audit`, neither EXAMPLE-ORG's own book nor the
# named peer `example-org-sor` -- that `acknowledges` EXAMPLE-ORG's Close (a
# producer can mint a second book equally easily). A different book_id is necessary, not sufficient: the linking
# book must be the claim's named peer. The walk ignores it and reads
# UNILATERAL.
third_book_ack_content: RecordDoc = {
    "v": 1,
    "book_id": "example-org-audit",
    "seq": 7,
    "record_type": "close",
    "epistemic_type": "producer_claim",
    "committed_at": "2026-09-02T00:20:00Z",
    "event_time_claim": "2026-09-02T00:00:00Z",
    "links": [{"type": "acknowledges", "target": OWN_CLOSE_DIGEST}],
    "subject_ref": RECONCILE_CONTRACT_REF,
    "statement": _close_v1_body("example-org-audit", 7, "2026-09-02T00:20:00Z", "the example-org-audit 2026-09-01 record set"),
}
# EXAMPLE-ORG's Close with NO `book_id` at all: a Close that names no
# book has no counterparty, so no linker -- not even the named peer's --
# can make it AGREED. Its digest differs from OWN_CLOSE_DIGEST, so the
# peer's acknowledging record below targets THIS digest.
bookless_close_content: RecordDoc = {
    key: value for key, value in own_close_content.items() if key != "book_id"
}
BOOKLESS_CLOSE_DIGEST = json_digest(bookless_close_content)
peer_ack_of_bookless_close_content: RecordDoc = {
    **_peer_record(20, None),
    "links": [
        {"type": "closes", "target": json_digest({"note": "example-org-sor 2026-09-01 record set, v0 placeholder"})},
        {"type": "acknowledges", "target": BOOKLESS_CLOSE_DIGEST},
    ],
}
close_proof_content = {"note": "EXAMPLE-ORG Close inclusion proof, v0 placeholder"}

# --- close-1 (AGREED) -- the peer's Close cites ours back ----------------
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
        "close_ref": digest_ref(own_close_content),
        "peer": "example-org-sor",
        "peer_close_ref": digest_ref(peer_close_content),
    },
}

# --- close-1 (CONTESTED) -- a peer record carries a `rebuts` link to ------
#     ours (draft-mih-agent-evidence-layer-00, 'Reconcile and Close'). The
#     state is what the Result builder READ from the Close's inbound links,
#     never a field the Close set. peer_close_ref cites the rebutting record
#     by digest, exactly as AGREED cites the acknowledging Close.
#     (peer_rebuttal_content is the record header defined above.)
#
#     A CONTESTED Close does not count as met: the peer rebuts it, so the clause the claim reports on
#     is `not_met` while the rebuttal stands. Sufficiency stays SATISFIED
#     -- both the Close and the rebuttal are in evidence, nothing is
#     missing -- and the claim sits in the not_met bucket. The schema's
#     Claim rule forbids `met` under CONTESTED (neg-close-contested-
#     verdict-met pins it).

close_contested: ClaimDoc = {
    "id": "close-1",
    "type": "close",
    "contract_ref": RECONCILE_CONTRACT_REF,
    "requirement_ref": "close",
    "tier": "recomputed",
    "grade": "self-attested",
    "sufficiency": "SATISFIED",
    "verdict": "not_met",
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
        "close_ref": digest_ref(own_close_content),
        "peer": "example-org-sor",
        "peer_close_ref": digest_ref(peer_rebuttal_content),
    },
}

# --- close-1 (UNILATERAL) -- no peer record acknowledges or rebuts ours; --
#     no peer named (the claim carries nothing about a counterparty)
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
        "close_ref": digest_ref(own_close_content),
    },
}

# --- close-1 (UNILATERAL, peer named) -- the same unilateral Close, with ---
#     the peer it was closed against named and nothing cited: example-org-sor has
#     not (yet) acknowledged or rebutted it. `peer` is OPTIONAL on
#     UNILATERAL (close-v1's peer-Close link is unconditional; the Evidence
#     Layer defines UNILATERAL only as "no corresponding `acknowledges`
#     link exists yet"). Naming the peer is not agreeing with it: the
#     row must still carry no agreed affordance -- a renderer's rule,
#     pinned in capsule-viewer, not a schema rule.
close_unilateral_named_peer: ClaimDoc = json.loads(json.dumps(close_unilateral))
close_unilateral_named_peer["close"]["peer"] = "example-org-sor"


def _close_result(close_claim: ClaimDoc, title: str) -> EvidenceResultDoc:
    # The buckets follow the claims' own verdicts (spec section 4: a
    # verifier checks every bucket entry names a claim with that verdict).
    buckets: dict = {"met": [], "not_met": [], "not_evaluable": []}
    for claim in (claim_1, close_claim):
        buckets[claim["verdict"]].append(claim["id"])
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
            "buckets": buckets,
        },
        "view": {
            "spec_version": "presentation/v1",
            "producer_name": "EXAMPLE-ORG",
            "title": title,
        },
    }


pos_example_org_close_agreed_result = _close_result(close_agreed, "EXAMPLE-ORG Close -- 2026-09-01 (agreed)")
pos_example_org_close_unilateral_result = _close_result(close_unilateral, "EXAMPLE-ORG Close -- 2026-09-01 (unilateral)")
pos_example_org_close_unilateral_named_peer_result = _close_result(
    close_unilateral_named_peer, "EXAMPLE-ORG Close -- 2026-09-01 (unilateral, peer named)"
)
pos_example_org_close_contested_result = _close_result(close_contested, "EXAMPLE-ORG Close -- 2026-09-01 (contested)")

# --- neg-close-contested-verdict-met -- the CONTESTED positive with -------
#     verdict `met` and NOTHING else changed (the bucket still lists close-1
#     under not_met, which the schema does not cross-check -- so the ONLY
#     rule rejecting this fixture is the Claim rule "a CONTESTED Close is
#     never met").
neg_close_contested_verdict_met = _mutated(pos_example_org_close_contested_result)
neg_close_contested_verdict_met["claims"][1]["verdict"] = "met"

# --- neg-close-agreed-self-acknowledged -- an AGREED close whose ----------
#     acknowledging record is from the producer's OWN book: peer_close_ref
#     cites own_ack_content (book_id "example-org", the Close's own book), and the
#     claim still names example-org-sor as the peer. Schema-valid (peer and
#     peer_close_ref are present); the walk ignores a link whose record
#     shares the Close's `book_id`, reads UNILATERAL, and rejects the claim.
close_self_acknowledged: ClaimDoc = json.loads(json.dumps(close_agreed))
close_self_acknowledged["evidence"] = [digest_ref(own_close_content), digest_ref(own_ack_content)]
close_self_acknowledged["presentation"]["evidence"] = [digest_ref(own_close_content), digest_ref(own_ack_content)]
close_self_acknowledged["close"]["peer_close_ref"] = digest_ref(own_ack_content)
neg_close_agreed_self_acknowledged = _close_result(
    close_self_acknowledged, "EXAMPLE-ORG Close -- 2026-09-01 (agreed by EXAMPLE-ORG's own book)"
)

# --- neg-close-agreed-third-book -- an AGREED close whose acknowledging ---
#     record is from a THIRD book (example-org-audit): a different book_id, but not
#     the named peer example-org-sor. Schema-valid; the walk ignores a link from a
#     book that is not the claim's `peer`, reads UNILATERAL, rejects.
close_third_book: ClaimDoc = json.loads(json.dumps(close_agreed))
close_third_book["evidence"] = [digest_ref(own_close_content), digest_ref(third_book_ack_content)]
close_third_book["presentation"]["evidence"] = [digest_ref(own_close_content), digest_ref(third_book_ack_content)]
close_third_book["close"]["peer_close_ref"] = digest_ref(third_book_ack_content)
neg_close_agreed_third_book = _close_result(
    close_third_book, "EXAMPLE-ORG Close -- 2026-09-01 (agreed by a third book, not the named peer)"
)

# --- neg-close-agreed-bookless-close -- the cited Close carries no --------
#     `book_id`; the named peer's record acknowledges it. Schema-valid (the
#     schema never sees the record); the walk lets no linker count against
#     a Close that names no book, reads UNILATERAL, rejects.
close_bookless: ClaimDoc = json.loads(json.dumps(close_agreed))
close_bookless["evidence"] = [digest_ref(bookless_close_content), digest_ref(peer_ack_of_bookless_close_content)]
close_bookless["presentation"]["evidence"] = [
    digest_ref(bookless_close_content),
    digest_ref(peer_ack_of_bookless_close_content),
]
close_bookless["close"]["close_ref"] = digest_ref(bookless_close_content)
close_bookless["close"]["peer_close_ref"] = digest_ref(peer_ack_of_bookless_close_content)
neg_close_agreed_bookless_close = _close_result(
    close_bookless, "EXAMPLE-ORG Close -- 2026-09-01 (agreed, but the Close names no book)"
)

# --- neg-close-ref-not-in-evidence / neg-close-peer-ref-not-in-evidence --
#     the AGREED positive with `close_ref` (resp. `peer_close_ref`) no
#     longer among the claim's evidence[] digests. Both refs MUST resolve
#     inside evidence[]: a claim cannot report
#     on a Close, or cite the record that makes its state, that it does
#     not put in evidence. Schema-valid (JSON Schema cannot compare two
#     digests); the checker rejects each.
neg_close_ref_not_in_evidence = _mutated(pos_example_org_close_agreed_result)
neg_close_ref_not_in_evidence["claims"][1]["evidence"] = [digest_ref(peer_close_content)]
neg_close_peer_ref_not_in_evidence = _mutated(pos_example_org_close_agreed_result)
neg_close_peer_ref_not_in_evidence["claims"][1]["evidence"] = [digest_ref(own_close_content)]

# --- neg-close-agreed-without-peer -- close-1 AGREED, `peer` removed -----
#     (CloseClaim's AGREED rule: peer + peer_close_ref required)
neg_close_agreed_without_peer = _mutated(pos_example_org_close_agreed_result)
del neg_close_agreed_without_peer["claims"][1]["close"]["peer"]

# --- neg-close-contested-without-peer-close-ref -- close-1 CONTESTED, ----
#     `peer_close_ref` removed (CloseClaim's AGREED-or-CONTESTED rule: a
#     contested close must cite the rebutting record)
neg_close_contested_without_peer_close_ref = _mutated(pos_example_org_close_contested_result)
del neg_close_contested_without_peer_close_ref["claims"][1]["close"]["peer_close_ref"]

# --- neg-reconcile-tallies-missing-state -- reconcile-1 tallies.unresolved
#     removed (ReconcileTallies requires all six; absent is never zero)
neg_reconcile_tallies_missing_state = _mutated(pos_example_org_reconcile_result)
del neg_reconcile_tallies_missing_state["claims"][1]["reconcile"]["tallies"]["unresolved"]

# --- neg-close-agreed-relabelled-contested -- the CONTESTED positive with --
#     close_state relabelled AGREED and NOTHING else changed: peer_close_ref
#     still cites the record that `rebuts` ours. This is the adversarial
#     case (2026-09-28): "a contested close relabelled 'agreed' validates".
#     It DOES validate against the schema -- that is the hole -- and is
#     rejected by the checker's link walk over its .records.json, which
#     recomputes CONTESTED from the `rebuts` link and fails the claim on
#     the mismatch (spec section 4.1's normative rule).
neg_close_agreed_relabelled_contested = _mutated(pos_example_org_close_contested_result)
neg_close_agreed_relabelled_contested["claims"][1]["close"]["close_state"] = "AGREED"
neg_close_agreed_relabelled_contested["view"]["title"] = "EXAMPLE-ORG Close -- 2026-09-01 (relabelled agreed)"

# --- the records each close fixture's link walk reads -------------------
#     One sidecar per fixture: `<name>.records.json`, a JSON array of the
#     record objects whose json_digest the fixture's close claim cites. The
#     relabelled negative ships the CONTESTED positive's records unchanged --
#     the Result lies, the bundle does not.
CLOSE_RECORDS: dict = {
    "pos-example-org-close-agreed-result": [own_close_content, peer_close_content],
    "pos-example-org-close-contested-result": [own_close_content, peer_rebuttal_content],
    "pos-example-org-close-unilateral-result": [own_close_content],
    "pos-example-org-close-unilateral-named-peer-result": [own_close_content, peer_silent_close_content],
    "neg-close-agreed-without-peer": [own_close_content, peer_close_content],
    "neg-close-contested-without-peer-close-ref": [own_close_content, peer_rebuttal_content],
    "neg-close-agreed-relabelled-contested": [own_close_content, peer_rebuttal_content],
    "neg-close-contested-verdict-met": [own_close_content, peer_rebuttal_content],
    "neg-close-agreed-self-acknowledged": [own_close_content, own_ack_content],
    "neg-close-ref-not-in-evidence": [own_close_content, peer_close_content],
    "neg-close-peer-ref-not-in-evidence": [own_close_content, peer_close_content],
    "neg-close-agreed-third-book": [own_close_content, third_book_ack_content],
    "neg-close-agreed-bookless-close": [bookless_close_content, peer_ack_of_bookless_close_content],
}

# --- neg-unrecognized-claim-type -- claim-1 given a type outside ----------
#     ClaimType's closed enum. Fails HERE (schema is closed-world); the
#     viewer renders this same fixture as an "unrecognized" row, never
#     dropped (ruling 2026-09-25) -- that half lives in capsule-viewer.
neg_unrecognized_claim_type = _mutated(pos_example_org_claims_result)
neg_unrecognized_claim_type["claims"][0]["type"] = "adjudication"


# --- section 8a: the x- extension slot ------------------------------------
#     The document and each claim admit members named `x-...`; everything
#     else stays closed. One positive (two x- members added) and two
#     negatives (one bare member added), all derived from
#     pos-example-org-claims-result: strip the x- members from the positive
#     and it is byte-identical to the claims positive.
#
#     pos-example-org-extended-result: `x-judge-pin` on claim-2 (the judged
#     claim) and `x-judged-selection` on the document.
x_judge_pin = {
    "model_id": "example-judge-1",
    "prompt_template_hash": json_digest({"note": "EXAMPLE-ORG judge prompt template, v0 placeholder"}),
    "schema_hash": json_digest({"note": "EXAMPLE-ORG judge answer schema, v0 placeholder"}),
    "input_refs": ["amount_minor", "currency"],
    "model_hosting": "hosted",
}
# These three carry a member EvidenceResultDoc does not declare, so each is a
# plain dict copy of the positive rather than an EvidenceResultDoc.
def _untyped(base: EvidenceResultDoc) -> dict:
    return json.loads(json.dumps(base))


pos_example_org_extended_result = _untyped(pos_example_org_claims_result)
pos_example_org_extended_result["claims"][1]["x-judge-pin"] = x_judge_pin
pos_example_org_extended_result["x-judged-selection"] = {
    "requirement_refs": ["req-claim-2"],
    "out_of_scope": [],
}

# --- neg-unprefixed-document-member -- a bare `judged_selection` on the ---
#     document: neither an EvidenceResult member nor x-prefixed.
neg_unprefixed_document_member = _untyped(pos_example_org_claims_result)
neg_unprefixed_document_member["judged_selection"] = {
    "requirement_refs": ["req-claim-2"],
    "out_of_scope": [],
}

# --- neg-unprefixed-claim-member -- a bare `rule_id` on claim-2: neither a -
#     Claim member nor x-prefixed.
neg_unprefixed_claim_member = _untyped(pos_example_org_claims_result)
neg_unprefixed_claim_member["claims"][1]["rule_id"] = "9"

# --- a judging producer's output, before and after the rename -------------
#     neg-judge-producer-unprefixed-result is the Result document a judging
#     producer wrote for two judged rows on a mock judge backend. Every key
#     and every structure is as the producer wrote it. Three values are
#     replaced with neutral placeholders: contract_ref, the pin's model_id,
#     and the rationale text. judge_pin_digest is then recomputed over the
#     placeholder pin the way the producer computes it (SHA-256 of the pin's
#     sort_keys JSON), so the pin and its digest still agree. Its claims carry four members the
#     schema does not define (rule_id, judge_pin, judge_pin_digest,
#     rationale), so it fails. pos-judge-producer-x-judge-result renames each
#     into the slot (JUDGE_PRODUCER_RENAMES) and adds the run's judged
#     selection, which that commit writes to a sidecar, as
#     `x-judged-selection`. Nothing else changes, and it validates.
_producer_evidence = [{"digest": "a" * 64, "digest_alg": "SHA-256"}]
_producer_pin = {
    "input_refs": ["amount_minor", "currency", "recurrence"],
    "model_hosting": "hosted",
    "model_id": "example-judge-1 (mock backend, no model read the evidence)",
    "prompt_template_hash": "8bce70a5b98a961af54f9889cb741976744854533b7c746a41ca440223784b65",
    "schema_hash": "69fa84e81389a9544d456b189411048e32ab5b36071ef3d0136accd1db465434",
}
_producer_pin_digest = hashlib.sha256(json.dumps(_producer_pin, sort_keys=True).encode()).hexdigest()


def _producer_claim(requirement_ref: str, rule_id: str, verdict: str) -> dict:
    return {
        "contract_ref": "example-org/everyday-rules@0.2.0",
        "evidence": _producer_evidence,
        "grade": "self-attested",
        "id": requirement_ref,
        "judge_pin": _producer_pin,
        "judge_pin_digest": _producer_pin_digest,
        "presentation": {"evidence": _producer_evidence, "kind": "disclosure", "status": "SATISFIED"},
        "proofs": [],
        "rationale": f"judge choice: {verdict} (mock backend)",
        "requirement_ref": requirement_ref,
        "rule_id": rule_id,
        "sufficiency": "SATISFIED",
        "tier": "judged",
        "verdict": verdict,
    }


# The producer document is not an EvidenceResultDoc: its claims carry members
# the schema rejects, which is the point of the fixture.
neg_judge_producer_unprefixed_result: dict = {
    "aggregate": {
        "buckets": {
            "met": ["transaction_scope.material_terms_changed"],
            "not_evaluable": [],
            "not_met": ["transaction_scope.materially_different_offer"],
        },
        "coverage": {"evaluated_population": 2, "excluded_not_applicable": 0, "unknown_count": 0},
    },
    "claims": [
        _producer_claim("transaction_scope.material_terms_changed", "9", "met"),
        _producer_claim("transaction_scope.materially_different_offer", "10", "not_met"),
    ],
    "generated_at": "2026-10-08T00:00:00Z",
    "result_version": "evidence-result-v0",
    "view": {"spec_version": "presentation/v1", "title": "Outcome result -- test-bundle-disclosed"},
}
_producer_judged_selection = {
    "allow_out_of_scope": True,
    "out_of_scope": [],
    "requirement_refs": [
        "transaction_scope.material_terms_changed",
        "transaction_scope.materially_different_offer",
    ],
    "rule_ids": ["9", "10"],
}

JUDGE_PRODUCER_RENAMES = {
    "rule_id": "x-judge-rule-id",
    "judge_pin": "x-judge-pin",
    "judge_pin_digest": "x-judge-pin-digest",
    "rationale": "x-judge-rationale",
}

pos_judge_producer_x_judge_result: dict = json.loads(json.dumps(neg_judge_producer_unprefixed_result))
for _claim in pos_judge_producer_x_judge_result["claims"]:
    for _old, _new in JUDGE_PRODUCER_RENAMES.items():
        _claim[_new] = _claim.pop(_old)
pos_judge_producer_x_judge_result["x-judged-selection"] = _producer_judged_selection
# ---------------------------------------------------------------------------
# PROPOSED coverage_report (spec section 7.1) -- the claims positive plus a
# per-requirement coverage section. req-claim-1 and req-claim-2 have every
# source present from two producers (SATISFIED; claim-2's verdict is not_met,
# which coverage does not change). req-claim-1's producers are identified by
# signer key id; req-claim-2's by asserted operator/developer, and one of its
# records names no producer, so it counts toward none. req-claim-3 is NOT_FOUND: one source has
# no record, and the remedy names the connector that would capture it.
# ---------------------------------------------------------------------------


def _source(name: str, records: list, producers: int, backfilled: int = 0, epistemic_type: str | None = None) -> dict:
    row = {
        "source": name,
        "status": "SATISFIED" if records else "NOT_FOUND",
        "record_count": len(records),
        "contemporaneous_count": len(records) - backfilled,
        "backfilled_count": backfilled,
        "duplicates_collapsed": 0,
        "producer_count": producers,
        "evidence": [digest_ref(r) for r in records],
    }
    if epistemic_type is not None:
        row["epistemic_type"] = epistemic_type
    return row


def _rec(label: str) -> dict:
    return {"note": f"EXAMPLE-ORG coverage record {label}, v0 placeholder"}


coverage_report: CoverageReportDoc = {
    "spec_version": "coverage-report/v0",
    "contract_ref": CONTRACT_REF,
    "requirements": [
        {
            "requirement_ref": "req-claim-1",
            "obligation_refs": [],
            "status": "SATISFIED",
            "sufficiency": "SATISFIED",
            "claim_ids": ["claim-1"],
            "sources": [
                _source("claims-system-record", [_rec("1a")], 1, backfilled=1, epistemic_type="system_of_record_fact"),
                _source("payment-events", [_rec("1b"), _rec("1c")], 1, epistemic_type="observed_event"),
            ],
            "independence": {
                "required_producers": 2,
                "independent_producers": 2,
                "correlated_records": 1,
                "unattributed_records": 0,
                "producer_basis": "key",
                "met": True,
            },
            "gaps": [],
        },
        {
            "requirement_ref": "req-claim-2",
            "obligation_refs": [],
            "status": "SATISFIED",
            "sufficiency": "SATISFIED",
            "claim_ids": ["claim-2"],
            "sources": [_source("review-events", [_rec("2a"), _rec("2b-unattributed")], 1)],
            "independence": {
                "required_producers": 1,
                "independent_producers": 1,
                "correlated_records": 0,
                "unattributed_records": 1,
                "producer_basis": "asserted",
                "met": True,
            },
            "gaps": [],
        },
        {
            "requirement_ref": "req-claim-3",
            "obligation_refs": [],
            "status": "NOT_FOUND",
            "sufficiency": "GAP",
            "claim_ids": ["claim-3"],
            "sources": [
                _source("notice-records", [_rec("3a")], 1),
                _source("override-events", [], 0, epistemic_type="human_report"),
            ],
            "independence": {
                "required_producers": 1,
                "independent_producers": 1,
                "correlated_records": 0,
                "unattributed_records": 0,
                "producer_basis": "asserted",
                "met": True,
            },
            "gaps": [
                {
                    "kind": "missing_source",
                    "source": "override-events",
                    "detail": "no record from source 'override-events' is in the evaluated records",
                    "remedy": {"connector": "human_approval", "raises_to": "observed"},
                }
            ],
        },
    ],
    "summary": {"requirements": 3, "satisfied": 2, "with_gaps": 1, "gaps": 1, "gaps_without_remedy": 0},
}

pos_example_org_coverage_result = _mutated(pos_example_org_claims_result)
pos_example_org_coverage_result["coverage_report"] = coverage_report

# --- neg-coverage-satisfied-with-gap -- req-claim-1 stays SATISFIED but ----
#     carries a gap (schema: a SATISFIED row has no gaps).
neg_coverage_satisfied_with_gap = _mutated(pos_example_org_coverage_result)
neg_coverage_satisfied_with_gap["coverage_report"]["requirements"][0]["gaps"].append(
    {"kind": "missing_source", "source": "payment-events", "detail": "placeholder gap", "remedy": None}
)

# --- neg-coverage-not-found-source-with-records -- a source marked ---------
#     NOT_FOUND that still counts a record (schema: NOT_FOUND exactly when
#     record_count is 0).
neg_coverage_not_found_source_with_records = _mutated(pos_example_org_coverage_result)
neg_coverage_not_found_source_with_records["coverage_report"]["requirements"][1]["sources"][0]["status"] = "NOT_FOUND"

# --- neg-coverage-gap-remedy-absent -- the gap's `remedy` key removed ------
#     (schema: remedy is required; "no remedy" is an explicit null).
neg_coverage_gap_remedy_absent = _mutated(pos_example_org_coverage_result)
del neg_coverage_gap_remedy_absent["coverage_report"]["requirements"][2]["gaps"][0]["remedy"]

# --- neg-coverage-unknown-epistemic-type -- a source typed outside the ----
#     closed EvidenceBook set (schema: EpistemicType's enum).
neg_coverage_unknown_epistemic_type = _mutated(pos_example_org_coverage_result)
neg_coverage_unknown_epistemic_type["coverage_report"]["requirements"][0]["sources"][0]["epistemic_type"] = "trusted_fact"

# --- neg-coverage-uppercase-epistemic-type -- a known type in upper case ---
#     (schema: the values are lower case; upper case is not the same token).
neg_coverage_uppercase_epistemic_type = _mutated(pos_example_org_coverage_result)
neg_coverage_uppercase_epistemic_type["coverage_report"]["requirements"][0]["sources"][0]["epistemic_type"] = "SYSTEM_OF_RECORD_FACT"

# --- neg-coverage-correlated-counted-as-met -- req-claim-1's records are ----
#     relabelled as one producer's (independent_producers 1, correlated 2),
#     met left true. Schema-valid; the cross-element check rejects it:
#     records from one producer correlate, they do not corroborate.
neg_coverage_correlated_counted_as_met = _mutated(pos_example_org_coverage_result)
neg_coverage_correlated_counted_as_met["coverage_report"]["requirements"][0]["independence"].update(
    {"independent_producers": 1, "correlated_records": 2}
)

# --- neg-coverage-summary-does-not-recompute -- summary.satisfied 3 --------
#     over rows with two SATISFIED. Schema-valid; cross-element rejected.
neg_coverage_summary_does_not_recompute = _mutated(pos_example_org_coverage_result)
neg_coverage_summary_does_not_recompute["coverage_report"]["summary"]["satisfied"] = 3

# ---------------------------------------------------------------------------
# PROPOSED aggregate.coverage_declaration (spec section 7.2) -- the claims
# positive with the aggregate's coverage kind, and one kind outside the three.
# ---------------------------------------------------------------------------
pos_example_org_coverage_declaration_result = _mutated(pos_example_org_claims_result)
pos_example_org_coverage_declaration_result["aggregate"]["coverage_declaration"] = {"kind": "holder_selected"}

# --- neg-coverage-declaration-unknown-kind -- a kind outside the three -----
#     (schema: CoverageKind's closed enum). "complete" is the claim the
#     vocabulary exists to keep apart from its population.
neg_coverage_declaration_unknown_kind = _mutated(pos_example_org_coverage_declaration_result)
neg_coverage_declaration_unknown_kind["aggregate"]["coverage_declaration"]["kind"] = "complete"


# ---------------------------------------------------------------------------
# Spec section 7.3: plan_ref and dataset_ref -- the claims positive naming the
# dataset plan and dataset of vectors/evidence-dataset/pos-window-and-exclusion,
# a Result carrying one of the two, and one inlining the plan.
# ---------------------------------------------------------------------------
pos_example_org_dataset_result = _mutated(pos_example_org_claims_result)
pos_example_org_dataset_result["plan_ref"] = {"digest_alg": "SHA-256", "digest": json_digest(PLAN)}
pos_example_org_dataset_result["dataset_ref"] = {"digest_alg": "SHA-256", "digest": json_digest(DATASET)}

# --- neg-dataset-ref-without-plan-ref -- one member without the other -------
#     (schema: EvidenceResult's dependentRequired).
neg_dataset_ref_without_plan_ref = _mutated(pos_example_org_dataset_result)
del neg_dataset_ref_without_plan_ref["plan_ref"]

# --- neg-plan-ref-inline-plan -- the plan itself where its digest goes ------
#     (schema: DigestRef is closed; section 7.3 carries digests only).
neg_plan_ref_inline_plan = _mutated(pos_example_org_dataset_result)
neg_plan_ref_inline_plan["plan_ref"] = PLAN

# --- pos-example-org-recorded-absence-result -- a story claim about a -------
#     recorded absence (spec section 2) cites the absence record itself by
#     digest. The record is interop-profile-v0 section 10's absence-record
#     example, so its digest is the one printed there
#     (82108c56...). It is the claims positive's claim-3 replaced by this claim,
#     mapped as interop-profile-v0 section 8.1 maps a recorded absence:
#     UNKNOWN / UNKNOWN / not_evaluable, so unknown_count is 1.
recorded_absence_content = {
    "outcome": "recorded_absence",
    "recorded_at": "2026-10-12T00:01:05Z",
    "request_digest": "ba7fee76b7afe9f3ec5ce46975865e06040492f0da733b28cbc86bd2be609d5e",
    "route": "peer:example-responder",
    "window": {"closed": "2026-10-12T00:01:05Z", "opened": "2026-10-12T00:00:05Z"},
}
absence_claim: ClaimDoc = {
    "id": "claim-3",
    "contract_ref": CONTRACT_REF,
    "requirement_ref": "req-claim-3",
    "tier": "recomputed",
    "grade": "self-attested",
    "sufficiency": "UNKNOWN",
    "verdict": "not_evaluable",
    "evidence": [digest_ref(recorded_absence_content)],
    "proofs": [],
    "presentation": {
        "kind": "story",
        "status": "UNKNOWN",
        "narrative": "EXAMPLE-ORG requested the record on 2026-10-12; no envelope or refusal "
        "arrived within the one-minute window, and the absence was recorded.",
    },
}
pos_example_org_recorded_absence_result = _mutated(pos_example_org_claims_result)
pos_example_org_recorded_absence_result["claims"][2] = absence_claim
pos_example_org_recorded_absence_result["aggregate"]["coverage"]["unknown_count"] = 1

# --- neg-claim-evidence-empty -- the same story claim citing nothing --------
#     (spec section 1, Traceability: evidence[] holds at least one entry).
neg_claim_evidence_empty = _mutated(pos_example_org_recorded_absence_result)
neg_claim_evidence_empty["claims"][2]["evidence"] = []


# --- pos-example-org-repeated-requirement-result -- coverage counts ---------
#     evaluations, one per claim (spec section 3). The claims positive with
#     claim-2 evaluating claim-1's requirement on a second subject: two
#     evaluations of req-claim-1, one met and one not_met, so the population is
#     still 3 (evaluations of 2 requirements) and nothing rolls req-claim-1 up
#     to one verdict: claim-1 stays in met and claim-2 in not_met.
pos_example_org_repeated_requirement_result = _mutated(pos_example_org_claims_result)
pos_example_org_repeated_requirement_result["claims"][1]["requirement_ref"] = "req-claim-1"


# --- spec section 4.2: out_of_scope, the fourth verdict -------------------
#     pos-example-org-out-of-scope-result: the claims positive with claim-1
#     and claim-2 copying the contract's switch (out_of_scope_allowed), and
#     claim-2 judged out_of_scope (SATISFIED: the situation did not arise). It
#     sits in its own fourth bucket; claim-1's switch keeps the bucket
#     required when claim-2's is removed, so each negative below fails at
#     exactly one rule.
pos_example_org_out_of_scope_result = _mutated(pos_example_org_claims_result)
for _claim in pos_example_org_out_of_scope_result["claims"][:2]:
    _claim["out_of_scope_allowed"] = True
pos_example_org_out_of_scope_result["claims"][1]["verdict"] = "out_of_scope"
pos_example_org_out_of_scope_result["aggregate"]["buckets"]["not_met"] = []
pos_example_org_out_of_scope_result["aggregate"]["buckets"]["out_of_scope"] = ["claim-2"]

# switched on, nothing judged out_of_scope: the fourth bucket is shown, empty
pos_example_org_out_of_scope_empty_result = _mutated(pos_example_org_claims_result)
pos_example_org_out_of_scope_empty_result["claims"][0]["out_of_scope_allowed"] = True
pos_example_org_out_of_scope_empty_result["aggregate"]["buckets"]["out_of_scope"] = []

neg_out_of_scope_without_switch = _mutated(pos_example_org_out_of_scope_result)
del neg_out_of_scope_without_switch["claims"][1]["out_of_scope_allowed"]

neg_out_of_scope_bucket_absent = _mutated(pos_example_org_out_of_scope_empty_result)
del neg_out_of_scope_bucket_absent["aggregate"]["buckets"]["out_of_scope"]

neg_out_of_scope_bucket_without_switch = _mutated(pos_example_org_claims_result)
neg_out_of_scope_bucket_without_switch["aggregate"]["buckets"]["out_of_scope"] = []

neg_out_of_scope_with_gap = _mutated(pos_example_org_out_of_scope_result)
neg_out_of_scope_with_gap["claims"][1]["sufficiency"] = "GAP"

neg_out_of_scope_not_applicable_carrier = _mutated(pos_example_org_out_of_scope_result)
neg_out_of_scope_not_applicable_carrier["claims"][1]["presentation"]["status"] = "NOT_APPLICABLE"

neg_satisfied_not_evaluable = _mutated(pos_example_org_claims_result)
neg_satisfied_not_evaluable["claims"][1]["verdict"] = "not_evaluable"

neg_not_applicable_verdict = _mutated(pos_example_org_claims_result)
neg_not_applicable_verdict["claims"][1]["verdict"] = "not_applicable"

# the out_of_scope verdict is for requirement claims only
neg_out_of_scope_on_reconcile_claim = _mutated(pos_example_org_reconcile_result)
neg_out_of_scope_on_reconcile_claim["claims"][1]["out_of_scope_allowed"] = True
neg_out_of_scope_on_reconcile_claim["claims"][1]["verdict"] = "out_of_scope"
neg_out_of_scope_on_reconcile_claim["aggregate"]["buckets"]["not_met"] = []
neg_out_of_scope_on_reconcile_claim["aggregate"]["buckets"]["out_of_scope"] = ["reconcile-1"]

# checker negatives: schema-valid, rejected by the cross-element rules
neg_out_of_scope_listed_in_met = _mutated(pos_example_org_out_of_scope_result)
neg_out_of_scope_listed_in_met["aggregate"]["buckets"]["met"] = ["claim-1", "claim-2"]
neg_out_of_scope_listed_in_met["aggregate"]["buckets"]["out_of_scope"] = []

neg_switch_disagrees_in_row = _mutated(pos_example_org_out_of_scope_result)
del neg_switch_disagrees_in_row["claims"][0]["out_of_scope_allowed"]
neg_switch_disagrees_in_row["claims"][1]["requirement_ref"] = "req-claim-1"

# the copied switch on a typed claim of the same requirement: a close claim
# and a requirement claim of one row, both switched on, neither out_of_scope
pos_example_org_close_switched_on_result = _mutated(pos_example_org_close_agreed_result)
for _claim in pos_example_org_close_switched_on_result["claims"]:
    _claim["out_of_scope_allowed"] = True
pos_example_org_close_switched_on_result["claims"][1]["requirement_ref"] = "req-claim-1"
pos_example_org_close_switched_on_result["aggregate"]["buckets"]["out_of_scope"] = []
CLOSE_RECORDS["pos-example-org-close-switched-on-result"] = CLOSE_RECORDS["pos-example-org-close-agreed-result"]


# --- spec section 4.3: applicability ---------------------------------------
#     generated_at is 2026-09-22. claim-1 has applied since 2026-01-01 and is
#     in force; claim-2 (not_met) and three more later claims apply from
#     2027-08-02, so they keep their verdicts as readiness and are in no
#     bucket: claim-4 a later UNKNOWN (not in unknown_count) and claim-5 a
#     later out_of_scope (not in the switched-on, empty fourth bucket).
#     claim-3 is undated. Population 2, not_yet_in_force 3.
LATER = "2027-08-02"
pos_example_org_applicability_result = _mutated(pos_example_org_claims_result)
_claims = pos_example_org_applicability_result["claims"]
_claims[0]["applies_from"] = "2026-01-01"
_claims[1]["applies_from"] = LATER
_later_unknown = json.loads(json.dumps(absence_claim))
_later_unknown.update({"id": "claim-4", "requirement_ref": "req-claim-4", "applies_from": LATER})
_later_out_of_scope = json.loads(json.dumps(_claims[1]))
_later_out_of_scope.update({
    "id": "claim-5", "requirement_ref": "req-claim-5", "verdict": "out_of_scope",
    "out_of_scope_allowed": True, "applies_from": LATER,
})
_claims.extend([_later_unknown, _later_out_of_scope])
pos_example_org_applicability_result["aggregate"] = {
    "coverage": {
        "evaluated_population": 2,
        "excluded_not_applicable": 1,
        "unknown_count": 0,
        "not_yet_in_force": 3,
    },
    "buckets": {"met": ["claim-1"], "not_met": [], "not_evaluable": ["claim-3"], "out_of_scope": []},
}

#     The UTC date decides. generated_at 2026-09-22T23:30:00-05:00 is
#     2026-09-23 in UTC: claim-1 applies from that date and is in force, as is
#     claim-3 (a leap day long past); claim-2 applies from the next day and is
#     later.
pos_example_org_applicability_boundary_result = _mutated(pos_example_org_claims_result)
pos_example_org_applicability_boundary_result["generated_at"] = "2026-09-22T23:30:00-05:00"
_claims = pos_example_org_applicability_boundary_result["claims"]
_claims[0]["applies_from"] = "2026-09-23"
_claims[1]["applies_from"] = "2026-09-24"
_claims[2]["applies_from"] = "2024-02-29"
pos_example_org_applicability_boundary_result["aggregate"]["coverage"].update(
    {"evaluated_population": 2, "not_yet_in_force": 1}
)
pos_example_org_applicability_boundary_result["aggregate"]["buckets"]["not_met"] = []

# dated, and every dated claim already in force: no claim is later, so
# there is no not_yet_in_force, but a reader still prints the as-of date
pos_example_org_applicability_in_force_result = _mutated(pos_example_org_claims_result)
pos_example_org_applicability_in_force_result["claims"][0]["applies_from"] = "2026-01-01"
# a year below 100 is a year like any other, never read as 19xx
pos_example_org_applicability_in_force_result["claims"][1]["applies_from"] = "0099-01-01"

# a requirement claim and a reconcile claim of one row, both later
pos_example_org_reconcile_later_result = _mutated(pos_example_org_reconcile_result)
_claims = pos_example_org_reconcile_later_result["claims"]
_claims[1]["contract_ref"] = _claims[0]["contract_ref"]
_claims[1]["requirement_ref"] = "req-claim-1"
for _claim in _claims[:2]:
    _claim["applies_from"] = LATER
pos_example_org_reconcile_later_result["aggregate"]["coverage"].update(
    {"evaluated_population": 1, "not_yet_in_force": 2}
)
pos_example_org_reconcile_later_result["aggregate"]["buckets"].update({"met": [], "not_met": []})

# checker negatives
neg_later_claim_in_bucket = _mutated(pos_example_org_applicability_result)
neg_later_claim_in_bucket["aggregate"]["buckets"]["not_met"] = ["claim-2"]

neg_later_claim_in_population = _mutated(pos_example_org_applicability_result)
neg_later_claim_in_population["aggregate"]["coverage"]["evaluated_population"] = 5

neg_later_unknown_counted = _mutated(pos_example_org_applicability_result)
neg_later_unknown_counted["aggregate"]["coverage"]["unknown_count"] = 1

neg_not_yet_in_force_absent = _mutated(pos_example_org_applicability_result)
del neg_not_yet_in_force_absent["aggregate"]["coverage"]["not_yet_in_force"]

neg_not_yet_in_force_wrong = _mutated(pos_example_org_applicability_result)
neg_not_yet_in_force_wrong["aggregate"]["coverage"]["not_yet_in_force"] = 2

neg_generated_at_unparseable = _mutated(pos_example_org_applicability_result)
neg_generated_at_unparseable["generated_at"] = "2026-09-22"

neg_generated_at_impossible = _mutated(pos_example_org_applicability_result)
neg_generated_at_impossible["generated_at"] = "2026-02-30T00:00:00Z"

neg_generated_at_without_seconds = _mutated(pos_example_org_applicability_result)
neg_generated_at_without_seconds["generated_at"] = "2026-09-22T10:00+00:00"

neg_not_yet_in_force_without_later = _mutated(pos_example_org_applicability_in_force_result)
neg_not_yet_in_force_without_later["aggregate"]["coverage"]["not_yet_in_force"] = 0

neg_applies_from_not_a_date = _mutated(pos_example_org_applicability_result)
neg_applies_from_not_a_date["claims"][1]["applies_from"] = "2027-02-30"

neg_applies_from_disagrees_in_row = _mutated(pos_example_org_reconcile_later_result)
del neg_applies_from_disagrees_in_row["claims"][1]["applies_from"]
neg_applies_from_disagrees_in_row["aggregate"]["coverage"].update(
    {"evaluated_population": 2, "not_yet_in_force": 1}
)
neg_applies_from_disagrees_in_row["aggregate"]["buckets"]["not_met"] = ["reconcile-1"]

# ---------------------------------------------------------------------------
# Section 3: requirements_covered. The claims positive names the three
# requirements its claims cite and req-claim-4, the one evaluation it
# excludes as NOT_APPLICABLE (excluded_not_applicable 1). Two checker
# negatives drop a claimed requirement from the list and leave the listed
# requirement no claim cites without an exclusion; one schema negative lists
# a pair twice.
# ---------------------------------------------------------------------------


def _covered(*requirements: str) -> list:
    return [{"contract_ref": CONTRACT_REF, "requirement_ref": r} for r in requirements]


pos_example_org_requirements_covered_result = _mutated(pos_example_org_claims_result)
pos_example_org_requirements_covered_result["aggregate"]["coverage"]["requirements_covered"] = _covered(
    "req-claim-1", "req-claim-2", "req-claim-3", "req-claim-4"
)

neg_requirements_covered_omits_claimed = _mutated(pos_example_org_requirements_covered_result)
neg_requirements_covered_omits_claimed["aggregate"]["coverage"]["requirements_covered"] = _covered(
    "req-claim-1", "req-claim-3", "req-claim-4"
)

neg_requirements_covered_unaccounted = _mutated(pos_example_org_requirements_covered_result)
neg_requirements_covered_unaccounted["aggregate"]["coverage"]["excluded_not_applicable"] = 0

neg_requirements_covered_duplicate = _mutated(pos_example_org_requirements_covered_result)
neg_requirements_covered_duplicate["aggregate"]["coverage"]["requirements_covered"] = _covered(
    "req-claim-1", "req-claim-2", "req-claim-3", "req-claim-4", "req-claim-4"
)


# --- JSON Schema reads `pattern` as ECMA-262 ----------------------------------
#     Three schema negatives on which Python's `re` and ECMA-262 disagree. In
#     ECMA-262 `$` (no m flag) matches only at the end of the text, where
#     Python's also matches before a final newline; and ECMA-262's `\s`
#     includes U+FEFF, which Python's does not.
neg_digest_trailing_newline = _mutated(pos_example_org_claims_result)
neg_digest_trailing_newline["claims"][0]["evidence"][0]["digest"] += "\n"

neg_applies_from_trailing_newline = _mutated(pos_example_org_applicability_result)
neg_applies_from_trailing_newline["claims"][1]["applies_from"] += "\n"

neg_contract_ref_ecma_whitespace = _mutated(pos_example_org_claims_result)
neg_contract_ref_ecma_whitespace["claims"][0]["contract_ref"] += "\ufeff"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write("pos-example-org-claims-result", pos_example_org_claims_result)
    write("neg-untiered-claim", neg_untiered_claim)
    write("neg-met-with-sufficiency-gap", neg_met_with_sufficiency_gap)
    write("neg-aggregate-without-coverage", neg_aggregate_without_coverage)
    write("neg-contract-ref-missing", neg_contract_ref_missing)
    write("neg-disclosure-carrier-under-withheld", neg_disclosure_carrier_under_withheld)
    write("pos-example-org-reconcile-result", pos_example_org_reconcile_result)
    write("pos-example-org-close-agreed-result", pos_example_org_close_agreed_result)
    write("pos-example-org-close-unilateral-result", pos_example_org_close_unilateral_result)
    write("pos-example-org-close-unilateral-named-peer-result", pos_example_org_close_unilateral_named_peer_result)
    write("pos-example-org-close-contested-result", pos_example_org_close_contested_result)
    write("neg-close-agreed-without-peer", neg_close_agreed_without_peer)
    write("neg-close-contested-without-peer-close-ref", neg_close_contested_without_peer_close_ref)
    write("neg-reconcile-tallies-missing-state", neg_reconcile_tallies_missing_state)
    write("neg-unrecognized-claim-type", neg_unrecognized_claim_type)
    write("neg-close-agreed-relabelled-contested", neg_close_agreed_relabelled_contested)
    write("neg-close-contested-verdict-met", neg_close_contested_verdict_met)
    write("neg-close-agreed-self-acknowledged", neg_close_agreed_self_acknowledged)
    write("neg-close-ref-not-in-evidence", neg_close_ref_not_in_evidence)
    write("neg-close-peer-ref-not-in-evidence", neg_close_peer_ref_not_in_evidence)
    write("neg-close-agreed-third-book", neg_close_agreed_third_book)
    write("neg-close-agreed-bookless-close", neg_close_agreed_bookless_close)
    write("pos-example-org-extended-result", pos_example_org_extended_result)
    write("neg-unprefixed-document-member", neg_unprefixed_document_member)
    write("neg-unprefixed-claim-member", neg_unprefixed_claim_member)
    write("pos-judge-producer-x-judge-result", pos_judge_producer_x_judge_result)
    write("neg-judge-producer-unprefixed-result", neg_judge_producer_unprefixed_result)
    write("pos-example-org-coverage-result", pos_example_org_coverage_result)
    write("neg-coverage-satisfied-with-gap", neg_coverage_satisfied_with_gap)
    write("neg-coverage-not-found-source-with-records", neg_coverage_not_found_source_with_records)
    write("neg-coverage-gap-remedy-absent", neg_coverage_gap_remedy_absent)
    write("neg-coverage-unknown-epistemic-type", neg_coverage_unknown_epistemic_type)
    write("neg-coverage-uppercase-epistemic-type", neg_coverage_uppercase_epistemic_type)
    write("neg-coverage-correlated-counted-as-met", neg_coverage_correlated_counted_as_met)
    write("neg-coverage-summary-does-not-recompute", neg_coverage_summary_does_not_recompute)
    write("pos-example-org-coverage-declaration-result", pos_example_org_coverage_declaration_result)
    write("neg-coverage-declaration-unknown-kind", neg_coverage_declaration_unknown_kind)
    write("pos-example-org-recorded-absence-result", pos_example_org_recorded_absence_result)
    write("pos-example-org-repeated-requirement-result", pos_example_org_repeated_requirement_result)
    write("pos-example-org-out-of-scope-result", pos_example_org_out_of_scope_result)
    write("pos-example-org-out-of-scope-empty-result", pos_example_org_out_of_scope_empty_result)
    write("neg-out-of-scope-without-switch", neg_out_of_scope_without_switch)
    write("neg-out-of-scope-bucket-absent", neg_out_of_scope_bucket_absent)
    write("neg-out-of-scope-bucket-without-switch", neg_out_of_scope_bucket_without_switch)
    write("neg-out-of-scope-with-gap", neg_out_of_scope_with_gap)
    write("neg-out-of-scope-not-applicable-carrier", neg_out_of_scope_not_applicable_carrier)
    write("neg-satisfied-not-evaluable", neg_satisfied_not_evaluable)
    write("neg-not-applicable-verdict", neg_not_applicable_verdict)
    write("neg-out-of-scope-on-reconcile-claim", neg_out_of_scope_on_reconcile_claim)
    write("neg-out-of-scope-listed-in-met", neg_out_of_scope_listed_in_met)
    write("neg-switch-disagrees-in-row", neg_switch_disagrees_in_row)
    write("pos-example-org-close-switched-on-result", pos_example_org_close_switched_on_result)
    write("pos-example-org-applicability-result", pos_example_org_applicability_result)
    write("pos-example-org-applicability-boundary-result", pos_example_org_applicability_boundary_result)
    write("pos-example-org-applicability-in-force-result", pos_example_org_applicability_in_force_result)
    write("pos-example-org-reconcile-later-result", pos_example_org_reconcile_later_result)
    write("neg-later-claim-in-bucket", neg_later_claim_in_bucket)
    write("neg-later-claim-in-population", neg_later_claim_in_population)
    write("neg-later-unknown-counted", neg_later_unknown_counted)
    write("neg-not-yet-in-force-absent", neg_not_yet_in_force_absent)
    write("neg-not-yet-in-force-wrong", neg_not_yet_in_force_wrong)
    write("neg-generated-at-unparseable", neg_generated_at_unparseable)
    write("neg-applies-from-not-a-date", neg_applies_from_not_a_date)
    write("neg-generated-at-impossible", neg_generated_at_impossible)
    write("neg-generated-at-without-seconds", neg_generated_at_without_seconds)
    write("neg-not-yet-in-force-without-later", neg_not_yet_in_force_without_later)
    write("neg-applies-from-disagrees-in-row", neg_applies_from_disagrees_in_row)
    write("neg-claim-evidence-empty", neg_claim_evidence_empty)
    write("pos-example-org-requirements-covered-result", pos_example_org_requirements_covered_result)
    write("neg-requirements-covered-omits-claimed", neg_requirements_covered_omits_claimed)
    write("neg-requirements-covered-unaccounted", neg_requirements_covered_unaccounted)
    write("neg-requirements-covered-duplicate", neg_requirements_covered_duplicate)
    write("neg-digest-trailing-newline", neg_digest_trailing_newline)
    write("neg-applies-from-trailing-newline", neg_applies_from_trailing_newline)
    write("neg-contract-ref-ecma-whitespace", neg_contract_ref_ecma_whitespace)
    write("pos-example-org-dataset-result", pos_example_org_dataset_result)
    write("neg-dataset-ref-without-plan-ref", neg_dataset_ref_without_plan_ref)
    write("neg-plan-ref-inline-plan", neg_plan_ref_inline_plan)
    for name, records in CLOSE_RECORDS.items():
        write(f"{name}.records", records)
    return 0


if __name__ == "__main__":
    sys.exit(main())
