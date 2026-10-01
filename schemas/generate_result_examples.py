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

PROPOSED claim types (the 2026-09-25 ruling): five more positives --
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

close_state is DERIVABLE (2026-09-28, after the maintainer's adversarial
review): every close claim cites its Close (`close_ref`), the cited Close
and peer records are real record headers shipped beside each close fixture
as `<name>.records.json`, and one more negative --
neg-close-agreed-relabelled-contested -- is the CONTESTED positive with
close_state relabelled AGREED. It validates against the schema (that is the
hole) and is rejected by the checker's link walk, which recomputes the state
from the `rebuts` link in the sidecar.

The maintainer's second pass (2026-09-28) adds four negatives:
  - neg-close-contested-verdict-met: the CONTESTED positive with verdict
    `met`. A contested Close never counts as met (the positive now carries
    `not_met`); the schema's Claim rule rejects it.
  - neg-close-agreed-self-acknowledged: an AGREED close whose acknowledging
    record is from the producer's OWN book (`book_id` "oo", seq 42). An
    `acknowledges` / `rebuts` link counts only from a counterparty -- a
    record whose `book_id` differs from the Close's -- so the walk reads
    UNILATERAL and rejects the claim. Schema-valid.
  - neg-close-ref-not-in-evidence / neg-close-peer-ref-not-in-evidence: the
    AGREED positive with `close_ref` (resp. `peer_close_ref`) dropped from
    the claim's `evidence[]`. Both refs MUST resolve inside `evidence[]`;
    the checker rejects each. Schema-valid.

The maintainer's third pass (2026-09-29) -- "neither book_id nor signer
alone is enough, since a producer can mint a second book or a second key
equally easily" -- makes the counterparty rule three-part: (1) a different
`book_id`, (2) the linking book equals the claim's named `peer`, (3) a
different signer key (enforced where the signer is visible: the emitter
and the CLI; the record header here carries none). Two more negatives:
  - neg-close-agreed-third-book: the acknowledging record is from a third
    book (`oo-audit`, seq 7) that is not the named peer `oo-sor`. A
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
    RecordDoc,
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
# PROPOSED claim types (the 2026-09-25 ruling: "close + reconcile as
# claim types in result v0, so they feed the same result"). Each positive
# below keeps the untouched requirement claim-1 beside its typed claims, so
# the pre-existing shape is proven to coexist with each type in the same
# claims[] array: the three close positives pair claim-1 with ONE typed
# claim; the reconcile positive carries TWO (reconcile-1 SATISFIED,
# reconcile-2 GAP), because the sufficiency-derivation rule needs both
# branches on one document.
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

# --- The Close records themselves (2026-09-28: close_state is DERIVABLE) --
#     A close claim's close_state is never asserted: it MUST equal the state
#     read from the cited Close's inbound links (spec section 4.1), so the
#     cited records here are real record headers -- the evidence-book shape a
#     bundle discloses (v, book_id, seq, record_type, epistemic_type,
#     committed_at, event_time_claim, links[{type, target}], subject_ref,
#     statement) -- and each close fixture ships them beside it as
#     `<name>.records.json`, a JSON array, so the checker can walk the links
#     and recompute the state. Every digest a claim cites is json_digest of
#     the record object exactly as written in the sidecar.
close_bound_set_content = {"note": "OO 2026-09-01 record set bound by the Close, v0 placeholder"}

own_close_content: RecordDoc = {
    "v": 1,
    "book_id": "oo",
    "seq": 41,
    "record_type": "close",
    "epistemic_type": "producer_claim",
    "committed_at": "2026-09-02T00:05:00Z",
    "event_time_claim": "2026-09-02T00:00:00Z",
    "links": [{"type": "closes", "target": json_digest(close_bound_set_content)}],
    "subject_ref": RECONCILE_CONTRACT_REF,
    "statement": {"period": DAY_1, "note": "OO own Close record for 2026-09-01, v0 placeholder"},
}
OWN_CLOSE_DIGEST = json_digest(own_close_content)


def _peer_record(seq: int, link_type: str | None, note: str) -> RecordDoc:
    """The peer's (oo-sor) record for the same period: acknowledging ours
    (AGREED), rebutting ours (CONTESTED), or carrying no link back at all
    (the peer's own Close we reconciled with, which leaves ours UNILATERAL)."""
    links: list = [{"type": "closes", "target": json_digest({"note": "oo-sor 2026-09-01 record set, v0 placeholder"})}]
    if link_type is not None:
        links.append({"type": link_type, "target": OWN_CLOSE_DIGEST})
    return {
        "v": 1,
        "book_id": "oo-sor",
        "seq": seq,
        "record_type": "close",
        "epistemic_type": "producer_claim",
        "committed_at": "2026-09-02T01:00:00Z",
        "event_time_claim": "2026-09-02T00:00:00Z",
        "links": links,
        "subject_ref": RECONCILE_CONTRACT_REF,
        "statement": {"period": DAY_1, "note": note},
    }


# The peer's Close that `acknowledges` ours -- AGREED is read from this link.
peer_close_content = _peer_record(
    17, "acknowledges", "OO peer (oo-sor) Close record for 2026-09-01 acknowledging OO's, v0 placeholder"
)
# The peer's record that `rebuts` ours -- CONTESTED is read from this link.
peer_rebuttal_content = _peer_record(
    18, "rebuts", "OO peer (oo-sor) record for 2026-09-01 rebutting OO's Close, v0 placeholder"
)
# The peer's Close for the period that links to nothing of ours: reconciled
# with, never answered. Its presence in a bundle changes nothing -- the
# state is read from links TO our Close, and this record carries none.
peer_silent_close_content = _peer_record(
    19, None, "OO peer (oo-sor) Close record for 2026-09-01, no link back to OO's, v0 placeholder"
)
# A record from OO's OWN book that `acknowledges` OO's own Close (2026-09-28,
# maintainer's second pass: "an `acknowledges` link has to come from the
# counterparty"). Same `book_id` as the Close, so the link makes no state:
# a producer cannot agree with itself. The walk ignores it and reads
# UNILATERAL.
own_ack_content: RecordDoc = {
    "v": 1,
    "book_id": "oo",
    "seq": 42,
    "record_type": "close",
    "epistemic_type": "producer_claim",
    "committed_at": "2026-09-02T00:10:00Z",
    "event_time_claim": "2026-09-02T00:00:00Z",
    "links": [{"type": "acknowledges", "target": OWN_CLOSE_DIGEST}],
    "subject_ref": RECONCILE_CONTRACT_REF,
    "statement": {"period": DAY_1, "note": "OO record from OO's own book acknowledging OO's own Close, v0 placeholder"},
}
# A record from a THIRD book -- `oo-audit`, neither OO's own book nor the
# named peer `oo-sor` -- that `acknowledges` OO's Close (2026-09-29,
# maintainer's third pass: "a producer can mint a second book ... equally
# easily"). A different book_id is necessary, not sufficient: the linking
# book must be the claim's named peer. The walk ignores it and reads
# UNILATERAL.
third_book_ack_content: RecordDoc = {
    "v": 1,
    "book_id": "oo-audit",
    "seq": 7,
    "record_type": "close",
    "epistemic_type": "producer_claim",
    "committed_at": "2026-09-02T00:20:00Z",
    "event_time_claim": "2026-09-02T00:00:00Z",
    "links": [{"type": "acknowledges", "target": OWN_CLOSE_DIGEST}],
    "subject_ref": RECONCILE_CONTRACT_REF,
    "statement": {"period": DAY_1, "note": "record from a third book (oo-audit) acknowledging OO's Close, v0 placeholder"},
}
# OO's Close with NO `book_id` at all (third pass): a Close that names no
# book has no counterparty, so no linker -- not even the named peer's --
# can make it AGREED. Its digest differs from OWN_CLOSE_DIGEST, so the
# peer's acknowledging record below targets THIS digest.
bookless_close_content: RecordDoc = {
    key: value for key, value in own_close_content.items() if key != "book_id"
}
BOOKLESS_CLOSE_DIGEST = json_digest(bookless_close_content)
peer_ack_of_bookless_close_content: RecordDoc = {
    **_peer_record(20, None, "OO peer (oo-sor) Close record acknowledging OO's book-less Close, v0 placeholder"),
    "links": [
        {"type": "closes", "target": json_digest({"note": "oo-sor 2026-09-01 record set, v0 placeholder"})},
        {"type": "acknowledges", "target": BOOKLESS_CLOSE_DIGEST},
    ],
}
close_proof_content = {"note": "OO Close inclusion proof, v0 placeholder"}

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
        "peer": "oo-sor",
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
#     A CONTESTED Close does not count as met (2026-09-28, maintainer's
#     second pass): the peer rebuts it, so the clause the claim reports on
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
        "peer": "oo-sor",
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
#     the peer it was closed against named and nothing cited: oo-sor has
#     not (yet) acknowledged or rebutted it. `peer` is OPTIONAL on
#     UNILATERAL (close-v1's peer_close is unconditional; the Evidence
#     Layer defines UNILATERAL only as "no corresponding `acknowledges`
#     link exists yet"). Naming the peer is not agreeing with it: the
#     row must still carry no agreed affordance -- a renderer's rule,
#     pinned in capsule-viewer, not a schema rule.
close_unilateral_named_peer: ClaimDoc = json.loads(json.dumps(close_unilateral))
close_unilateral_named_peer["close"]["peer"] = "oo-sor"


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
            "producer_name": "OO",
            "title": title,
        },
    }


pos_oo_close_agreed_result = _close_result(close_agreed, "OO Close -- 2026-09-01 (agreed)")
pos_oo_close_unilateral_result = _close_result(close_unilateral, "OO Close -- 2026-09-01 (unilateral)")
pos_oo_close_unilateral_named_peer_result = _close_result(
    close_unilateral_named_peer, "OO Close -- 2026-09-01 (unilateral, peer named)"
)
pos_oo_close_contested_result = _close_result(close_contested, "OO Close -- 2026-09-01 (contested)")

# --- neg-close-contested-verdict-met -- the CONTESTED positive with -------
#     verdict `met` and NOTHING else changed (the bucket still lists close-1
#     under not_met, which the schema does not cross-check -- so the ONLY
#     rule rejecting this fixture is the Claim rule "a CONTESTED Close is
#     never met"). Maintainer's second pass, 2026-09-28: "a CONTESTED close
#     shouldn't count as met".
neg_close_contested_verdict_met = _mutated(pos_oo_close_contested_result)
neg_close_contested_verdict_met["claims"][1]["verdict"] = "met"

# --- neg-close-agreed-self-acknowledged -- an AGREED close whose ----------
#     acknowledging record is from the producer's OWN book: peer_close_ref
#     cites own_ack_content (book_id "oo", the Close's own book), and the
#     claim still names oo-sor as the peer. Schema-valid (peer and
#     peer_close_ref are present); the walk ignores a link whose record
#     shares the Close's `book_id`, reads UNILATERAL, and rejects the claim.
close_self_acknowledged: ClaimDoc = json.loads(json.dumps(close_agreed))
close_self_acknowledged["evidence"] = [digest_ref(own_close_content), digest_ref(own_ack_content)]
close_self_acknowledged["presentation"]["evidence"] = [digest_ref(own_close_content), digest_ref(own_ack_content)]
close_self_acknowledged["close"]["peer_close_ref"] = digest_ref(own_ack_content)
neg_close_agreed_self_acknowledged = _close_result(
    close_self_acknowledged, "OO Close -- 2026-09-01 (agreed by OO's own book)"
)

# --- neg-close-agreed-third-book -- an AGREED close whose acknowledging ---
#     record is from a THIRD book (oo-audit): a different book_id, but not
#     the named peer oo-sor. Schema-valid; the walk ignores a link from a
#     book that is not the claim's `peer`, reads UNILATERAL, rejects.
close_third_book: ClaimDoc = json.loads(json.dumps(close_agreed))
close_third_book["evidence"] = [digest_ref(own_close_content), digest_ref(third_book_ack_content)]
close_third_book["presentation"]["evidence"] = [digest_ref(own_close_content), digest_ref(third_book_ack_content)]
close_third_book["close"]["peer_close_ref"] = digest_ref(third_book_ack_content)
neg_close_agreed_third_book = _close_result(
    close_third_book, "OO Close -- 2026-09-01 (agreed by a third book, not the named peer)"
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
    close_bookless, "OO Close -- 2026-09-01 (agreed, but the Close names no book)"
)

# --- neg-close-ref-not-in-evidence / neg-close-peer-ref-not-in-evidence --
#     the AGREED positive with `close_ref` (resp. `peer_close_ref`) no
#     longer among the claim's evidence[] digests. Both refs MUST resolve
#     inside evidence[] (maintainer's second pass): a claim cannot report
#     on a Close, or cite the record that makes its state, that it does
#     not put in evidence. Schema-valid (JSON Schema cannot compare two
#     digests); the checker rejects each.
neg_close_ref_not_in_evidence = _mutated(pos_oo_close_agreed_result)
neg_close_ref_not_in_evidence["claims"][1]["evidence"] = [digest_ref(peer_close_content)]
neg_close_peer_ref_not_in_evidence = _mutated(pos_oo_close_agreed_result)
neg_close_peer_ref_not_in_evidence["claims"][1]["evidence"] = [digest_ref(own_close_content)]

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

# --- neg-close-agreed-relabelled-contested -- the CONTESTED positive with --
#     close_state relabelled AGREED and NOTHING else changed: peer_close_ref
#     still cites the record that `rebuts` ours. This is the adversarial
#     case (2026-09-28): "a contested close relabelled 'agreed' validates".
#     It DOES validate against the schema -- that is the hole -- and is
#     rejected by the checker's link walk over its .records.json, which
#     recomputes CONTESTED from the `rebuts` link and fails the claim on
#     the mismatch (spec section 4.1's normative rule).
neg_close_agreed_relabelled_contested = _mutated(pos_oo_close_contested_result)
neg_close_agreed_relabelled_contested["claims"][1]["close"]["close_state"] = "AGREED"
neg_close_agreed_relabelled_contested["view"]["title"] = "OO Close -- 2026-09-01 (relabelled agreed)"

# --- the records each close fixture's link walk reads -------------------
#     One sidecar per fixture: `<name>.records.json`, a JSON array of the
#     record objects whose json_digest the fixture's close claim cites. The
#     relabelled negative ships the CONTESTED positive's records unchanged --
#     the Result lies, the bundle does not.
CLOSE_RECORDS: dict = {
    "pos-oo-close-agreed-result": [own_close_content, peer_close_content],
    "pos-oo-close-contested-result": [own_close_content, peer_rebuttal_content],
    "pos-oo-close-unilateral-result": [own_close_content],
    "pos-oo-close-unilateral-named-peer-result": [own_close_content, peer_silent_close_content],
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
    write("pos-oo-close-unilateral-named-peer-result", pos_oo_close_unilateral_named_peer_result)
    write("pos-oo-close-contested-result", pos_oo_close_contested_result)
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
    for name, records in CLOSE_RECORDS.items():
        write(f"{name}.records", records)
    return 0


if __name__ == "__main__":
    sys.exit(main())
