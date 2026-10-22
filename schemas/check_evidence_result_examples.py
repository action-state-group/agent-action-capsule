#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
check_evidence_result_examples.py

Validates every committed Evidence Result v0 example fixture
(vectors/evidence-result/) against schemas/evidence-result-v0.json, and
proves each negative fixture's rejection is load-bearing rather than a check
that can never fire.

What this enforces (spec/evidence-result-v0.md is normative; this is the
mechanical half):

  1. POSITIVE: pos-example-org-claims-result.json (three claims, one per verdict
     bucket) validates against $defs/EvidenceResult.
  2. NEGATIVE: five fixtures, each a byte-for-byte copy of the positive with
     exactly one field changed, MUST fail validation:
       - neg-untiered-claim.json: claim-1 missing `tier`.
       - neg-met-with-sufficiency-gap.json: claim-1 keeps verdict `met` with
         sufficiency changed to `GAP` (spec section 1's binding rule).
       - neg-aggregate-without-coverage.json: `aggregate.coverage` removed.
       - neg-contract-ref-missing.json: claim-1 missing `contract_ref`.
       - neg-disclosure-carrier-under-withheld.json: claim-3's presentation
         changed from `analysis` to `disclosure` while `status` stays
         `WITHHELD` (spec section 2's disclosure-policy gate).
  3. MUTANT CHECK: each negative's rejection is
     re-tested with the specific schema rule it depends on stripped out. With
     the rule removed, the SAME fixture MUST validate -- proving the check
     above can actually fail, not just report green by construction. The
     rule is then restored in memory (the committed schema file is never
     modified) and re-verified red.
  4. CLAIM TYPES, reconcile normative, close PROPOSED (the 2026-09-25
     ruling -- "close +
     reconcile as claim types in result v0"): five more positives
     (pos-example-org-reconcile-result, pos-example-org-close-agreed-result,
     pos-example-org-close-unilateral-result, pos-example-org-close-unilateral-named-peer-
     result, pos-example-org-close-contested-result -- the Evidence Layer's three
     Close states, read from links; UNILATERAL both with and without the
     peer named, since `peer` / `peer_close_ref` are OPTIONAL there, as
     close-v1's unconditional peer-Close link has them) MUST validate, and
     four more negatives MUST fail, each with its own mutant check:
       - neg-close-agreed-without-peer.json: close-1 is AGREED but `peer`
         is removed (CloseClaim's AGREED-or-CONTESTED rule).
       - neg-close-contested-without-peer-close-ref.json: close-1 is
         CONTESTED but `peer_close_ref` (the rebutting record, by digest)
         is removed (same rule). There is deliberately NO negative for a
         UNILATERAL close that names a peer or cites one: the schema
         permits both; that such a row never READS as agreement is
         capsule-viewer's rule, pinned there.
       - neg-reconcile-tallies-missing-state.json: reconcile-1's
         tallies.unresolved removed (all six states required; absent is
         never zero; keys as schemas/judge/close-v1.json spells them).
       - neg-unrecognized-claim-type.json: claim-1 given `type:
         "adjudication"`, outside ClaimType's closed enum. The schema is
         closed-world so it fails HERE; rendering the same document as an
         "unrecognized" row (never dropped) is capsule-viewer's job and is
         pinned by that repo's tests, not this checker.
  5. CLOSE STATE IS DERIVABLE (otherwise a contested close relabelled
     'agreed' would validate). The schema
     cannot see across records, so this checker walks links: every close
     fixture ships `<name>.records.json`, the record headers its close claim
     cites, and for each `type: close` claim the checker (a) resolves
     `close.close_ref` to a record by json_digest, (b) reads every
     `acknowledges` / `rebuts` link in the sidecar that targets that digest,
     (c) derives the state -- any `rebuts` => CONTESTED, else any
     `acknowledges` => AGREED, else UNILATERAL -- and (d) FAILS the claim
     when the asserted `close_state` differs, or when an AGREED/CONTESTED
     claim's `peer_close_ref` is not the digest of a record carrying that
     link. Every close positive MUST pass the walk (a close positive with no
     sidecar is a finding, not a skip), and:
       - neg-close-agreed-relabelled-contested.json: the CONTESTED positive
         with close_state relabelled AGREED, nothing else changed, same
         records. It MUST validate clean against the schema (the hole) and
         MUST be rejected by the walk; its mutant check flips the walk to
         trust the asserted field (the pre-review behaviour) and confirms
         the same fixture then passes, then restores the walk and re-rejects.
  6. THREE MORE CLOSE RULES, one
     schema negative and three link negatives, each with its own mutant:
       - COUNTERPARTY: an `acknowledges` / `rebuts` link makes a state only
         when the linking record's `book_id` is present and differs from
         the cited Close's `book_id` (the store identity the evidence-book
         header carries; the -00 draft's header names no store field and
         its `principal_ref` is opaque). A link from the Close's own book is
         ignored. neg-close-agreed-self-acknowledged.json (schema-valid) is
         rejected as UNILATERAL; its mutant is a walk that counts any link
         whatever its book (`ignore_counterparty`).
       - REFS RESOLVE INSIDE evidence[]: `close_ref.digest` and, when
         present, `peer_close_ref.digest` MUST be among the claim's
         `evidence[]` digests. neg-close-ref-not-in-evidence.json and
         neg-close-peer-ref-not-in-evidence.json (schema-valid) are each
         rejected; their mutant skips the membership check
         (`skip_evidence_membership`).
       - CONTESTED IS NEVER met: the schema's Claim rule forbids verdict
         `met` when close.close_state is CONTESTED
         (neg-close-contested-verdict-met.json, a schema negative with the
         usual strip-the-rule mutant), and the walk applies the same rule
         to the RECOMPUTED state, so relabelling the state away does not
         rescue `met`. The CONTESTED positive now carries `not_met`.
  7. THE COUNTERPARTY RULE: neither book_id nor signer alone is enough,
     since a producer can mint a second book or a second key equally
     easily. The counterparty rule is now three-part, and this
     checker enforces the two parts a record header can show:
       (1) the linking record's `book_id` is present and differs from the
           cited Close's `book_id`;
       (2) the linking record's `book_id` equals the Close claim's named
           `peer` (the record header carries no peer field; the claim's
           `close.peer` is the named peer);
       (3) the linking record is signed under a different key than the
           Close -- NOT checked here: the header carries no signer. Until
           the contract pins the peer's key, a second book named as the
           peer and signed under a second key still passes this check.
     A Close with no `book_id` accepts no linker at all (UNILATERAL at
     best). AGREED therefore means "acknowledged by the named peer's book
     under a different key", not "by an independent party", until the
     contract pins the peer's key. Two more link negatives, each with its
     own mutant:
       - neg-close-agreed-third-book.json: the acknowledging record is from
         a third book (`example-org-audit`, seq 7) that is not the named peer
         `example-org-sor`. Rule (1) passes, rule (2) fails; the walk reads
         UNILATERAL. Mutant `ignore_named_peer`: the second-pass walk, which
         required only a different book.
       - neg-close-agreed-bookless-close.json: the cited Close carries no
         `book_id` at all; the named peer's record acknowledges it. Rejected
         as UNILATERAL: nothing can be a counterparty to a Close that names
         no book. Mutant `accept_bookless_close`: a walk that lets rules (1)
         and (2) run against a missing book (`book != None` is true for any
         book, so the named peer's link counts).

  8. THE x- EXTENSION SLOT (spec section 8a): the document and each claim
     admit members named `x-...`, and everything else stays closed.
       - POSITIVE: pos-example-org-extended-result (`x-judge-pin` on claim-2,
         `x-judged-selection` on the document) and
         pos-judge-producer-x-judge-result (a judging producer's output with
         its judge members renamed into the slot) validate. Each has a
         mutant per level that removes that level's slot, and the fixture
         MUST then fail. This proves both levels are load-bearing.
       - NEGATIVE: neg-unprefixed-document-member (a bare `judged_selection`
         on the document), neg-unprefixed-claim-member (a bare `rule_id` on
         claim-2) and neg-judge-producer-unprefixed-result (the producer's
         output as written) MUST fail. Their mutant widens the slot at the
         offending level to admit any name, and the fixture MUST then
         validate.
       - ADDITIVE: every other committed fixture gets the same verdict
         (valid or rejected) from the schema with both slots removed. Those
         fixtures carry no x- member, so this is a guard against a slot
         written too wide (a pattern matching every name), not a proof
         over documents in general. The proof is that patternProperties
         `^x-` touches only `x-` names.
       - EXTENSION SCOPE: x- members on every claim of the reconcile
         positive validate. An x- member inside a typed body does not.
       - IGNORED: stripping every x- member from
         pos-example-org-extended-result gives exactly
         pos-example-org-claims-result. Adding x- members to every close
         positive leaves the link walk's findings unchanged.
  9. PROPOSED coverage_report (spec section 7.1): one more positive,
     pos-example-org-coverage-result (the claims positive plus a per-requirement
     coverage section), MUST validate and pass the cross-element coverage
     check. Five schema negatives MUST fail, each with a strip-the-rule
     mutant:
       - neg-coverage-satisfied-with-gap: a SATISFIED row carries a gap.
       - neg-coverage-not-found-source-with-records: a source is NOT_FOUND
         while still counting a record.
       - neg-coverage-gap-remedy-absent: a gap's `remedy` key is removed
         ("no remedy" is an explicit null, never an absent key).
       - neg-coverage-unknown-epistemic-type: a source typed outside the
         closed set.
       - neg-coverage-uppercase-epistemic-type: a known type written in
         upper case; the tokens are lower case only. The checker also pins
         $defs.EpistemicType to schemas/vendor/epistemic-types.json exactly.
     Two negatives validate against the schema and are rejected by the
     cross-element check, each with a check mutant:
       - neg-coverage-correlated-counted-as-met: req-claim-1's records
         relabelled as one producer's, independence.met left true. Records
         from one producer correlate, they do not corroborate. Mutant
         `count_records`: independence reached by counting records.
       - neg-coverage-summary-does-not-recompute: summary.satisfied 3 over
         two SATISFIED rows. Mutant `trust_summary`: no recompute.
  10. PROPOSED aggregate.coverage_declaration (spec section 7.2): one more
     positive, pos-example-org-coverage-declaration-result (the claims
     positive with the aggregate's coverage kind), MUST validate, and with
     the member removed MUST equal the claims positive byte for byte. One
     schema negative MUST fail, with a strip-the-rule mutant:
       - neg-coverage-declaration-unknown-kind: kind `complete`, outside the
         closed CoverageKind enum.
     The never-stronger-than-the-evidence rule needs the evidence sets; its
     vector is vectors/coverage-declaration-v0/aggregate-stronger-than-evidence.
  11. Traceability (spec sections 1 and 2): pos-example-org-recorded-absence-result
     (the claims positive with claim-3 a story claim about a recorded absence,
     citing the absence record by digest) MUST validate. One schema negative
     MUST fail, with a strip-the-rule mutant:
       - neg-claim-evidence-empty: the same claim with `evidence: []`.
  12. Coverage counts evaluations, one per claim (spec section 3):
     pos-example-org-repeated-requirement-result (two claims of one
     requirement, one met and one not_met) MUST validate, and every positive's
     `evaluated_population` MUST equal its in-force claim count and
     `unknown_count` its in-force UNKNOWN claims (section 4.3). `excluded_not_applicable` has no claim and is not
     recomputed.
  13. The fourth verdict and applicability (spec sections 4.2, 4.3): the
     out_of_scope, close-switched-on and applicability positives MUST
     validate and pass revision_findings; the eight schema negatives MUST
     fail, each with a strip-the-rule mutant; the REVISION_NEGATIVES MUST
     pass the schema and fail revision_findings, each flipped by its mutant.

Usage:
    python3 schemas/check_evidence_result_examples.py       # from repo root
    python3 check_evidence_result_examples.py                # from schemas/

Exit 0: every check above passed. Exit 1: a finding was printed. Exit 2: a
harness error (missing dependency, missing fixture).

NOT covered here (explicitly named, not silently skipped):
  - `generated_at`'s "format": "date-time" keyword is annotation-only under
    python-jsonschema's default Draft202012Validator (no FormatChecker is
    attached) -- a garbage generated_at value currently validates clean.
    Same caveat evidence-plan-ir-v0.md's checker documents; not a defect
    introduced here.
  - Claim `id` uniqueness within a Result is a cross-element constraint
    plain JSON Schema cannot express (spec section 4); the TypeScript reader
    enforces it, this checker does not. The bucket partition (every in-force
    claim in the bucket of its verdict, a later claim in none) is checked
    here by revision_findings (item 13).
  - The one-directional disclosure gate (disclosure-carrier status is
    restricted; analysis/story are not) is exercised by exactly one negative
    fixture (kind: disclosure under WITHHELD). The converse -- an
    analysis/story carrier used when disclosure would have been legal -- is
    valid by design (spec section 6) and is not a rejection case.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _result_types import ClaimDoc, EvidenceResultDoc, RecordDoc  # noqa: E402

SCHEMAS_DIR = (
    Path(__file__).parent
    if Path(__file__).parent.name == "schemas"
    else Path(__file__).parent / "schemas"
)
VECTORS_DIR = SCHEMAS_DIR.parent / "vectors" / "evidence-result"
SCHEMA_PATH = SCHEMAS_DIR / "evidence-result-v0.json"

# The link walk keys the sidecar's records by this repository's own
# canonicalization (lowercase-hex SHA-256 of UTF8(JCS(record))) -- the same
# json_digest the generator used to write every digest the fixtures cite.
sys.path.insert(0, str(SCHEMAS_DIR.parent / "python"))
from agent_action_capsule.canonical import json_digest

# Negatives that VALIDATE against the schema and are rejected only by the
# close-state link walk (checks 5 and 6). Kept apart from NEGATIVES on
# purpose: a schema rejection here would mean the fixture no longer
# demonstrates the hole it exists to pin. Each names the walk MUTANT that
# must flip it (the verifier behaviour the rule replaced) and a label.
LINK_NEGATIVES = [
    (
        "neg-close-agreed-relabelled-contested",
        "trust_asserted",
        "the walk trusting the asserted close_state",
    ),
    (
        "neg-close-agreed-self-acknowledged",
        "ignore_counterparty",
        "the walk counting a link from the Close's own book",
    ),
    (
        "neg-close-ref-not-in-evidence",
        "skip_evidence_membership",
        "the close_ref/peer_close_ref-in-evidence[] check",
    ),
    (
        "neg-close-peer-ref-not-in-evidence",
        "skip_evidence_membership",
        "the close_ref/peer_close_ref-in-evidence[] check",
    ),
    (
        "neg-close-agreed-third-book",
        "ignore_named_peer",
        "the linking book must be the claim's named peer",
    ),
    (
        "neg-close-agreed-bookless-close",
        "accept_bookless_close",
        "a Close with no book_id accepts no linker",
    ),
]

WALK_MUTANTS = (
    "trust_asserted",
    "ignore_counterparty",
    "skip_evidence_membership",
    "ignore_named_peer",
    "accept_bookless_close",
)

CLOSE_LINK_TYPES = ("acknowledges", "rebuts")

# The record-header field that identifies the store a record was committed
# in -- the evidence-book HeaderMember's `book_id`, the shape every sidecar
# here carries. draft-mih-agent-evidence-layer-00's own header names no
# store field (its `principal_ref` is opaque and host-defined, and a store
# needs none for its own records); the Close rule there is stated at store
# level ("a record from the counterparty"), so this is the field the
# counterparty check keys on.
COUNTERPARTY_FIELD = "book_id"


def _records_for(name: str) -> list[RecordDoc] | None:
    path = VECTORS_DIR / f"{name}.records.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def derive_close_state(
    records_by_digest: dict[str, RecordDoc],
    close_digest: str,
    peer: str | None,
    mutant: str | None = None,
) -> tuple[str, dict[str, set[str]], dict[str, set[str]]]:
    """(state, {counterparty record digest: {link types}}, {ignored record
    digest: {link types}}) read from the inbound `acknowledges` / `rebuts`
    links at `close_digest` -- spec section 4.1's rule: any `rebuts` =>
    CONTESTED; else any `acknowledges` => AGREED; else UNILATERAL. Never
    reads a state field from any record. A link counts only from a
    COUNTERPARTY (all of):
      (1) the linking record's `book_id` is present and differs from the
          Close's;
      (2) it equals `peer`, the Close claim's named peer (`close.peer`);
      (3) [not visible here] the record is signed under a different key --
          not checked by this walk.
    A Close with no `book_id` accepts no linker: every link is returned as
    ignored and the state is UNILATERAL. Mutants (each the walk a rule
    replaced): `ignore_counterparty` counts every link; `ignore_named_peer`
    requires only a different book (the second-pass walk);
    `accept_bookless_close` runs (1) and (2) against a Close with no book."""
    close_book = records_by_digest[close_digest].get(COUNTERPARTY_FIELD)
    linking: dict[str, set[str]] = {}
    ignored: dict[str, set[str]] = {}
    for digest, record in records_by_digest.items():
        book = record.get(COUNTERPARTY_FIELD)
        if mutant == "ignore_counterparty":
            counterparty = True
        elif close_book is None and mutant != "accept_bookless_close":
            counterparty = False
        else:
            counterparty = book is not None and book != close_book
            if mutant != "ignore_named_peer":
                counterparty = counterparty and book == peer
        for link in record.get("links") or []:
            if link.get("target") == close_digest and link.get("type") in CLOSE_LINK_TYPES:
                (linking if counterparty else ignored).setdefault(digest, set()).add(link["type"])
    types = set().union(*linking.values()) if linking else set()
    if "rebuts" in types:
        state = "CONTESTED"
    elif "acknowledges" in types:
        state = "AGREED"
    else:
        state = "UNILATERAL"
    return state, linking, ignored


def close_state_findings(
    name: str, doc: EvidenceResultDoc, records: list[RecordDoc], mutant: str | None = None
) -> list[str]:
    """Findings from recomputing every close claim's state from `records`.
    `mutant` names a verifier behaviour a rule replaced, used only to prove
    that rule load-bearing: `trust_asserted` resolves close_ref but never
    walks a link (the pre-review verifier); `ignore_counterparty` counts a
    link from the Close's own book; `skip_evidence_membership` never holds
    close_ref / peer_close_ref to the claim's evidence[]; `ignore_named_peer`
    counts a link from any other book, not only the claim's named peer;
    `accept_bookless_close` lets a Close with no book_id take a linker."""
    if mutant is not None and mutant not in WALK_MUTANTS:
        raise ValueError(f"unknown walk mutant {mutant!r}")
    findings = []
    by_digest = {json_digest(record): record for record in records}
    for index, claim in enumerate(doc.get("claims", [])):
        if claim.get("type") != "close":
            continue
        close = claim.get("close") or {}
        asserted = close.get("close_state")
        close_digest = (close.get("close_ref") or {}).get("digest")
        peer_digest = (close.get("peer_close_ref") or {}).get("digest")
        # Both refs resolve inside evidence[] (2026-09-28): a claim reports
        # only on a Close, and cites only a state-making record, that it
        # puts in evidence.
        if mutant != "skip_evidence_membership":
            in_evidence = {ref.get("digest") for ref in claim.get("evidence") or []}
            for field, digest in (("close_ref", close_digest), ("peer_close_ref", peer_digest)):
                if digest is not None and digest not in in_evidence:
                    findings.append(
                        f"{name}: claims[{index}].close.{field} ({digest[:12]}...) does not "
                        f"resolve inside the claim's evidence[]"
                    )
        if close_digest not in by_digest:
            findings.append(
                f"{name}: claims[{index}].close.close_ref names no record in "
                f"{name}.records.json -- the state cannot be recomputed"
            )
            continue
        if mutant == "trust_asserted":
            # The mutant verifier: it never walks a link, so it has nothing
            # to compare the field against and nothing to hold
            # peer_close_ref to -- every check below is the walk.
            continue
        derived, linking, ignored = derive_close_state(
            by_digest, close_digest, close.get("peer"), mutant=mutant
        )
        if derived != asserted:
            read = ", ".join(sorted(t for ts in linking.values() for t in ts)) or "no counterparty acknowledges/rebuts link"
            if ignored:
                why = (
                    f"the Close carries no {COUNTERPARTY_FIELD}, so nothing can be its counterparty"
                    if by_digest[close_digest].get(COUNTERPARTY_FIELD) is None
                    else f"a record in the Close's own {COUNTERPARTY_FIELD}, with none, or not the named peer"
                )
                read += f"; ignored {', '.join(sorted(t for ts in ignored.values() for t in ts))} from {why}"
            findings.append(
                f"{name}: claims[{index}].close.close_state is asserted {asserted} but the "
                f"cited Close's inbound links read {derived} ({read})"
            )
            continue
        # A CONTESTED Close is never met (2026-09-28) -- applied to the
        # RECOMPUTED state, so the schema's rule on the asserted field
        # cannot be dodged by relabelling.
        if derived == "CONTESTED" and claim.get("verdict") == "met":
            findings.append(
                f"{name}: claims[{index}] is CONTESTED by the cited Close's inbound links "
                f"but carries verdict `met` -- a contested Close never counts as met"
            )
        if derived in ("AGREED", "CONTESTED"):
            wanted = "acknowledges" if derived == "AGREED" else "rebuts"
            if wanted not in linking.get(peer_digest, set()):
                findings.append(
                    f"{name}: claims[{index}].close.peer_close_ref is not the digest of a "
                    f"counterparty record carrying the `{wanted}` link that makes this Close {derived}"
                )
    return findings

POSITIVE_RESULT = "pos-example-org-claims-result"

# Claim types (2026-09-25 ruling; reconcile normative, close PROPOSED):
# every positive keeps the
# untouched requirement claim-1 beside its typed claims -- one typed claim
# on each close positive, two on the reconcile positive (reconcile-1
# SATISFIED, reconcile-2 GAP).
POSITIVES = [
    POSITIVE_RESULT,
    "pos-example-org-reconcile-result",
    "pos-example-org-close-agreed-result",
    "pos-example-org-close-unilateral-result",
    "pos-example-org-close-unilateral-named-peer-result",
    "pos-example-org-close-contested-result",
    "pos-example-org-extended-result",
    "pos-judge-producer-x-judge-result",
    "pos-example-org-coverage-result",
    "pos-example-org-coverage-declaration-result",
    "pos-example-org-recorded-absence-result",
    "pos-example-org-repeated-requirement-result",
    "pos-example-org-out-of-scope-result",
    "pos-example-org-out-of-scope-empty-result",
    "pos-example-org-close-switched-on-result",
    "pos-example-org-applicability-result",
    "pos-example-org-applicability-boundary-result",
    "pos-example-org-applicability-in-force-result",
    "pos-example-org-reconcile-later-result",
]

# name -> (mutant description, path to the $defs entry whose rule is
# stripped to prove the rejection is load-bearing)
NEGATIVES = [
    "neg-untiered-claim",
    "neg-met-with-sufficiency-gap",
    "neg-aggregate-without-coverage",
    "neg-contract-ref-missing",
    "neg-disclosure-carrier-under-withheld",
    "neg-close-agreed-without-peer",
    "neg-close-contested-without-peer-close-ref",
    "neg-reconcile-tallies-missing-state",
    "neg-unrecognized-claim-type",
    "neg-close-contested-verdict-met",
    "neg-unprefixed-document-member",
    "neg-unprefixed-claim-member",
    "neg-judge-producer-unprefixed-result",
    "neg-coverage-satisfied-with-gap",
    "neg-coverage-not-found-source-with-records",
    "neg-coverage-gap-remedy-absent",
    "neg-coverage-unknown-epistemic-type",
    "neg-coverage-uppercase-epistemic-type",
    "neg-coverage-declaration-unknown-kind",
    "neg-claim-evidence-empty",
    "neg-out-of-scope-without-switch",
    "neg-out-of-scope-bucket-absent",
    "neg-out-of-scope-bucket-without-switch",
    "neg-out-of-scope-with-gap",
    "neg-out-of-scope-not-applicable-carrier",
    "neg-satisfied-not-evaluable",
    "neg-not-applicable-verdict",
    "neg-out-of-scope-on-reconcile-claim",
]

# Spec sections 3, 4.2 and 4.3: cross-element negatives that pass the schema
# and fail revision_findings, each with the mutant that switches its rule off.
REVISION_NEGATIVES = [
    ("neg-out-of-scope-listed-in-met", "trust_buckets", "the bucket partition"),
    ("neg-later-claim-in-bucket", "trust_buckets", "the bucket partition"),
    ("neg-switch-disagrees-in-row", "skip_rows", "the one-value-per-requirement rule"),
    ("neg-applies-from-disagrees-in-row", "skip_rows", "the one-value-per-requirement rule"),
    ("neg-later-claim-in-population", "population_all_claims", "counting in-force claims only"),
    ("neg-later-unknown-counted", "unknown_all_claims", "counting in-force claims only"),
    ("neg-not-yet-in-force-absent", "skip_later_count", "the not_yet_in_force count"),
    ("neg-not-yet-in-force-wrong", "skip_later_count", "the not_yet_in_force count"),
    ("neg-generated-at-unparseable", "skip_date_parse", "the date parse"),
    ("neg-applies-from-not-a-date", "skip_date_parse", "the date parse"),
    ("neg-generated-at-impossible", "skip_date_parse", "the date parse"),
    ("neg-generated-at-without-seconds", "skip_date_parse", "the date parse"),
    ("neg-not-yet-in-force-without-later", "skip_later_count", "the not_yet_in_force count"),
]

# Section 8a: the two levels that carry the x- slot, as $defs names.
EXTENSION_LEVELS = ("EvidenceResult", "Claim")
EXTENSION_PATTERN = "^x-"

# Each slot positive and the levels where it carries an x- member. Removing
# the slot at any one of those levels MUST make it fail.
EXTENSION_POSITIVES = {
    "pos-example-org-extended-result": ("EvidenceResult", "Claim"),
    "pos-judge-producer-x-judge-result": ("EvidenceResult", "Claim"),
}

# Each slot negative and the one level whose closure rejects it. Widening the
# slot at that level to any name MUST make it validate.
EXTENSION_NEGATIVES = {
    "neg-unprefixed-document-member": "EvidenceResult",
    "neg-unprefixed-claim-member": "Claim",
    "neg-judge-producer-unprefixed-result": "Claim",
}


def _without_slot(schema: dict, levels: tuple[str, ...] = EXTENSION_LEVELS) -> dict:
    """The schema with the x- slot removed at `levels`: the pre-section-8a
    schema when `levels` is both."""
    mutant = copy.deepcopy(schema)
    for level in levels:
        del mutant["$defs"][level]["patternProperties"]
    return mutant


def _slot_open_to_any_name(schema: dict, level: str) -> dict:
    """The schema with `level`'s slot widened to every member name. The
    pattern `.*` matches any name, so nothing at that level is additional."""
    mutant = copy.deepcopy(schema)
    mutant["$defs"][level]["patternProperties"] = {".*": {}}
    return mutant


# `value` is any JSON value; the walk is shape-agnostic.
def _strip_extensions(value: object) -> object:
    """`value` with every x- member removed from the document and its claims,
    the two levels that admit one."""
    doc = json.loads(json.dumps(value))
    for claim in doc.get("claims", []):
        for key in [k for k in claim if k.startswith("x-")]:
            del claim[key]
    for key in [k for k in doc if k.startswith("x-")]:
        del doc[key]
    return doc

# PROPOSED coverage_report (spec section 7.1): negatives that VALIDATE
# against the schema and are rejected only by the cross-element coverage
# check. Each names the check MUTANT that must flip it and a label.
COVERAGE_NEGATIVES = [
    (
        "neg-coverage-correlated-counted-as-met",
        "count_records",
        "counting records instead of producers toward independence",
    ),
    (
        "neg-coverage-summary-does-not-recompute",
        "trust_summary",
        "taking summary as given instead of recomputing it",
    ),
]

_STATUS_TO_SUFFICIENCY = {
    "SATISFIED": "SATISFIED",
    "NOT_FOUND": "GAP",
    "INSUFFICIENT": "INSUFFICIENT",
    "UNKNOWN": "UNKNOWN",
}


# RFC 3339 section 5.6 with a required offset, the same grammar the TypeScript
# reader applies (ts/src/result-root.ts `utcDateOf`). A leap second (60) is
# not accepted.
RFC3339_WITH_OFFSET = re.compile(
    r"\A(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|([+-])(\d{2}):(\d{2}))\Z"
)
CALENDAR_DATE = re.compile(r"\A(\d{4})-(\d{2})-(\d{2})\Z")


def _calendar_date(value: str) -> date | None:
    match = CALENDAR_DATE.match(value)
    if match is None:
        return None
    try:
        return date(*(int(part) for part in match.groups()))
    except ValueError:
        return None


def _utc_date(generated_at: str) -> date | None:
    match = RFC3339_WITH_OFFSET.match(generated_at)
    if match is None:
        return None
    year, month, day, hours, minutes, seconds = (int(part) for part in match.groups()[:6])
    sign, offset_hours, offset_minutes = match.group(7), match.group(8), match.group(9)
    if hours > 23 or minutes > 59 or seconds > 59:
        return None
    if sign is not None and (int(offset_hours) > 23 or int(offset_minutes) > 59):
        return None
    try:
        local = datetime(year, month, day, hours, minutes, seconds)
    except ValueError:
        return None
    offset = timedelta(0)
    if sign is not None:
        offset = timedelta(hours=int(offset_hours), minutes=int(offset_minutes))
        if sign == "-":
            offset = -offset
    return (local - offset).date()


def revision_findings(doc: EvidenceResultDoc, *, mutant: str | None = None) -> list[str]:
    """Spec sections 3, 4.2 and 4.3's cross-element rules, which JSON Schema
    cannot express: every in-force claim is in exactly the bucket of its
    verdict and a later claim in none; every claim of one requirement carries
    the same copied facts; coverage counts in-force claims, and
    not_yet_in_force the later ones; dates parse. ``mutant`` switches off one
    rule to prove a rejection is that rule's: ``trust_buckets``,
    ``skip_rows``, ``population_all_claims`` and ``unknown_all_claims`` (count
    every claim, as before section 4.3), ``skip_later_count`` and
    ``skip_date_parse``."""
    out: list[str] = []
    claims = doc["claims"]
    aggregate = doc["aggregate"]
    coverage = aggregate["coverage"]
    dated = [c for c in claims if "applies_from" in c]
    later: set[str] = set()
    if dated and mutant == "skip_date_parse":
        # the rule switched off: dates compared as text, nothing parsed
        as_of_text = doc["generated_at"][:10]
        later = {c["id"] for c in dated if c["applies_from"] > as_of_text}
    elif dated:
        as_of = _utc_date(doc["generated_at"])
        if as_of is None:
            out.append(f"generated_at {doc['generated_at']!r} is not an RFC 3339 date-time with an offset")
            return out
        for claim in dated:
            applies = _calendar_date(claim["applies_from"])
            if applies is None:
                out.append(f"{claim['id']}: applies_from {claim['applies_from']!r} is not a calendar date")
            elif applies > as_of:
                later.add(claim["id"])
    in_force = [c for c in claims if c["id"] not in later]

    if mutant != "trust_buckets":
        buckets = aggregate["buckets"]
        placed: dict[str, list[str]] = {}
        for key, ids in buckets.items():
            for claim_id in ids:
                placed.setdefault(claim_id, []).append(key)
        for claim in claims:
            where = placed.pop(claim["id"], [])
            if claim["id"] in later:
                if where:
                    out.append(f"{claim['id']} is not yet in force but is in buckets {where}")
            elif where != [claim["verdict"]]:
                out.append(f"{claim['id']} ({claim['verdict']}) is in buckets {where}")
        for claim_id in placed:
            out.append(f"buckets name {claim_id!r}, which has no claim")

    if mutant != "skip_rows":
        rows: dict[tuple[str, str], list[ClaimDoc]] = {}
        for claim in claims:
            rows.setdefault((claim["contract_ref"], claim["requirement_ref"]), []).append(claim)
        for (contract, requirement), members in rows.items():
            for member in ("out_of_scope_allowed", "applies_from"):
                if len({json.dumps(c.get(member)) for c in members}) > 1:
                    out.append(f"{contract} {requirement}: its claims disagree on {member}")

    population = claims if mutant == "population_all_claims" else in_force
    if coverage["evaluated_population"] != len(population):
        out.append(f"evaluated_population {coverage['evaluated_population']}, but {len(population)} in-force claim(s)")
    counted = claims if mutant == "unknown_all_claims" else in_force
    unknown = sum(1 for c in counted if c["sufficiency"] == "UNKNOWN")
    if coverage["unknown_count"] != unknown:
        out.append(f"unknown_count {coverage['unknown_count']}, but {unknown} in-force UNKNOWN claim(s)")
    if mutant != "skip_later_count":
        stated = coverage.get("not_yet_in_force")
        if later and stated != len(later):
            out.append(f"not_yet_in_force {stated}, but {len(later)} later claim(s)")
        if not later and stated is not None:
            out.append("not_yet_in_force is present, but no claim is later")
    return out


def coverage_findings(doc: EvidenceResultDoc, *, mutant: str | None = None) -> list[str]:
    """Spec section 7.1's cross-element rules, which JSON Schema cannot
    express. Not checkable here, by design (spec section 7.1, "What a
    verifier of the document alone cannot catch"): a hand edit that moves
    counts from correlated_records to independent_producers, or lowers
    required_producers -- the document carries no producer identities. ``mutant`` switches off one rule to prove a rejection is that
    rule's: ``count_records`` takes independence as met when the records
    (not the producers) reach the requirement; ``trust_summary`` skips the
    summary recompute."""
    report = doc.get("coverage_report")
    if report is None:
        return []
    out: list[str] = []
    claims = {c["id"]: c for c in doc.get("claims", [])}
    rows = report.get("requirements", [])
    for row in rows:
        ref = row["requirement_ref"]
        for claim_id in row.get("claim_ids", []):
            claim = claims.get(claim_id)
            if claim is None:
                out.append(f"{ref}: claim_ids names {claim_id!r}, which has no claim")
            elif claim["requirement_ref"] != ref or claim["contract_ref"] != report["contract_ref"]:
                out.append(f"{ref}: claim {claim_id!r} is for another requirement or contract")
        digests = set()
        for src in row.get("sources", []):
            if src["contemporaneous_count"] + src["backfilled_count"] != src["record_count"]:
                out.append(f"{ref}/{src['source']}: contemporaneous + backfilled != record_count")
            if len(src["evidence"]) != src["record_count"]:
                out.append(f"{ref}/{src['source']}: evidence digests != record_count")
            digests.update(e["digest"] for e in src["evidence"])
        ind = row["independence"]
        if mutant == "count_records":
            reached = len(digests) >= ind["required_producers"]
        else:
            reached = ind["independent_producers"] >= ind["required_producers"]
            counted = ind["independent_producers"] + ind["correlated_records"] + ind["unattributed_records"]
            if counted != len(digests):
                out.append(
                    f"{ref}: independent_producers + correlated_records + unattributed_records "
                    f"!= {len(digests)} distinct records"
                )
            if (ind["producer_basis"] == "none") != (ind["independent_producers"] == 0):
                out.append(f"{ref}: producer_basis {ind['producer_basis']!r} disagrees with independent_producers")
        if ind["met"] != reached:
            out.append(
                f"{ref}: independence.met is {ind['met']} but {ind['independent_producers']} producer(s) "
                f"against {ind['required_producers']} required -- records from one producer correlate, "
                "they do not corroborate"
            )
    if mutant != "trust_summary":
        all_gaps = [g for r in rows for g in r.get("gaps", [])]
        expected = {
            "requirements": len(rows),
            "satisfied": sum(1 for r in rows if r["status"] == "SATISFIED"),
            "with_gaps": sum(1 for r in rows if r.get("gaps")),
            "gaps": len(all_gaps),
            "gaps_without_remedy": sum(1 for g in all_gaps if g.get("remedy") is None),
        }
        if report.get("summary") != expected:
            out.append(f"summary {report.get('summary')!r} does not recompute; expected {expected!r}")
    return out


def _load(name: str) -> EvidenceResultDoc:
    path = VECTORS_DIR / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


# `schema` is an arbitrary JSON Schema document: the keyword set is open-ended
# and recursive ($defs/$ref/if/then/...), so a TypedDict here would assert a
# fixed shape JSON Schema does not have, which is less honest than `dict`.
def _validator_for(schema: dict):
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - environment problem, not a finding
        print(f"ERROR: the 'jsonschema' package is required to run this check: {exc}")
        sys.exit(2)
    return jsonschema.Draft202012Validator(schema)


# `schema` and the return value are the same open-ended JSON Schema document
# type justified above `_validator_for` -- a mutant is that same document with
# one $defs rule altered, not a shape this module owns.
def _mutant_schema_dropping_claim_required(schema: dict, field: str) -> dict:
    mutant = copy.deepcopy(schema)
    mutant["$defs"]["Claim"]["required"] = [
        r for r in mutant["$defs"]["Claim"]["required"] if r != field
    ]
    return mutant


def main() -> int:
    if not SCHEMA_PATH.exists():
        print(f"ERROR: schema not found at {SCHEMA_PATH}")
        return 2
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = _validator_for(schema)

    findings = []

    # --- 1. POSITIVE: each MUST validate clean ---
    for name in POSITIVES:
        instance = _load(name)
        errors = sorted(validator.iter_errors(instance), key=lambda e: e.path)
        if errors:
            findings.append(f"POSITIVE-REJECTED {name}: {errors[0].message}")
        else:
            print(f"OK  EvidenceResult {name}.json")

    # --- 2. NEGATIVE: each MUST fail ---
    negative_errors_by_name = {}
    for name in NEGATIVES:
        neg_instance = _load(name)
        neg_errors = list(validator.iter_errors(neg_instance))
        negative_errors_by_name[name] = neg_errors
        if not neg_errors:
            findings.append(
                f"NEGATIVE-DID-NOT-FAIL {name}: expected schema validation to reject "
                "this fixture, but it validated clean"
            )
        else:
            print(f"OK  EvidenceResult {name}.json correctly REJECTED "
                  f"({len(neg_errors)} error(s), e.g. {neg_errors[0].message!r})")

    # --- 3. MUTANT CHECKS: strip the specific rule, confirm the SAME -------
    #        negative fixture now validates, then confirm restoring makes it
    #        fail again. Proves each check 2 case is load-bearing.

    # `mutant_schema` is again the open-ended JSON Schema document type
    # justified above `_validator_for`.
    def _mutant_check(name: str, mutant_schema: dict, mutation_label: str) -> None:
        neg_instance = _load(name)
        mutant_validator = _validator_for(mutant_schema)
        mutant_errors = list(mutant_validator.iter_errors(neg_instance))
        if mutant_errors:
            findings.append(
                f"MUTANT-DID-NOT-FLIP {name}: removing {mutation_label} did not make "
                f"the fixture pass (still {len(mutant_errors)} error(s)) -- the "
                "rejection may be failing for an unrelated reason, not the rule "
                "this mutation targets"
            )
        else:
            print(f"OK  MUTANT        {name} -- with {mutation_label} removed, "
                  "the fixture now VALIDATES CLEAN (confirms the check is load-bearing)")
        restored_validator = _validator_for(schema)
        restored_errors = list(restored_validator.iter_errors(neg_instance))
        if not restored_errors:
            findings.append(
                f"MUTANT-RESTORE-FAILED {name}: after restoring {mutation_label}, "
                "the fixture validated clean instead of failing"
            )
        else:
            print(f"OK  MUTANT        {name} -- restored rule re-rejects the same fixture")

    if negative_errors_by_name["neg-untiered-claim"]:
        _mutant_check(
            "neg-untiered-claim",
            _mutant_schema_dropping_claim_required(schema, "tier"),
            "Claim.required's 'tier' entry",
        )

    if negative_errors_by_name["neg-met-with-sufficiency-gap"]:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["Claim"]["allOf"] = []
        _mutant_check(
            "neg-met-with-sufficiency-gap",
            mutant,
            "Claim's sufficiency/verdict if/then rule",
        )

    if negative_errors_by_name["neg-aggregate-without-coverage"]:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["Aggregate"]["required"] = [
            r for r in mutant["$defs"]["Aggregate"]["required"] if r != "coverage"
        ]
        _mutant_check(
            "neg-aggregate-without-coverage",
            mutant,
            "Aggregate.required's 'coverage' entry",
        )

    if negative_errors_by_name["neg-contract-ref-missing"]:
        _mutant_check(
            "neg-contract-ref-missing",
            _mutant_schema_dropping_claim_required(schema, "contract_ref"),
            "Claim.required's 'contract_ref' entry",
        )

    if negative_errors_by_name["neg-disclosure-carrier-under-withheld"]:
        mutant = copy.deepcopy(schema)
        # Widen DisclosureCarrier.status back to the full EvidenceStatus set,
        # removing the section 2 gate's restriction to DisclosedStatus.
        mutant["$defs"]["DisclosureCarrier"]["properties"]["status"] = {
            "$ref": "#/$defs/EvidenceStatus"
        }
        _mutant_check(
            "neg-disclosure-carrier-under-withheld",
            mutant,
            "DisclosureCarrier.status's restriction to DisclosedStatus",
        )

    # --- Claim types (2026-09-25 ruling) -----------------------------------

    if negative_errors_by_name["neg-close-agreed-without-peer"]:
        mutant = copy.deepcopy(schema)
        # Strip CloseClaim's AGREED/CONTESTED <-> peer/peer_close_ref binding.
        mutant["$defs"]["CloseClaim"]["allOf"] = []
        _mutant_check(
            "neg-close-agreed-without-peer",
            mutant,
            "CloseClaim's AGREED-or-CONTESTED-requires-peer if/then rule",
        )

    if negative_errors_by_name["neg-close-contested-without-peer-close-ref"]:
        mutant = copy.deepcopy(schema)
        # Same rule, other branch of the enum: CONTESTED must cite the
        # rebutting record. Stripping the binding must flip this one too.
        mutant["$defs"]["CloseClaim"]["allOf"] = []
        _mutant_check(
            "neg-close-contested-without-peer-close-ref",
            mutant,
            "CloseClaim's AGREED-or-CONTESTED-requires-peer if/then rule",
        )

    if negative_errors_by_name["neg-reconcile-tallies-missing-state"]:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["ReconcileTallies"]["required"] = [
            r for r in mutant["$defs"]["ReconcileTallies"]["required"] if r != "unresolved"
        ]
        _mutant_check(
            "neg-reconcile-tallies-missing-state",
            mutant,
            "ReconcileTallies.required's 'unresolved' entry",
        )

    if negative_errors_by_name["neg-unrecognized-claim-type"]:
        mutant = copy.deepcopy(schema)
        # Open the closed-world ClaimType enum to any string. The fixture's
        # claim carries no reconcile/close body, so the type<->body binding's
        # else-branch still passes -- the enum is the ONLY rule rejecting it.
        mutant["$defs"]["ClaimType"] = {"type": "string"}
        _mutant_check(
            "neg-unrecognized-claim-type",
            mutant,
            "ClaimType's closed enum",
        )

    if negative_errors_by_name["neg-close-contested-verdict-met"]:
        mutant = copy.deepcopy(schema)
        # Strip only the CONTESTED-is-never-met rule (the third Claim.allOf
        # entry, the one whose description names CONTESTED); the
        # sufficiency/verdict binding and the type<->body binding stay. The
        # fixture's bucket still lists close-1 under not_met, which the
        # schema never cross-checks, so this rule is the ONLY one rejecting
        # it.
        mutant["$defs"]["Claim"]["allOf"] = [
            rule for rule in mutant["$defs"]["Claim"]["allOf"]
            if "CONTESTED" not in rule.get("description", "")
        ]
        _mutant_check(
            "neg-close-contested-verdict-met",
            mutant,
            "Claim's CONTESTED-is-never-met if/then rule",
        )

    if negative_errors_by_name["neg-claim-evidence-empty"]:
        mutant = copy.deepcopy(schema)
        # Section 1, Traceability: a claim cites at least one record. Without
        # minItems the story claim citing nothing validates again.
        del mutant["$defs"]["Claim"]["properties"]["evidence"]["minItems"]
        _mutant_check(
            "neg-claim-evidence-empty",
            mutant,
            "Claim.evidence's minItems: 1",
        )

    # --- 8. THE x- EXTENSION SLOT (spec section 8a) ---------------------------
    for level in EXTENSION_LEVELS:
        properties = schema["$defs"][level].get("patternProperties")
        if properties != {EXTENSION_PATTERN: {"$ref": "#/$defs/Extension"}}:
            findings.append(
                f"EXTENSION-SLOT-MISSING {level}: patternProperties is {properties!r}, "
                f"expected exactly {EXTENSION_PATTERN!r} -> Extension"
            )
        if schema["$defs"][level].get("additionalProperties") is not False:
            findings.append(f"EXTENSION-LEVEL-OPEN {level}: additionalProperties is not false")

    for name, levels in EXTENSION_POSITIVES.items():
        instance = _load(name)
        for level in levels:
            mutant_errors = list(_validator_for(_without_slot(schema, (level,))).iter_errors(instance))
            if not mutant_errors:
                findings.append(
                    f"MUTANT-DID-NOT-FLIP {name}: with {level}'s x- slot removed the "
                    "fixture still validates -- it carries no x- member at that level"
                )
            else:
                print(f"OK  MUTANT        {name} -- with {level}'s x- slot removed, the "
                      f"fixture FAILS ({mutant_errors[0].message!r})")

    for name, level in EXTENSION_NEGATIVES.items():
        if not negative_errors_by_name[name]:
            continue
        _mutant_check(name, _slot_open_to_any_name(schema, level), f"{level}'s restriction of the slot to x- names")

    # x- members on every claim of the reconcile positive: still valid, and
    # an x- member inside a claim's typed body (which stays closed) is not.
    reconcile = _load("pos-example-org-reconcile-result")
    for claim in reconcile["claims"]:
        claim["x-note"] = "extension"
    if list(validator.iter_errors(reconcile)):
        findings.append("EXTENSION-REJECTED pos-example-org-reconcile-result: x- members on its claims fail the schema")
    else:
        print("OK  EXTENSION     pos-example-org-reconcile-result.json with x- members on every claim validates")
    for claim in reconcile["claims"]:
        if "reconcile" in claim:
            claim["reconcile"]["x-note"] = "extension"
    if not list(validator.iter_errors(reconcile)):
        findings.append("EXTENSION-TOO-WIDE pos-example-org-reconcile-result: an x- member inside a reconcile body validates")
    else:
        print("OK  EXTENSION     an x- member inside a reconcile body is rejected (the slot is document + claim only)")

    pre_slot = _validator_for(_without_slot(schema))
    pre_slot_fixtures = [
        name
        for name in POSITIVES + NEGATIVES + [link[0] for link in LINK_NEGATIVES]
        if name not in EXTENSION_POSITIVES and name not in EXTENSION_NEGATIVES
    ]
    for name in pre_slot_fixtures:
        instance = _load(name)
        before = not list(pre_slot.iter_errors(instance))
        after = not list(validator.iter_errors(instance))
        if before != after:
            findings.append(
                f"NOT-ADDITIVE {name}: {'valid' if before else 'rejected'} without the x- slot, "
                f"{'valid' if after else 'rejected'} with it"
            )
    print(f"OK  ADDITIVE      {len(pre_slot_fixtures)} pre-slot fixture(s) get the same verdict "
          "with and without the x- slot")

    stripped = json.dumps(_strip_extensions(_load("pos-example-org-extended-result")), indent=2, sort_keys=True) + "\n"
    if stripped.encode("utf-8") != (VECTORS_DIR / f"{POSITIVE_RESULT}.json").read_bytes():
        findings.append(
            "EXTENSION-NOT-ISOLATED pos-example-org-extended-result: with its x- members "
            f"stripped it is not {POSITIVE_RESULT}.json"
        )
    else:
        print(f"OK  IGNORED       pos-example-org-extended-result.json minus its x- members "
              f"== {POSITIVE_RESULT}.json")
    # --- PROPOSED coverage_report (spec section 7.1) -------------------------

    if negative_errors_by_name["neg-coverage-satisfied-with-gap"]:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["RequirementCoverage"]["allOf"] = []
        _mutant_check(
            "neg-coverage-satisfied-with-gap",
            mutant,
            "RequirementCoverage's status if/then rules",
        )

    if negative_errors_by_name["neg-coverage-not-found-source-with-records"]:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["SourceCoverage"]["allOf"] = []
        _mutant_check(
            "neg-coverage-not-found-source-with-records",
            mutant,
            "SourceCoverage's NOT_FOUND-exactly-when-empty rule",
        )

    if negative_errors_by_name["neg-coverage-gap-remedy-absent"]:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["CoverageGap"]["required"] = [
            r for r in mutant["$defs"]["CoverageGap"]["required"] if r != "remedy"
        ]
        _mutant_check(
            "neg-coverage-gap-remedy-absent",
            mutant,
            "CoverageGap.required's 'remedy' entry",
        )

    if negative_errors_by_name["neg-coverage-uppercase-epistemic-type"]:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["EpistemicType"] = {"type": "string"}
        _mutant_check(
            "neg-coverage-uppercase-epistemic-type",
            mutant,
            "EpistemicType's closed (lower-case) enum",
        )

    if negative_errors_by_name["neg-coverage-unknown-epistemic-type"]:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["EpistemicType"] = {"type": "string"}
        _mutant_check(
            "neg-coverage-unknown-epistemic-type",
            mutant,
            "EpistemicType's closed enum",
        )

    # PROPOSED aggregate.coverage_declaration (spec section 7.2): the kind is
    # a closed enum, and the member is additive -- removing it from its
    # positive gives the claims positive byte for byte.
    # --- Spec sections 4.2 and 1: the fourth verdict -----------------------
    def _without_claim_rule(marker: str) -> dict:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["Claim"]["allOf"] = [
            rule for rule in mutant["$defs"]["Claim"]["allOf"]
            if marker not in json.dumps(rule)
        ]
        return mutant

    out_of_scope_rule = "an out_of_scope claim's requirement allows it"
    pairing_rule = '"const": "SATISFIED"'
    for name, mutant_schema, label in (
        ("neg-out-of-scope-without-switch", _without_claim_rule(out_of_scope_rule),
         "Claim's out_of_scope if/then rule"),
        ("neg-out-of-scope-not-applicable-carrier", _without_claim_rule(out_of_scope_rule),
         "Claim's out_of_scope if/then rule"),
        ("neg-out-of-scope-on-reconcile-claim", _without_claim_rule(out_of_scope_rule),
         "Claim's out_of_scope if/then rule"),
        ("neg-out-of-scope-with-gap", _without_claim_rule(pairing_rule),
         "Claim's sufficiency/verdict if/then rule"),
        ("neg-satisfied-not-evaluable", _without_claim_rule(pairing_rule),
         "Claim's sufficiency/verdict if/then rule"),
    ):
        if negative_errors_by_name[name]:
            _mutant_check(name, mutant_schema, label)
    bucket_mutant = copy.deepcopy(schema)
    bucket_mutant["$defs"]["EvidenceResult"]["allOf"] = []
    for name in ("neg-out-of-scope-bucket-absent", "neg-out-of-scope-bucket-without-switch"):
        if negative_errors_by_name[name]:
            _mutant_check(name, bucket_mutant, "EvidenceResult's out_of_scope bucket rule")
    # A not_applicable token is refused twice over: by the closed Verdict enum
    # and by the pairing rule, so the mutant opens both.
    if negative_errors_by_name["neg-not-applicable-verdict"]:
        mutant = _without_claim_rule(pairing_rule)
        mutant["$defs"]["Verdict"] = {"type": "string"}
        _mutant_check("neg-not-applicable-verdict", mutant, "the closed Verdict enum and the pairing rule")

    if negative_errors_by_name["neg-coverage-declaration-unknown-kind"]:
        mutant = copy.deepcopy(schema)
        mutant["$defs"]["CoverageKind"] = {"type": "string"}
        _mutant_check(
            "neg-coverage-declaration-unknown-kind",
            mutant,
            "CoverageKind's closed enum",
        )
    declared = _load("pos-example-org-coverage-declaration-result")
    del declared["aggregate"]["coverage_declaration"]
    if json.dumps(declared, indent=2, sort_keys=True) + "\n" != (VECTORS_DIR / f"{POSITIVE_RESULT}.json").read_text(encoding="utf-8"):
        findings.append(
            "COVERAGE-DECLARATION-NOT-ISOLATED pos-example-org-coverage-declaration-result: with "
            f"aggregate.coverage_declaration removed it is not {POSITIVE_RESULT}.json"
        )
    else:
        print("OK  ADDITIVE      pos-example-org-coverage-declaration-result.json minus "
              f"aggregate.coverage_declaration == {POSITIVE_RESULT}.json")

    # EpistemicType is the record header's set exactly as the vendored copy
    # lists it: same tokens, same (lower) case, same order.
    vendored = json.loads((SCHEMAS_DIR / "vendor" / "epistemic-types.json").read_text(encoding="utf-8"))
    if schema["$defs"]["EpistemicType"]["enum"] != vendored["values"]:
        findings.append("EPISTEMIC-TYPE-DRIFT: $defs.EpistemicType differs from schemas/vendor/epistemic-types.json")
    else:
        print("OK  PARITY        $defs.EpistemicType matches schemas/vendor/epistemic-types.json")

    # Cross-element coverage rules: every positive passes; each coverage
    # negative passes the schema, fails the check, and its mutant flips it.
    for name in POSITIVES:
        cov = coverage_findings(_load(name))
        if cov:
            findings.extend(f"COVERAGE-MISMATCH {name}: {line}" for line in cov)
        elif "coverage_report" in _load(name):
            print(f"OK  COVERAGE      {name}.json -- cross-element rules hold")

    for name, cov_mutant, mutation_label in COVERAGE_NEGATIVES:
        instance = _load(name)
        schema_errors = list(validator.iter_errors(instance))
        if schema_errors:
            findings.append(
                f"COVERAGE-NEGATIVE-SCHEMA-REJECTED {name}: this fixture exists to show the "
                f"schema ALONE accepts it; it was rejected instead ({schema_errors[0].message!r})"
            )
            continue
        cov = coverage_findings(instance)
        if not cov:
            findings.append(f"COVERAGE-NEGATIVE-DID-NOT-FAIL {name}: the coverage check accepted it")
            continue
        print(f"OK  COVERAGE      {name}.json correctly REJECTED ({cov[0]!r})")
        if coverage_findings(instance, mutant=cov_mutant):
            findings.append(
                f"MUTANT-DID-NOT-FLIP {name}: under the mutant ({mutation_label}) the fixture still failed"
            )
        else:
            print(f"OK  MUTANT        {name} -- under the mutant ({mutation_label}) the fixture "
                  "PASSES (confirms the rule is load-bearing)")

    # Coverage counts evaluations (spec section 3): one per in-force claim,
    # so a requirement evaluated twice counts twice; and spec sections 4.2 and
    # 4.3's bucket, row and applicability rules. Every positive passes; each
    # revision negative passes the schema, fails the check, and its mutant
    # flips it.
    # The date grammar, case by case, as the TypeScript reader's tests pin it
    # (ts/test/result-revision.test.ts).
    for stamp, expected in (
        ("2026-09-22T23:30:00-05:00", "2026-09-23"),
        ("2026-09-22t23:30:00-05:00", "2026-09-23"),
        ("2026-09-22T00:30:00+01:00", "2026-09-21"),
        ("2026-02-30T00:00:00Z", None),
        ("2026-09-22T24:00:00Z", None),
        ("2026-09-22T10:00+00:00", None),
        ("2026-09-22X00:00:00+00:00", None),
        ("2026-09-22T00:00:00+00:00:30", None),
        ("2026-09-22", None),
    ):
        got = _utc_date(stamp)
        if (got.isoformat() if got else None) != expected:
            findings.append(f"DATE-GRAMMAR {stamp!r}: read as {got}, expected {expected}")
    for value, ok in (("0099-01-01", True), ("2024-02-29", True), ("0000-01-01", False), ("2027-02-30", False)):
        if (_calendar_date(value) is not None) != ok:
            findings.append(f"DATE-GRAMMAR {value!r}: calendar date should be {ok}")

    count_findings = len(findings)
    for name in POSITIVES:
        for line in revision_findings(_load(name)):
            findings.append(f"REVISION-RULE {name}: {line}")
    repeated = _load("pos-example-org-repeated-requirement-result")
    rows = {(c["contract_ref"], c["requirement_ref"]) for c in repeated["claims"]}
    # Load-bearing: the same positive counted per requirement (2, not 3) is
    # what the rule refuses.
    if repeated["aggregate"]["coverage"]["evaluated_population"] == len(rows):
        findings.append("COVERAGE-COUNT-NOT-LOAD-BEARING: the repeated-requirement positive "
                        "counts as many requirements as evaluations")
    if len(findings) == count_findings:
        print(f"OK  COUNTS        every positive counts evaluations and passes the bucket, row and "
              f"applicability rules; the repeated-requirement positive has "
              f"{len(repeated['claims'])} evaluations of {len(rows)} requirements")
    for name, rule_mutant, mutation_label in REVISION_NEGATIVES:
        instance = _load(name)
        schema_errors = list(validator.iter_errors(instance))
        if schema_errors:
            findings.append(
                f"REVISION-NEGATIVE-SCHEMA-REJECTED {name}: this fixture exists to show the schema "
                f"ALONE accepts it; it was rejected instead ({schema_errors[0].message!r})"
            )
            continue
        rule = revision_findings(instance)
        if not rule:
            findings.append(f"REVISION-NEGATIVE-DID-NOT-FAIL {name}: the cross-element rules accepted it")
            continue
        print(f"OK  REVISION      {name}.json correctly REJECTED ({rule[0]!r})")
        if revision_findings(instance, mutant=rule_mutant):
            findings.append(
                f"MUTANT-DID-NOT-FLIP {name}: without {mutation_label} the fixture still failed "
                f"({revision_findings(instance, mutant=rule_mutant)[0]!r})"
            )
        else:
            print(f"OK  MUTANT        {name} -- without {mutation_label} the fixture PASSES "
                  "(confirms the rule is load-bearing)")

    # --- 5. CLOSE STATE IS DERIVABLE: the link walk ----------------------------
    #        Schema validation cannot see across records; this can. Every
    #        positive that carries a close claim must ship its records and
    #        pass the recompute; the link negative must pass the schema and
    #        fail the walk, with the walk proven load-bearing by a mutant
    #        that trusts the asserted field.
    for name in POSITIVES:
        instance = _load(name)
        if not any(claim.get("type") == "close" for claim in instance.get("claims", [])):
            continue
        records = _records_for(name)
        if records is None:
            findings.append(
                f"CLOSE-RECORDS-MISSING {name}: carries a close claim but no "
                f"{name}.records.json to recompute its state from"
            )
            continue
        walk = close_state_findings(name, instance, records)
        if walk:
            findings.extend(f"CLOSE-STATE-MISMATCH {line}" for line in walk)
        else:
            states = [
                claim["close"]["close_state"]
                for claim in instance["claims"]
                if claim.get("type") == "close"
            ]
            print(f"OK  LINK-WALK     {name}.json -- close_state {', '.join(states)} recomputed "
                  f"from {len(records)} record(s), matches")
        # Section 8a: the walk ignores x- members. The same document with an
        # x- member on itself and on every claim (one that names a different
        # state) gets the same findings.
        extended = json.loads(json.dumps(instance))
        extended["x-close-state"] = "AGREED"
        for claim in extended["claims"]:
            claim["x-close-state"] = "AGREED"
        extended_errors = list(validator.iter_errors(extended))
        if extended_errors:
            findings.append(
                f"EXTENSION-REJECTED {name}: with x- members on the document and every claim "
                f"it fails the schema ({extended_errors[0].message!r})"
            )
        if close_state_findings(name, extended, records) != walk:
            findings.append(f"EXTENSION-CHANGED-WALK {name}: an x- member changed the link walk's findings")
        else:
            print(f"OK  IGNORED       {name}.json -- x- members leave the link walk unchanged")

    for name, walk_mutant, mutation_label in LINK_NEGATIVES:
        instance = _load(name)
        schema_errors = list(validator.iter_errors(instance))
        if schema_errors:
            findings.append(
                f"LINK-NEGATIVE-SCHEMA-REJECTED {name}: this fixture exists to show the "
                f"schema ALONE accepts it; it was rejected by the schema "
                f"instead ({schema_errors[0].message!r})"
            )
            continue
        print(f"OK  EvidenceResult {name}.json validates against the schema "
              "(the hole: JSON Schema cannot see across records or compare digests)")
        records = _records_for(name)
        if records is None:
            findings.append(f"CLOSE-RECORDS-MISSING {name}: no {name}.records.json")
            continue
        walk = close_state_findings(name, instance, records)
        if not walk:
            findings.append(
                f"LINK-NEGATIVE-DID-NOT-FAIL {name}: the link walk accepted this fixture"
            )
            continue
        print(f"OK  LINK-WALK     {name}.json correctly REJECTED ({walk[0]!r})")
        # MUTANT: the verifier behaviour the rule replaced must accept the
        # same fixture -- otherwise the rejection is not this rule's.
        mutated = close_state_findings(name, instance, records, mutant=walk_mutant)
        if mutated:
            findings.append(
                f"MUTANT-DID-NOT-FLIP {name}: with {mutation_label} removed, the fixture "
                f"still failed ({mutated[0]!r}) -- the rejection is not the rule this "
                "mutation targets"
            )
        else:
            print(f"OK  MUTANT        {name} -- with {mutation_label} removed, the fixture "
                  "PASSES (confirms the walk rule is load-bearing)")
        restored = close_state_findings(name, instance, records)
        if not restored:
            findings.append(f"MUTANT-RESTORE-FAILED {name}: the restored walk accepted the fixture")
        else:
            print(f"OK  MUTANT        {name} -- restored walk re-rejects the same fixture")

    if findings:
        print("\nFAIL — findings:")
        for f in findings:
            print(f"  {f}")
        return 1

    print(f"\nOK — {len(POSITIVES)} positive result(s), {len(NEGATIVES)} negative fixture(s), "
          f"{len(LINK_NEGATIVES)} link-walk negative(s), {len(COVERAGE_NEGATIVES)} coverage "
          f"negative(s), {len(REVISION_NEGATIVES)} revision negative(s), and all mutant checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
