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

  1. POSITIVE: pos-oo-claims-result.json (three claims, one per verdict
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
  4. PROPOSED CLAIM TYPES (Steven's ruling, 2026-09-25 -- "close +
     reconcile as claim types in result v0"): five more positives
     (pos-oo-reconcile-result, pos-oo-close-agreed-result,
     pos-oo-close-unilateral-result, pos-oo-close-unilateral-named-peer-
     result, pos-oo-close-contested-result -- the Evidence Layer's three
     Close states, read from links; UNILATERAL both with and without the
     peer named, since `peer` / `peer_close_ref` are OPTIONAL there, as
     close-v1's unconditional `peer_close` has them) MUST validate, and
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
  5. CLOSE STATE IS DERIVABLE (2026-09-28, after the maintainer's adversarial
     review: "a contested close relabelled 'agreed' validates"). The schema
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
  - Claim `id` uniqueness within a Result, and `aggregate.buckets` entries
    actually naming a claim `id` that exists with the matching `verdict`,
    are, by spec/evidence-result-v0.md section 4's own text, cross-element
    constraints plain JSON Schema cannot express. Nothing in this repository
    enforces them yet; they are a verifier's obligation, not this schema's.
  - The one-directional disclosure gate (disclosure-carrier status is
    restricted; analysis/story are not) is exercised by exactly one negative
    fixture (kind: disclosure under WITHHELD). The converse -- an
    analysis/story carrier used when disclosure would have been legal -- is
    valid by design (spec section 6) and is not a rejection case.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _result_types import EvidenceResultDoc, RecordDoc  # noqa: E402

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
# close-state link walk (check 5). Kept apart from NEGATIVES on purpose: a
# schema rejection here would mean the fixture no longer demonstrates the
# hole it exists to pin.
LINK_NEGATIVES = [
    "neg-close-agreed-relabelled-contested",
]

CLOSE_LINK_TYPES = ("acknowledges", "rebuts")


def _records_for(name: str) -> list[RecordDoc] | None:
    path = VECTORS_DIR / f"{name}.records.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def derive_close_state(records_by_digest: dict[str, RecordDoc], close_digest: str) -> tuple[str, dict[str, set[str]]]:
    """(state, {linking record digest: {link types}}) read from the inbound
    `acknowledges` / `rebuts` links at `close_digest` -- spec section 4.1's
    rule: any `rebuts` => CONTESTED; else any `acknowledges` => AGREED; else
    UNILATERAL. Never reads a state field from any record."""
    linking: dict[str, set[str]] = {}
    for digest, record in records_by_digest.items():
        for link in record.get("links") or []:
            if link.get("target") == close_digest and link.get("type") in CLOSE_LINK_TYPES:
                linking.setdefault(digest, set()).add(link["type"])
    types = set().union(*linking.values()) if linking else set()
    if "rebuts" in types:
        state = "CONTESTED"
    elif "acknowledges" in types:
        state = "AGREED"
    else:
        state = "UNILATERAL"
    return state, linking


def close_state_findings(
    name: str, doc: EvidenceResultDoc, records: list[RecordDoc], trust_asserted: bool = False
) -> list[str]:
    """Findings from recomputing every close claim's state from `records`.
    `trust_asserted=True` is the MUTANT: a verifier that resolves close_ref
    but never walks a link, so it neither recomputes the state nor holds
    peer_close_ref to the link that makes the state -- exactly the
    pre-review verifier. Used only to prove the walk is load-bearing."""
    findings = []
    by_digest = {json_digest(record): record for record in records}
    for index, claim in enumerate(doc.get("claims", [])):
        if claim.get("type") != "close":
            continue
        close = claim.get("close") or {}
        asserted = close.get("close_state")
        close_digest = (close.get("close_ref") or {}).get("digest")
        if close_digest not in by_digest:
            findings.append(
                f"{name}: claims[{index}].close.close_ref names no record in "
                f"{name}.records.json -- the state cannot be recomputed"
            )
            continue
        if trust_asserted:
            # The mutant verifier: it never walks a link, so it has nothing
            # to compare the field against and nothing to hold
            # peer_close_ref to -- both checks below are the walk.
            continue
        derived, linking = derive_close_state(by_digest, close_digest)
        if derived != asserted:
            findings.append(
                f"{name}: claims[{index}].close.close_state is asserted {asserted} but the "
                f"cited Close's inbound links read {derived} "
                f"({', '.join(sorted(t for ts in linking.values() for t in ts)) or 'no acknowledges/rebuts link'})"
            )
            continue
        if derived in ("AGREED", "CONTESTED"):
            peer_digest = (close.get("peer_close_ref") or {}).get("digest")
            wanted = "acknowledges" if derived == "AGREED" else "rebuts"
            if wanted not in linking.get(peer_digest, set()):
                findings.append(
                    f"{name}: claims[{index}].close.peer_close_ref is not the digest of a "
                    f"record carrying the `{wanted}` link that makes this Close {derived}"
                )
    return findings

POSITIVE_RESULT = "pos-oo-claims-result"

# PROPOSED claim types (2026-09-25 ruling): every positive keeps the
# untouched requirement claim-1 beside its typed claims -- one typed claim
# on each close positive, two on the reconcile positive (reconcile-1
# SATISFIED, reconcile-2 GAP).
POSITIVES = [
    POSITIVE_RESULT,
    "pos-oo-reconcile-result",
    "pos-oo-close-agreed-result",
    "pos-oo-close-unilateral-result",
    "pos-oo-close-unilateral-named-peer-result",
    "pos-oo-close-contested-result",
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
]


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

    # --- PROPOSED claim types (2026-09-25 ruling) ---------------------------

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

    for name in LINK_NEGATIVES:
        instance = _load(name)
        schema_errors = list(validator.iter_errors(instance))
        if schema_errors:
            findings.append(
                f"LINK-NEGATIVE-SCHEMA-REJECTED {name}: this fixture exists to show the "
                f"schema ALONE accepts a relabelled close; it was rejected by the schema "
                f"instead ({schema_errors[0].message!r})"
            )
            continue
        print(f"OK  EvidenceResult {name}.json validates against the schema "
              "(the hole: close_state is a producer assertion to JSON Schema)")
        records = _records_for(name)
        if records is None:
            findings.append(f"CLOSE-RECORDS-MISSING {name}: no {name}.records.json")
            continue
        walk = close_state_findings(name, instance, records)
        if not walk:
            findings.append(
                f"LINK-NEGATIVE-DID-NOT-FAIL {name}: the link walk accepted a close whose "
                "asserted state disagrees with its inbound links"
            )
            continue
        print(f"OK  LINK-WALK     {name}.json correctly REJECTED ({walk[0]!r})")
        # MUTANT: a verifier that trusts the field instead of walking links.
        trusting = close_state_findings(name, instance, records, trust_asserted=True)
        if trusting:
            findings.append(
                f"MUTANT-DID-NOT-FLIP {name}: with the link walk trusting the asserted "
                f"close_state, the fixture still failed ({trusting[0]!r}) -- the rejection "
                "is not the derivation rule this mutation targets"
            )
        else:
            print(f"OK  MUTANT        {name} -- with the walk trusting the asserted "
                  "close_state, the fixture PASSES (confirms the walk is load-bearing)")
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
          f"{len(LINK_NEGATIVES)} link-walk negative(s), and all mutant checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
