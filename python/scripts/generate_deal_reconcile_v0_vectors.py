#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the deal reconcile contract vectors (``spec/deal-reconcile-contract-v0.md``, cited as DR).

Each case is one deal with a half in one or both of two books, every field committed with
``sha256-jcs-nonce256``, read through the example half mapping (DR §4.2). DR §8 lists the cases and
what each shows.

It states every per-pairing state by hand from DR §6 and derives from them the six tallies,
sufficiency and verdict of DR §7, and the expected Evidence Result. Each case cites the sections
it comes from. The coverage properties of a declaration are given as a verifier reports
them under IP §6.7.3; computing them is IP's, and its vectors check that. Nothing here imports or
runs a verifier.

Output: ``vectors/deal-reconcile-v0/`` (or ``--out DIR``). Deterministic: no clock, no randomness;
each nonce is a label digest, never a nonce to use. ``README.md`` is never rewritten; every file in
the directory is listed in ``SHA256SUMS``. Dependencies: the standard library and the interop
profile generator beside this script, for its encodings and its Evidence Contract schema pin.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from generate_interop_profile_v0_vectors import EC_SCHEMA, jcs, json_digest, shx

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "deal-reconcile-v0"
SET = "aac-deal-reconcile-v0"
SPEC = "spec/deal-reconcile-contract-v0.md"
STATUS = ("Conformance vectors for the informational Deal Reconcile Contract v0 "
          "(spec/deal-reconcile-contract-v0.md), cited by a type: reconcile claim of Evidence Result v0. "
          "Every nonce is a label digest for these vectors only; never use one as a nonce.")
J = "application/json"

# DR §3.
CONTRACT = {
    "id": "ec:deal-reconcile",
    "version": "1",
    "requirements": [
        {"id": "amount-commitment-matched", "profile": "outcome",
         "statement": "Both halves of the deal commit to the same amount, and each amount commitment opens "
                      "to the text compared.",
         "evidence_requirements": {"accepted_epistemic_types": ["producer_claim"]}},
        {"id": "currency-commitment-matched", "profile": "outcome",
         "statement": "Both halves of the deal commit to the same currency, and each currency commitment opens "
                      "to the text compared.",
         "evidence_requirements": {"accepted_epistemic_types": ["producer_claim"]}},
    ],
}
CONTRACT_REF = f"{CONTRACT['id']}@{CONTRACT['version']}"
CONTRACT_DIGEST = json_digest(CONTRACT)
FIELDS = {"amount-commitment-matched": "amount", "currency-commitment-matched": "currency"}

COMMIT_ALG = "sha256-jcs-nonce256"
STATES = ("matched", "a_only", "b_only", "conflicting", "insufficient", "unresolved")
BOOK_A, BOOK_B = "book-a", "book-b"
DEAL = "deal-1"
PERIOD = {"start": "2026-10-01T00:00:00Z", "end": "2026-11-01T00:00:00Z"}
RECORDED = {BOOK_A: "2026-10-15T00:00:00Z", BOOK_B: "2026-10-15T00:00:01Z"}
GENERATED_AT = "2026-10-19T00:00:00Z"
# Placeholder terms; XTS is the code reserved for testing.
TERMS = {"amount": "100.00", "currency": "XTS"}


# DR §4.2: the example half mapping. Its half layout and profile name are for these vectors only.
MAPPING = {
    "profile": "example-half/0",
    "members": {"deal_id": "/deal_ref", "book_id": "/book", "recorded_at": "/recorded_at",
                "commit_alg": "/terms/alg", "amount_commitment": "/terms/amount",
                "currency_commitment": "/terms/currency"},
}


def label(text: str) -> str:
    return shx(f"deal-reconcile-v0 vectors: {text}".encode())


def opening(book: str, field: str, text: str) -> dict:
    return {"nonce": label(f"{field} nonce of {book}'s half of {DEAL}"), "text": text}


def commitment(o: dict) -> str:
    """DR §4, as PO §7 and PC §7.2: SHA-256 of JCS of {nonce, text}."""
    return json_digest({"nonce": o["nonce"], "text": o["text"]})


def half(book: str, terms: dict[str, str] = TERMS) -> tuple[dict, dict]:
    """One book's half in the example layout (DR §4.2) and its field openings (DR §5), as committed."""
    openings = {field: opening(book, field, text) for field, text in terms.items()}
    record = {"deal_ref": DEAL, "book": book, "recorded_at": RECORDED[book],
              "terms": {"alg": COMMIT_ALG, "amount": commitment(openings["amount"]),
                        "currency": commitment(openings["currency"])}}
    return record, openings


# DR §6.1: a book's coverage, as given, with its IP §6.7.2 properties as a verifier reports them.
def stream(book: str) -> dict:
    return {"kind": "stream_interval", "rule": "all_records",
            "interval": {"from": None, "to": label(f"anchor of {book}'s stream")},
            "live_set": [{"stream": book, "checkpoint": label(f"checkpoint of {book}'s stream"),
                          "start": 0, "count": 0}]}


def source(book: str) -> dict:
    return {"kind": "source_authoritative", "source": label(f"key of the source listing {book}'s halves"),
            "method": "an example native check (vectors only)",
            "population": label(f"the source's list of {book}'s halves")}


STREAM_PROPS = {"coverage_declaration_form": "PASS", "coverage_declaration_anchor": "PASS",
                "coverage_declaration_population": "PASS", "coverage_declaration_commitment": "NOT_CHECKED"}
SOURCE_PROPS = {"coverage_declaration_form": "PASS", "coverage_declaration_population": "PASS",
                "coverage_declaration_source": "PASS"}
# Each kind of coverage the cases give: (declaration, properties, period, DR §6.1 status).
OTHER_PERIOD = {"start": "2026-09-01T00:00:00Z", "end": "2026-10-01T00:00:00Z"}
COVERAGE = {
    "complete": (source, SOURCE_PROPS, PERIOD, "COMPLETE"),
    "undecided": (stream, STREAM_PROPS, PERIOD, "UNDECIDED"),
    "holder_selected": (lambda book: {"kind": "holder_selected"}, {"coverage_declaration_form": "PASS"}, PERIOD,
                        "NOT_SHOWN"),
    "population_fails": (stream, dict(STREAM_PROPS, coverage_declaration_population="FAIL"), PERIOD, "NOT_SHOWN"),
    "source_not_reported": (source, {k: v for k, v in SOURCE_PROPS.items() if k != "coverage_declaration_source"},
                            PERIOD, "NOT_SHOWN"),
    "other_period": (source, SOURCE_PROPS, OTHER_PERIOD, "NOT_SHOWN"),
}


def coverage(key: str, book: str) -> dict:
    declaration, properties, period, _ = COVERAGE[key]
    return {"period": period, "declaration": declaration(book), "properties": properties}


def set_completeness(key: str | None, book: str) -> dict:
    if key is None:
        return {"status": "NOT_SHOWN", "kind": None}
    return {"status": COVERAGE[key][3], "kind": coverage(key, book)["declaration"]["kind"]}


def digest_ref(digest: str) -> dict:
    return {"digest": digest, "digest_alg": "SHA-256"}


def tallies(state: str) -> dict:
    """One deal: the state it is given counts 1, the other five 0 (DR §7.1)."""
    return {s: int(s == state.lower()) for s in STATES}


def sufficiency(t: dict) -> str:
    """RES §4.1, DR §7.2."""
    if t["insufficient"]:
        return "GAP"
    return "UNKNOWN" if t["unresolved"] else "SATISFIED"


def verdict(t: dict) -> str:
    """DR §7.2."""
    if sufficiency(t) != "SATISFIED":
        return "not_evaluable"
    return "met" if t["matched"] and not (t["a_only"] or t["b_only"] or t["conflicting"]) else "not_met"


# DR §7.3: the disclosure carrier's status for each sufficiency.
CARRIER_STATUS = {"SATISFIED": "SATISFIED", "UNKNOWN": "UNKNOWN", "GAP": "INSUFFICIENT"}


def result(states: dict, evidence: list[str]) -> dict:
    """The Evidence Result a side-A builder emits (DR §7): one reconcile claim per requirement, the
    halves by digest only, no field opening and no Close."""
    claims, buckets = [], {"met": [], "not_met": [], "not_evaluable": []}
    for requirement, state in states.items():
        t = tallies(state)
        claim_id = f"reconcile-{FIELDS[requirement]}"
        refs = [digest_ref(d) for d in evidence]
        claims.append({
            "id": claim_id, "type": "reconcile", "contract_ref": CONTRACT_REF, "requirement_ref": requirement,
            "tier": "recomputed", "grade": "self-attested", "sufficiency": sufficiency(t), "verdict": verdict(t),
            "evidence": refs, "proofs": [],
            "presentation": {"kind": "disclosure", "status": CARRIER_STATUS[sufficiency(t)], "evidence": refs},
            "reconcile": {"join_key": "deal_id", "peer": BOOK_B, "period": PERIOD, "tallies": t,
                          "state_of_record": "none"},
        })
        buckets[verdict(t)].append(claim_id)
    unknown = sum(1 for c in claims if c["sufficiency"] == "UNKNOWN")
    return {"result_version": "evidence-result-v0", "generated_at": GENERATED_AT, "claims": claims,
            "aggregate": {"coverage": {"evaluated_population": len(claims), "excluded_not_applicable": 0,
                                       "unknown_count": unknown},
                          "buckets": buckets}}


def case(case_id: str, title: str, *, books: tuple[str, ...] = (BOOK_A, BOOK_B),
         terms: dict[str, str] = TERMS, b_terms: dict[str, str] | None = None, b_openings: dict | None = None,
         covered: dict[str, str] | None = None, states: dict[str, str],
         openings_expected: dict[str, dict[str, str]], sections: list[str]) -> dict:
    covered = covered or {}
    halves, carried = {}, {}
    for book in books:
        record, openings = half(book, b_terms if book == BOOK_B and b_terms else terms)
        if book == BOOK_B and b_openings is not None:
            openings = b_openings
        text = jcs(record)
        digest = shx(text.encode())
        halves[book] = {"book": book, "media_type": J, "octets_text": text, "digest": digest}
        carried[digest] = openings
    evidence = sorted(h["digest"] for h in halves.values())
    reconciled = all(s == "MATCHED" for s in states.values())
    return {
        "id": case_id,
        "title": title,
        "sections": sections,
        "inputs": {
            "contract_ref": CONTRACT_REF,
            "side_a": BOOK_A,
            "peer": BOOK_B,
            "period": PERIOD,
            "half_mappings": {book: MAPPING for book in (BOOK_A, BOOK_B)},
            "halves": [halves[book] for book in books],
            "field_openings": carried,
            "coverage": {book: coverage(key, book) for book, key in sorted(covered.items())},
        },
        "expected": {
            "field_openings": {halves[book]["digest"]: openings_expected[book] for book in books},
            "set_completeness": {book: set_completeness(covered.get(book), book) for book in (BOOK_A, BOOK_B)},
            "pairings": {requirement: {DEAL: state} for requirement, state in states.items()},
            "tallies": {requirement: tallies(state) for requirement, state in states.items()},
            "sufficiency": {requirement: sufficiency(tallies(state)) for requirement, state in states.items()},
            "verdict": {requirement: verdict(tallies(state)) for requirement, state in states.items()},
            "deal_state": {DEAL: "reconciled" if reconciled else "not_reconciled"},
            "cites_close": False,
            "result": result(states, evidence),
        },
    }


OPENS = {"amount": "PASS", "currency": "PASS"}
BOTH = ("amount-commitment-matched", "currency-commitment-matched")


def same(state: str) -> dict[str, str]:
    return dict.fromkeys(BOTH, state)


def cases() -> list[dict]:
    _, b_openings = half(BOOK_B)
    wrong = dict(b_openings, amount=dict(b_openings["amount"], text="90.00"))
    no_amount = {"currency": b_openings["currency"]}
    one_sided = ["DR §6 rule 2", "DR §6.1", "DR §7", "IP §6.7.3", "RES §4.1"]
    return [
        case("pair-matched",
             "Both halves commit to the same amount and currency; every field opening opens",
             states=same("MATCHED"),
             openings_expected={BOOK_A: OPENS, BOOK_B: OPENS},
             sections=["DR §4.2", "DR §5", "DR §6 rule 6", "DR §7", "RES §4.1"]),
        case("amount-conflicting",
             "Each half's amount opening opens, to different texts",
             b_terms=dict(TERMS, amount="90.00"),
             states={BOTH[0]: "CONFLICTING", BOTH[1]: "MATCHED"},
             openings_expected={BOOK_A: OPENS, BOOK_B: OPENS},
             sections=["DR §5", "DR §6 rule 6", "DR §7", "RES §4.1"]),
        case("amount-opening-fails",
             "Side B's amount opening carries other text than its commitment",
             b_openings=wrong,
             states={BOTH[0]: "UNRESOLVED", BOTH[1]: "MATCHED"},
             openings_expected={BOOK_A: OPENS, BOOK_B: dict(OPENS, amount="FAIL")},
             sections=["DR §5", "DR §6 rules 4 and 6", "DR §7", "RES §4.1"]),
        case("amount-opening-missing",
             "No amount opening is carried for side B's half",
             b_openings=no_amount,
             states={BOTH[0]: "INSUFFICIENT", BOTH[1]: "MATCHED"},
             openings_expected={BOOK_A: OPENS, BOOK_B: {"currency": "PASS"}},
             sections=["DR §5", "DR §6 rules 3 and 6", "DR §7", "RES §4.1"]),
        case("currency-texts-empty",
             "Both currency openings open, and both open to empty text",
             terms=dict(TERMS, currency=""),
             states={BOTH[0]: "MATCHED", BOTH[1]: "INSUFFICIENT"},
             openings_expected={BOOK_A: OPENS, BOOK_B: OPENS},
             sections=["DR §5", "DR §6 rules 5 and 6", "DR §7", "RES §4.1"]),
        case("currency-one-text-empty",
             "Both currency openings open; side B's opens to empty text",
             b_terms=dict(TERMS, currency=""),
             states={BOTH[0]: "MATCHED", BOTH[1]: "INSUFFICIENT"},
             openings_expected={BOOK_A: OPENS, BOOK_B: OPENS},
             sections=["DR §5", "DR §6 rules 5 and 6", "DR §7", "RES §4.1"]),
        case("a-only-peer-complete",
             "Side B holds no half, and its source_authoritative coverage passes every property",
             books=(BOOK_A,), covered={BOOK_B: "complete"},
             states=same("A_ONLY"), openings_expected={BOOK_A: OPENS}, sections=one_sided),
        case("b-only-side-a-complete",
             "Side A holds no half, and its source_authoritative coverage passes every property",
             books=(BOOK_B,), covered={BOOK_A: "complete"},
             states=same("B_ONLY"), openings_expected={BOOK_B: OPENS}, sections=one_sided),
        case("a-only-peer-commitment-not-checked",
             "Side B holds no half; its stream_interval coverage passes but for the NOT_CHECKED commitment",
             books=(BOOK_A,), covered={BOOK_B: "undecided"},
             states=same("UNRESOLVED"), openings_expected={BOOK_A: OPENS}, sections=one_sided),
        case("a-only-peer-not-declared",
             "Side B holds no half, and no coverage is given for it",
             books=(BOOK_A,),
             states=same("INSUFFICIENT"), openings_expected={BOOK_A: OPENS}, sections=one_sided),
        case("a-only-peer-holder-selected",
             "Side B holds no half, and its coverage declares holder_selected",
             books=(BOOK_A,), covered={BOOK_B: "holder_selected"},
             states=same("INSUFFICIENT"), openings_expected={BOOK_A: OPENS}, sections=one_sided),
        case("a-only-peer-coverage-fails",
             "Side B holds no half, and its stream_interval coverage fails coverage_declaration_population",
             books=(BOOK_A,), covered={BOOK_B: "population_fails"},
             states=same("INSUFFICIENT"), openings_expected={BOOK_A: OPENS}, sections=one_sided),
        case("a-only-peer-property-not-reported",
             "Side B holds no half; its source_authoritative report leaves out coverage_declaration_source",
             books=(BOOK_A,), covered={BOOK_B: "source_not_reported"},
             states=same("INSUFFICIENT"), openings_expected={BOOK_A: OPENS}, sections=one_sided),
        case("a-only-peer-other-period",
             "Side B holds no half; its complete coverage is given for another period",
             books=(BOOK_A,), covered={BOOK_B: "other_period"},
             states=same("INSUFFICIENT"), openings_expected={BOOK_A: OPENS}, sections=one_sided),
    ]


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    all_cases = cases()
    ids = [c["id"] for c in all_cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    corpus = {
        "set": SET,
        "status": STATUS,
        "spec": SPEC,
        "contract": {"document": CONTRACT, "document_jcs": jcs(CONTRACT), "contract_ref": CONTRACT_REF,
                     "contract_digest": CONTRACT_DIGEST, "schema": EC_SCHEMA},
        "fields": FIELDS,
        "commit_alg": COMMIT_ALG,
        "half_mapping_example": MAPPING,
        "count": len(all_cases),
        "cases": all_cases,
    }
    files = {"vectors.json": _dump(corpus)}
    files["manifest.json"] = _dump({
        "set": SET,
        "status": STATUS,
        "spec": SPEC,
        "generator": "python/scripts/generate_deal_reconcile_v0_vectors.py",
        "files": [{"path": name, "sha256": shx(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    files = sorted((p.relative_to(out).as_posix(), p) for p in out.rglob("*") if p.is_file())
    lines = [f"{shx(p.read_bytes())}  {rel}" for rel, p in files if rel != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    write(args.out)


if __name__ == "__main__":
    main()
