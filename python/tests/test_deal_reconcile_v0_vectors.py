# SPDX-License-Identifier: BSD-3-Clause
"""The deal reconcile contract vectors (``vectors/deal-reconcile-v0/``).

Every case is run from its inputs alone, by an evaluator written here from
``spec/deal-reconcile-contract-v0.md`` (DR) §4 to §7:

- each half read through its book's half mapping (DR §4.2);
- whether each field opening opens its half (DR §5);
- whether each side's set is complete for the period (DR §6.1);
- the per-pairing state of the deal under each requirement (DR §6);
- the six tallies, sufficiency, verdict and deal state (DR §7);
- the Evidence Result a side-A builder emits (DR §7.1 to §7.4).

All of it is compared with the case's whole ``expected`` block, which the generator states by
hand. Nothing here imports the generator. The test regenerates the corpus twice and requires
both runs to be byte-identical to the committed files. It also runs defective evaluators, each of
which must disagree with at least one case.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from agent_action_capsule.canonical import jcs

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "deal-reconcile-v0"
GENERATOR = ROOT / "python" / "scripts" / "generate_deal_reconcile_v0_vectors.py"
RESULT_SCHEMA = ROOT / "schemas" / "evidence-result-v0.json"
HAND_WRITTEN = ("README.md",)
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
SPEC_TEXT = (ROOT / DATA["spec"]).read_text(encoding="utf-8")

CONTRACT_REF = "ec:deal-reconcile@1"
# DR §3: each requirement names the field it compares.
FIELDS = {"amount-commitment-matched": "amount", "currency-commitment-matched": "currency"}
COMMIT_ALG = "sha256-jcs-nonce256"
STATES = ("matched", "a_only", "b_only", "conflicting", "insufficient", "unresolved")
HEX64 = re.compile(r"[0-9a-f]{64}")
# DR §7.3.
CARRIER_STATUS = {"SATISFIED": "SATISFIED", "UNKNOWN": "UNKNOWN", "GAP": "INSUFFICIENT"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def in_period(t: str, period: dict) -> bool:
    # IP §5.2 times (UTC, Z, seconds) order as strings.
    return period["start"] <= t < period["end"]


@dataclass(frozen=True)
class Rules:
    """Each field is one rule of DR; a defective evaluator replaces one."""
    mapping_applied: bool = True               # §4.2: abstract members are read through the mapping
    opening_checked: bool = True               # §5: an opening must recompute the commitment
    failed_opening_state: str = "UNRESOLVED"   # §6 rule 4
    completeness_checked: bool = True          # §6 rule 2: A_ONLY / B_ONLY only over a complete set
    holder_selected_complete: bool = False     # §6.1: holder_selected never makes a set complete
    coverage_properties_checked: bool = True   # §6.1: every property PASS for COMPLETE
    undecided_state: str = "UNRESOLVED"        # §6 rule 2: NOT_CHECKED / INCONCLUSIVE
    empty_text_state: str = "INSUFFICIENT"     # §6 rule 5
    unresolved_is_gap: bool = False            # §7.2: unresolved > 0 => UNKNOWN, not GAP
    reconciled_needs_both: bool = True         # §7.5
    result_carries_openings: bool = False      # §7.3
    result_cites_close: bool = False           # §7.4


SPEC = Rules()


def pointer(doc: object, ptr: str) -> object:
    """RFC 6901; None when the pointer resolves to nothing."""
    if ptr == "":
        return doc
    for token in ptr.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(doc, dict) and token in doc:
            doc = doc[token]
        elif isinstance(doc, list) and token.isdigit() and int(token) < len(doc):
            doc = doc[int(token)]
        else:
            return None
    return doc


def read_half(record: dict, mapping: dict, rules: Rules) -> dict:
    """DR §4.2: the abstract members of §4.1, an absent one left out."""
    if not rules.mapping_applied:
        return record
    values = {member: pointer(record, ptr) for member, ptr in mapping["members"].items()}
    return {member: v for member, v in values.items() if v is not None}


def completeness(coverage: dict | None, period: dict, rules: Rules) -> str:
    """DR §6.1: COMPLETE, UNDECIDED or NOT_SHOWN."""
    if coverage is None or coverage["period"] != period:
        return "NOT_SHOWN"
    declaration, props = coverage["declaration"], coverage["properties"]
    kind = declaration["kind"]
    if kind == "holder_selected":
        return "COMPLETE" if rules.holder_selected_complete else "NOT_SHOWN"
    if kind not in ("stream_interval", "source_authoritative") or (
            kind == "stream_interval" and declaration.get("rule") != "all_records"):
        return "NOT_SHOWN"
    if not rules.coverage_properties_checked:
        return "COMPLETE"
    statuses = set(props.values())
    if not statuses or statuses & {"FAIL", "NOT_PRESENT"}:
        return "NOT_SHOWN"
    return "COMPLETE" if statuses == {"PASS"} else "UNDECIDED"


def one_side(status: str, found: str, rules: Rules) -> str:
    """DR §6 rule 2, given the absent side's DR §6.1 status."""
    if status == "COMPLETE" or not rules.completeness_checked:
        return found
    return rules.undecided_state if status == "UNDECIDED" else "INSUFFICIENT"


def opens(half: dict, field: str, o: dict | None, rules: Rules) -> str:
    """DR §5: PASS when the opening recomputes the half's field commitment, FAIL when it does not,
    NOT_PRESENT when none is carried."""
    if o is None:
        return "NOT_PRESENT"
    if not rules.opening_checked:
        return "PASS"
    committed = half.get(f"{field}_commitment")
    ok = half.get("commit_alg") == COMMIT_ALG and committed == sha(jcs({"nonce": o["nonce"], "text": o["text"]}))
    return "PASS" if ok else "FAIL"


def pairing(a: list[dict], b: list[dict], field: str, openings: dict, set_status: dict[str, str],
            rules: Rules) -> str:
    """DR §6: the first rule that applies. ``set_status`` is keyed by side, "a" and "b"."""
    if len(a) > 1 or len(b) > 1:
        return "UNRESOLVED"
    if not b:
        return one_side(set_status["b"], "A_ONLY", rules)
    if not a:
        return one_side(set_status["a"], "B_ONLY", rules)
    (ha, da), (hb, db) = a[0], b[0]
    oa, ob = openings.get(da, {}).get(field), openings.get(db, {}).get(field)
    for h, o in ((ha, oa), (hb, ob)):
        if h.get("commit_alg") != COMMIT_ALG or f"{field}_commitment" not in h or o is None:
            return "INSUFFICIENT"
    if "FAIL" in (opens(ha, field, oa, rules), opens(hb, field, ob, rules)):
        return rules.failed_opening_state
    if "" in (oa["text"], ob["text"]):
        return rules.empty_text_state
    return "MATCHED" if oa["text"] == ob["text"] else "CONFLICTING"


def sufficiency(t: dict, rules: Rules) -> str:
    if t["insufficient"] or (rules.unresolved_is_gap and t["unresolved"]):
        return "GAP"
    return "UNKNOWN" if t["unresolved"] else "SATISFIED"


def verdict(t: dict, rules: Rules) -> str:
    if sufficiency(t, rules) != "SATISFIED":
        return "not_evaluable"
    return "met" if t["matched"] and not (t["a_only"] or t["b_only"] or t["conflicting"]) else "not_met"


def evaluate(case: dict, rules: Rules = SPEC) -> dict:
    inp = case["inputs"]
    sides = (inp["side_a"], inp["peer"])
    halves = []
    for h in inp["halves"]:
        raw = h["octets_text"].encode("utf-8")
        record = json.loads(raw)
        # Every case holds halves of its own two books; the book picks the mapping.
        book = next(b for b in sides if read_half(record, inp["half_mappings"][b], SPEC).get("book_id") == b)
        halves.append((read_half(record, inp["half_mappings"][book], rules), sha(raw)))
    halves = [(h, d) for h, d in halves
              if in_period(h.get("recorded_at", ""), inp["period"]) and h.get("book_id") in sides]
    openings = inp["field_openings"]
    deals = sorted({h["deal_id"] for h, _ in halves})
    set_completeness = {book: completeness(inp["coverage"].get(book), inp["period"], rules) for book in sides}
    by_side = {"a": set_completeness[inp["side_a"]], "b": set_completeness[inp["peer"]]}

    opened = {d: {f: opens(h, f, openings.get(d, {}).get(f), rules) for f in FIELDS.values()
                  if f in openings.get(d, {})} for h, d in halves}
    pairings, tallies = {}, {}
    for requirement, field in FIELDS.items():
        pairings[requirement] = {}
        for deal in deals:
            a = [(h, d) for h, d in halves if h["deal_id"] == deal and h["book_id"] == inp["side_a"]]
            b = [(h, d) for h, d in halves if h["deal_id"] == deal and h["book_id"] == inp["peer"]]
            pairings[requirement][deal] = pairing(a, b, field, openings, by_side, rules)
        tallies[requirement] = {s: sum(1 for v in pairings[requirement].values() if v.lower() == s) for s in STATES}
    suff = {r: sufficiency(t, rules) for r, t in tallies.items()}
    verd = {r: verdict(t, rules) for r, t in tallies.items()}
    deal_state = {}
    for deal in deals:
        states = [pairings[r][deal] for r in FIELDS]
        ok = all(s == "MATCHED" for s in states) if rules.reconciled_needs_both else "MATCHED" in states
        deal_state[deal] = "reconciled" if ok else "not_reconciled"

    # DR §7.1 to §7.4: the Result.
    refs = [{"digest": d, "digest_alg": "SHA-256"} for d in sorted(d for _, d in halves)]
    claims, buckets = [], {"met": [], "not_met": [], "not_evaluable": []}
    for requirement, field in FIELDS.items():
        claim_id = f"reconcile-{field}"
        claim = {"id": claim_id, "type": "reconcile", "contract_ref": CONTRACT_REF, "requirement_ref": requirement,
                 "tier": "recomputed", "grade": "self-attested", "sufficiency": suff[requirement],
                 "verdict": verd[requirement], "evidence": refs, "proofs": [],
                 "presentation": {"kind": "disclosure", "status": CARRIER_STATUS[suff[requirement]],
                                  "evidence": refs},
                 "reconcile": {"join_key": "deal_id", "peer": inp["peer"], "period": inp["period"],
                               "tallies": tallies[requirement], "state_of_record": "none"}}
        if rules.result_carries_openings:
            claim["x-field-openings"] = openings
        if rules.result_cites_close:
            claim["evidence"] = refs + [{"digest": sha(b"a Close"), "digest_alg": "SHA-256"}]
        claims.append(claim)
        buckets[verd[requirement]].append(claim_id)
    result = {"result_version": "evidence-result-v0",
              "generated_at": case["expected"]["result"]["generated_at"], "claims": claims,
              "aggregate": {"coverage": {"evaluated_population": len(claims), "excluded_not_applicable": 0,
                                         "unknown_count": sum(1 for v in suff.values() if v == "UNKNOWN")},
                            "buckets": buckets}}
    return {"field_openings": opened, "set_completeness": set_completeness, "pairings": pairings,
            "tallies": tallies, "sufficiency": suff,
            "verdict": verd, "deal_state": deal_state, "cites_close": rules.result_cites_close, "result": result}


# ---------------------------------------------------------------------------
# The corpus
# ---------------------------------------------------------------------------


def test_corpus_shape_and_contract():
    assert DATA["set"] == "aac-deal-reconcile-v0" and DATA["count"] == len(CASES) == 8
    c = DATA["contract"]
    assert c["document_jcs"].encode() == jcs(c["document"])
    assert c["contract_digest"] == sha(c["document_jcs"].encode())
    assert c["contract_ref"] == CONTRACT_REF == f"{c['document']['id']}@{c['document']['version']}"
    assert [r["id"] for r in c["document"]["requirements"]] == list(FIELDS)
    assert HEX64.fullmatch(c["schema"]["sha256"]) and c["schema"]["name"] == "evidence-contract-v0.json"


def test_spec_states_the_corpus_contract():
    """DR §3's JSON block is the contract document the corpus carries."""
    section = SPEC_TEXT.split("## 3. The contract document", 1)[1].split("\n## 4.", 1)[0]
    block = section.split("```json\n", 1)[1].split("```", 1)[0]
    assert json.loads(block) == DATA["contract"]["document"]


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(case):
    assert evaluate(case) == case["expected"]


def test_required_cases_are_present():
    by_id = {c["id"]: c["expected"] for c in CASES}
    matched = by_id["pair-matched"]
    assert all(p == {"deal-1": "MATCHED"} for p in matched["pairings"].values())
    assert matched["deal_state"] == {"deal-1": "reconciled"}
    failed = by_id["amount-opening-fails"]
    assert failed["pairings"]["amount-commitment-matched"] == {"deal-1": "UNRESOLVED"}
    assert failed["deal_state"] == {"deal-1": "not_reconciled"}
    assert "FAIL" in [s for o in failed["field_openings"].values() for s in o.values()]
    empty = by_id["currency-texts-empty"]
    assert empty["pairings"]["currency-commitment-matched"] == {"deal-1": "INSUFFICIENT"}
    complete_peer = by_id["a-only-peer-complete"]
    assert all(p == {"deal-1": "A_ONLY"} for p in complete_peer["pairings"].values())
    assert complete_peer["set_completeness"]["book-b"] == "COMPLETE"
    undecided = by_id["a-only-peer-commitment-not-checked"]
    assert all(p == {"deal-1": "UNRESOLVED"} for p in undecided["pairings"].values())
    assert undecided["set_completeness"]["book-b"] == "UNDECIDED"
    for case_id in ("a-only-peer-not-declared", "a-only-peer-holder-selected", "a-only-peer-coverage-fails"):
        assert all(p == {"deal-1": "INSUFFICIENT"} for p in by_id[case_id]["pairings"].values()), case_id
        assert by_id[case_id]["set_completeness"]["book-b"] == "NOT_SHOWN", case_id


def test_spec_states_the_example_mapping():
    """DR §4.2's JSON block is the mapping every case reads its halves through."""
    section = SPEC_TEXT.split("### 4.2 Half mapping", 1)[1].split("\n## 5.", 1)[0]
    block = section.split("```json\n", 1)[1].split("```", 1)[0]
    assert json.loads(block) == DATA["half_mapping_example"]
    for case in CASES:
        assert all(m == DATA["half_mapping_example"] for m in case["inputs"]["half_mappings"].values())
        for h in case["inputs"]["halves"]:
            record = json.loads(h["octets_text"])
            assert not set(record) & set(DATA["half_mapping_example"]["members"]) - {"recorded_at"}, case["id"]


def test_every_case_carries_six_tallies_per_requirement():
    for case in CASES:
        for requirement, t in case["expected"]["tallies"].items():
            assert requirement in FIELDS and set(t) == set(STATES), case["id"]
            assert all(isinstance(v, int) and v >= 0 for v in t.values()), case["id"]


def test_result_carries_digests_only_and_no_close():
    """DR §7.3, §7.4: no field opening, no field text, no Close member."""
    for case in CASES:
        text = json.dumps(case["expected"]["result"])
        for per_half in case["inputs"]["field_openings"].values():
            for o in per_half.values():
                assert o["nonce"] not in text and json.dumps(o["text"]) not in text, case["id"]
        for claim in case["expected"]["result"]["claims"]:
            assert "close" not in claim and claim["contract_ref"] == CONTRACT_REF
            assert {e["digest"] for e in claim["evidence"]} == {h["digest"] for h in case["inputs"]["halves"]}
        assert case["expected"]["cites_close"] is False


def test_halves_digest_their_octets():
    for case in CASES:
        for h in case["inputs"]["halves"]:
            assert sha(h["octets_text"].encode()) == h["digest"], case["id"]


def test_spec_lists_every_case():
    section = SPEC_TEXT.split("## 8. Vectors", 1)[1].split("\n## 9.", 1)[0]
    for case in CASES:
        assert f"`{case['id']}`" in section, case["id"]


def test_result_validates_against_the_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(RESULT_SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator({**schema, "$ref": "#/$defs/EvidenceResult"})
    for case in CASES:
        assert not list(validator.iter_errors(case["expected"]["result"])), case["id"]


# ---------------------------------------------------------------------------
# Negative checks: each defective evaluator must disagree with some case
# ---------------------------------------------------------------------------

DEFECTS = {
    "the half mapping is not applied": replace(SPEC, mapping_applied=False),
    "a one-sided pair is A_ONLY without a complete set": replace(SPEC, completeness_checked=False),
    "holder_selected makes a set complete": replace(SPEC, holder_selected_complete=True),
    "coverage properties are not checked": replace(SPEC, coverage_properties_checked=False),
    "an undecided set gives INSUFFICIENT": replace(SPEC, undecided_state="INSUFFICIENT"),
    "an undecided set gives A_ONLY": replace(SPEC, undecided_state="A_ONLY"),
    "two empty texts are MATCHED": replace(SPEC, empty_text_state="MATCHED"),
    "an empty text is UNRESOLVED": replace(SPEC, empty_text_state="UNRESOLVED"),
    "openings not checked": replace(SPEC, opening_checked=False),
    "a failed opening is CONFLICTING": replace(SPEC, failed_opening_state="CONFLICTING"),
    "a failed opening is MATCHED": replace(SPEC, failed_opening_state="MATCHED"),
    "a failed opening is INSUFFICIENT": replace(SPEC, failed_opening_state="INSUFFICIENT"),
    "unresolved gives GAP": replace(SPEC, unresolved_is_gap=True),
    "one matched field reconciles the deal": replace(SPEC, reconciled_needs_both=False),
    "the Result carries the openings": replace(SPEC, result_carries_openings=True),
    "the Result cites a Close": replace(SPEC, result_cites_close=True),
}


@pytest.mark.parametrize("name", list(DEFECTS))
def test_every_defective_evaluator_is_caught(name):
    rules = DEFECTS[name]
    assert any(evaluate(c, rules) != c["expected"] for c in CASES), name


# ---------------------------------------------------------------------------
# Reproducibility and registration
# ---------------------------------------------------------------------------


def _generate(out: Path) -> None:
    for name in HAND_WRITTEN:
        shutil.copyfile(VECTORS / name, out / name)
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(out)], check=True)


def _files(d: Path) -> list[str]:
    return sorted(p.relative_to(d).as_posix() for p in d.rglob("*") if p.is_file() and "__pycache__" not in p.parts)


def test_generator_is_deterministic_and_reproduces_every_file(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _generate(a)
    _generate(b)
    committed = _files(VECTORS)
    assert committed == _files(a) == _files(b)
    for name in committed:
        assert (a / name).read_bytes() == (b / name).read_bytes() == (VECTORS / name).read_bytes(), name


def test_sha256sums_and_registration():
    listed = dict(reversed(line.split("  ", 1)) for line in (VECTORS / "SHA256SUMS").read_text().splitlines())
    assert set(listed) == set(_files(VECTORS)) - {"SHA256SUMS"}
    for name, digest in listed.items():
        assert sha((VECTORS / name).read_bytes()) == digest, name
    top = dict(reversed(line.split("  ", 1)) for line in (ROOT / "vectors" / "SHA256SUMS").read_text().splitlines())
    for name in set(_files(VECTORS)) - {"SHA256SUMS"}:
        assert top[f"deal-reconcile-v0/{name}"] == sha((VECTORS / name).read_bytes()), name
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text())["corpora"]
    assert corpora["deal_reconcile_v0"] == "deal-reconcile-v0/manifest.json"
    assert "generate_deal_reconcile_v0_vectors.py" in (
        ROOT / "python" / "scripts" / "generate_all_vectors.py").read_text()


def test_does_not_import_the_generator():
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    modules = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    modules += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in modules if m.startswith("generate_")]

