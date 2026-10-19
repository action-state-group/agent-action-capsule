# SPDX-License-Identifier: BSD-3-Clause
"""The coverage declaration vectors of the interop profile (``vectors/coverage-declaration-v0/``).

Every case is run from its inputs alone:

- Each exchange goes through the reference verifier for ``evidence-interop/0``
  (``agent_action_capsule.interop_profile``), and the test applies the History profile's §6.1.
- The History properties of the History profile's §6.2 come from an evaluator written here.
- So do the coverage properties, the report and the aggregate rule of IP §6.7.2, §6.7.3 and
  §6.7.5, and issuer independence (§6.7.4).

All of it is compared with the case's whole ``expected`` block, which the generator states by
hand. Nothing here imports the generator. The test regenerates the corpus twice and requires
both runs to be byte-identical to the committed files. It also runs defective evaluators, each of
which must disagree with at least one case.
"""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from agent_action_capsule.canonical import jcs  # noqa: E402
from agent_action_capsule.interop_profile import (  # noqa: E402
    Exchange,
    InteropVerifier,
    Message,
    TrustPolicy,
    VerificationPolicy,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "coverage-declaration-v0"
GENERATOR = ROOT / "python" / "scripts" / "generate_coverage_declaration_v0_vectors.py"
HAND_WRITTEN = ("README.md",)
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
SET_CASES = [c for c in CASES if "definition" in c["inputs"]]
HALVES_CASES = [c for c in CASES if "halves" in c["inputs"]]
CONTRACT = DATA["contract"]["document"]
SPEC_TEXT = (ROOT / DATA["spec"]).read_text(encoding="utf-8")

# History profile §4.1, §4.3 and §3; IP §6.7.6 for the example definition.
BASIC = "personal_history_basic/1"
EXAMPLE = "coverage_declaration_example/0"
FIXED = {"kind": "projection", "subject_form": "correlation",
         "reads": ["committed_at", "epistemic_type", "event_time_claim", "record_type"]}
MEMBERS = {BASIC: {"name", "kind", "subject_form", "selection", "reads", "completeness", "recipient"},
           EXAMPLE: {"name", "kind", "subject_form", "selection", "reads", "coverage_declaration", "recipient"}}
ARTIFACT_MEMBERS = {"anchor", "derivation", "evidence_stream", "records", "subject"}
RECORD_KINDS = {"step_completed", "step_failed"}
MUST_PASS = ("profile_version", "envelope_signature", "responder_trust", "issued_at_form", "request_binding",
             "subject_binding", "artifact_digest", "anchor_match")

# IP §6.7.1.
DECLARATION_MEMBERS = {"holder_selected": {"kind"}, "stream_interval": {"kind", "rule", "interval", "live_set"},
                       "source_authoritative": {"kind", "source", "method", "population"}}
RULES = {"all_records"}
RELATIVE_TO = {
    "holder_selected": "not asserted",
    "stream_interval": "the live set the holder opened, under the rule and in the interval; "
                       "not checked against the anchor",
    "source_authoritative": "the source's list",
}
HEX64 = re.compile(r"[0-9a-f]{64}")
# The one source method this evaluator implements; any other is NOT_CHECKED (§6.7.2, §7.1).
SOURCE_METHOD = "Ed25519 over UTF-8 of JCS of the population object's other members (IP §6.7.6, vectors only)"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def is_hex64(v: Any) -> bool:
    return isinstance(v, str) and HEX64.fullmatch(v) is not None


def is_count(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def ed25519_ok(key_hex: Any, sig_hex: Any, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(bytes.fromhex(sig_hex), data)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def message(o: dict) -> Message:
    return Message(o["octets_text"].encode("utf-8"), o["media_type"])


def verifier(case: dict) -> InteropVerifier:
    pins = case["pins"]
    return InteropVerifier(TrustPolicy.from_dict(pins["trust_policy"]),
                           VerificationPolicy.from_dict(pins["verification_policy"]), pins["evaluation_time"],
                           contract=CONTRACT)


def render_requirements(reqs: dict) -> dict:
    out = {}
    for q, r in reqs.items():
        entry = {"row": r.row, "status": r.status, "sufficiency": r.sufficiency, "verdict": r.verdict}
        if r.note is not None:
            entry["note"] = r.note
        out[q] = entry
    return out


# ---------------------------------------------------------------------------
# The envelopes and the History properties (History profile §6.1, §6.2)
# ---------------------------------------------------------------------------


def run_exchanges(case: dict) -> list[dict]:
    exchanges = [Exchange(message(x["request"]), [message(x["reply"])]) for x in case["inputs"]["exchanges"]]
    result = verifier(case).verify(exchanges, requirements=["r-deal-steps"])
    out = []
    for ex, x in zip(result.exchanges, case["inputs"]["exchanges"]):
        (r,) = ex.replies
        assert r.message_type == "envelope", r.detail
        props = {p.property: p.status for p in r.properties}
        env = json.loads(x["reply"]["octets_text"])
        accepted = (all(props[k] == "PASS" for k in MUST_PASS) and props["anchor_inclusion"] == "NOT_CHECKED"
                    and "verification" not in env)
        out.append({"message_type": r.message_type, "subject": env["subject"], "properties": props,
                    "accepted": accepted, "requirements": render_requirements(r.requirements),
                    "claim": {"evidence": r.evidence, "proofs": r.proofs},
                    "_env": {**env, "artifact": json.loads(r.artifact)}})
    return out


def definition_form(d: Any) -> bool:
    if not isinstance(d, dict) or d.get("name") not in MEMBERS or set(d) != MEMBERS[d["name"]]:
        return False
    if any(d[k] != v for k, v in FIXED.items()) or (d["name"] == BASIC and d["completeness"] != "not_asserted"):
        return False
    sel, rec = d["selection"], d["recipient"]
    return (isinstance(sel, list) and bool(sel) and all(isinstance(s, str) and s for s in sel)
            and sel == sorted(set(sel)) and isinstance(rec, str) and bool(rec))


def artifact_form(envs: list[dict], reads: set) -> bool:
    for env in envs:
        a = env["artifact"]
        if not isinstance(a, dict) or set(a) != ARTIFACT_MEMBERS or not isinstance(a["evidence_stream"], str) \
                or not a["evidence_stream"]:
            return False
        if a["anchor"] != env["anchor"].get("digest") or a["derivation"] != env.get("derivation") \
                or a["subject"] != env["subject"]:
            return False
        recs = a["records"]
        if not isinstance(recs, list) or not recs or any(
                not isinstance(r, dict) or not {"digest", "leaf_index"} <= set(r) <= {"digest", "leaf_index"} | reads
                for r in recs):
            return False
    return True


def history_properties(definition: dict, envs: list[dict]) -> dict:
    selection = definition.get("selection", [])
    digest = sha(jcs(definition))
    subjects = [e["subject"] for e in envs]
    answered = Counter(s.get("correlation") for s in subjects)
    ok = {
        "definition_form": definition_form(definition),
        "definition_binding": all(e.get("derivation") == digest for e in envs),
        "selection_coverage": all(list(s) == ["correlation"] and s["correlation"] in selection for s in subjects)
        and all(answered[r] == 1 for r in selection),
        "single_signer": len({e["responder"] for e in envs}) == 1,
        "single_anchor": len({jcs(e["anchor"]) for e in envs}) == 1,
        "artifact_form": artifact_form(envs, set(definition.get("reads", []))),
        "record_kinds": all(r.get("record_type") in RECORD_KINDS for e in envs for r in e["artifact"]["records"]),
    }
    return {k: "PASS" if v else "FAIL" for k, v in ok.items()}


# ---------------------------------------------------------------------------
# The coverage declaration (IP §6.7), written here from the profile
# ---------------------------------------------------------------------------


def declaration_of(definition: dict) -> tuple[Any, str]:
    """The declaration and where it came from: the Basic level's completeness is holder_selected
    (History profile §2, PA-15); any other definition carries the member."""
    if definition.get("name") == BASIC:
        ok = definition.get("completeness") == "not_asserted" and "coverage_declaration" not in definition
        return ({"kind": "holder_selected"} if ok else None), "completeness"
    return definition.get("coverage_declaration"), "coverage_declaration"


def form_ok(dec: Any) -> bool:
    if not isinstance(dec, dict) or dec.get("kind") not in DECLARATION_MEMBERS \
            or set(dec) != DECLARATION_MEMBERS[dec["kind"]]:
        return False
    if dec["kind"] == "stream_interval":
        interval, live = dec["interval"], dec["live_set"]
        if dec["rule"] not in RULES or not isinstance(interval, dict) or set(interval) != {"from", "to"} \
                or not is_hex64(interval["to"]) or not (interval["from"] is None or is_hex64(interval["from"])):
            return False
        if not isinstance(live, list) or not live:
            return False
        for e in live:
            if not isinstance(e, dict) or set(e) != {"stream", "checkpoint", "start", "count"} \
                    or not isinstance(e["stream"], str) or not e["stream"] or not is_hex64(e["checkpoint"]) \
                    or not is_count(e["start"]) or not is_count(e["count"]):
                return False
        if interval["from"] is None and any(e["start"] != 0 for e in live):
            return False
        streams = [e["stream"] for e in live]
        return streams == sorted(set(streams))
    if dec["kind"] == "source_authoritative":
        return (is_hex64(dec["source"]) and isinstance(dec["method"], str) and bool(dec["method"])
                and is_hex64(dec["population"]))
    return True


def stream_population(dec: dict, envs: list[dict]) -> bool:
    live = {e["stream"]: e for e in dec["live_set"]}
    if any(e["artifact"]["evidence_stream"] not in live for e in envs):
        return False
    for stream, entry in live.items():
        carried = {r["digest"] for e in envs if e["artifact"]["evidence_stream"] == stream
                   for r in e["artifact"]["records"] if r["leaf_index"] >= entry["start"]}
        if len(carried) != entry["count"]:
            return False
    return True


def population_object(case: dict) -> tuple[bytes | None, Any]:
    pop = case["inputs"].get("population")
    if pop is None:
        return None, None
    octets = pop["octets_text"].encode("utf-8")
    return octets, json.loads(octets)


def source_population(case: dict, envs: list[dict]) -> str:
    octets, obj = population_object(case)
    if octets is None:
        return "NOT_PRESENT"
    items = obj.get("items") if isinstance(obj, dict) else None
    if not isinstance(items, list) or any(obj.get("subject") != e["responder"] for e in envs):
        return "FAIL"
    return "PASS" if sorted(items) == sorted(e["subject"]["correlation"] for e in envs) else "FAIL"


def source_check(case: dict, dec: dict) -> str:
    octets, obj = population_object(case)
    if octets is None:
        return "NOT_PRESENT"
    if dec["method"] != SOURCE_METHOD:
        return "NOT_CHECKED"
    if sha(octets) != dec["population"] or not isinstance(obj, dict) or obj.get("issuer") != dec["source"]:
        return "FAIL"
    body = {k: v for k, v in obj.items() if k != "sig"}
    if not ed25519_ok(dec["source"], obj.get("sig"), jcs(body)):
        return "FAIL"
    return "PASS" if dec["source"] in case["pins"]["trust_policy"]["foreign_keys"] else "FAIL"


def coverage_properties(case: dict, dec: Any, envs: list[dict]) -> dict:
    """IP §6.7.2 over the envelopes the History profile's §6.1 accepted. A property that does not
    apply to the kind is not reported."""
    if not form_ok(dec):
        return {"coverage_declaration_form": "FAIL"}
    props = {"coverage_declaration_form": "PASS"}
    if dec["kind"] == "stream_interval":
        to, frm = dec["interval"]["to"], dec["interval"]["from"]
        props["coverage_declaration_anchor"] = "PASS" if (
            frm != to and all(e["anchor"].get("digest") == to for e in envs)) else "FAIL"
        props["coverage_declaration_population"] = "PASS" if stream_population(dec, envs) else "FAIL"
        props["coverage_declaration_commitment"] = "NOT_CHECKED"
    elif dec["kind"] == "source_authoritative":
        props["coverage_declaration_population"] = source_population(case, envs)
        props["coverage_declaration_source"] = source_check(case, dec)
    return props


def satisfied_becomes(kind: str, props: dict) -> str | None:
    """IP §6.7.3 item 4: what a SATISFIED completeness-dependent requirement becomes."""
    statuses = set(props.values())
    if kind == "holder_selected" or statuses & {"FAIL", "NOT_PRESENT"}:
        return "INSUFFICIENT"
    if statuses & {"NOT_CHECKED", "INCONCLUSIVE"}:
        return "UNKNOWN"
    return None


def aggregate_kind(kind: str, props: dict) -> str:
    """IP §6.7.5 over one set: its declared kind unless a coverage property is FAIL."""
    return "holder_selected" if "FAIL" in props.values() else kind


Evaluator = Callable[[dict, Any, list[dict]], dict]


def run_set(case: dict, evaluate: Evaluator = coverage_properties,
            aggregate_rule: Callable[[str, dict], str] = aggregate_kind) -> dict:
    exchanges = run_exchanges(case)
    envs = [x.pop("_env") for x in exchanges]
    accepted_envs = [e for e, x in zip(envs, exchanges) if x["accepted"]]
    definition = case["inputs"]["definition"]
    hprops = history_properties(definition, accepted_envs)
    dec, by = declaration_of(definition)
    props = evaluate(case, dec, accepted_envs)
    kind = dec["kind"] if isinstance(dec, dict) and "kind" in dec else None
    cov: dict[str, Any] = {"declared_kind": kind, "declared_by": by, "properties": props,
                           "relative_to": RELATIVE_TO.get(kind), "accepted_as_declared": "FAIL" not in props.values(),
                           "satisfied_becomes": {"r-complete": satisfied_becomes(kind, props)}}
    agg = case["inputs"].get("aggregate")
    if agg is not None:
        declared, derived = agg["coverage_declaration"]["kind"], aggregate_rule(kind, props)
        cov["aggregate"] = {"declared": declared, "derived": derived,
                            "coverage_declaration_aggregate": "PASS" if declared == derived else "FAIL"}
    accepted = (all(x["accepted"] for x in exchanges) and all(v == "PASS" for v in hprops.values())
                and cov["accepted_as_declared"]
                and cov.get("aggregate", {}).get("coverage_declaration_aggregate") != "FAIL")
    return {"exchanges": exchanges, "history_properties": hprops, "coverage": cov, "accepted": accepted}


# IP §6.7.4.
INDEPENDENCE = {"FAIL": ("redundant, not corroborating", "INSUFFICIENT"),
                "NOT_CHECKED": ("not corroborating", "UNKNOWN"),
                "PASS": ("corroborating", None)}


def issuer_independence(a: dict, b: dict) -> str:
    """Same key: FAIL. Distinct keys, and nothing examined about their controllers: NOT_CHECKED.
    This revision registers no evidence that gives PASS."""
    return "FAIL" if a["producer"] == b["producer"] else "NOT_CHECKED"


def run_halves(case: dict, independence: Callable[[dict, dict], str] = issuer_independence) -> dict:
    trusted = set(case["pins"]["trust_policy"]["foreign_keys"])
    recs = [json.loads(h["octets_text"]) for h in case["inputs"]["halves"]]
    sigs = ["PASS" if r["producer"] in trusted
            and ed25519_ok(r["producer"], r["sig"], jcs({k: v for k, v in r.items() if k != "sig"})) else "FAIL"
            for r in recs]
    status = independence(*recs)
    shown, becomes = INDEPENDENCE[status]
    return {"signatures": sigs, "agree": recs[0]["claim"] == recs[1]["claim"], "issuer_independence": status,
            "shown_as": shown, "satisfied_becomes": {"r-corroborated": becomes}}


def comparable(expected: dict) -> dict:
    e = copy.deepcopy(expected)
    e.pop("fails")
    return e


def failing(result: dict) -> set:
    cov = result["coverage"]
    return ({p for x in result["exchanges"] for p, s in x["properties"].items() if s == "FAIL"}
            | {p for p, s in result["history_properties"].items() if s == "FAIL"}
            | {p for p, s in cov["properties"].items() if s == "FAIL"}
            | ({"coverage_declaration_aggregate"}
               if cov.get("aggregate", {}).get("coverage_declaration_aggregate") == "FAIL" else set()))


# ---------------------------------------------------------------------------
# The vectors
# ---------------------------------------------------------------------------


def test_corpus_shape_and_pins():
    assert DATA["count"] == len(CASES) == 13
    assert len(SET_CASES) == 11 and len(HALVES_CASES) == 2
    assert sha(DATA["contract"]["document_jcs"].encode()) == DATA["contract"]["contract_digest"]
    assert DATA["contract"]["document_jcs"].encode() == jcs(CONTRACT)
    run = ROOT / "vectors" / DATA["run"]["path"]
    assert sha(run.read_bytes()) == DATA["run"]["sha256"]
    for case in CASES:
        pins = case["pins"]
        assert pins["contract_digest"] == DATA["contract"]["contract_digest"]
        assert pins["verification_policy"] == {"online": False, "profiles_implemented": ["evidence-interop/0"],
                                               "kinds_implemented": ["cll-checkpoint", "cll-inclusion-proof",
                                                                     "cll-consistency-proof"]}
        assert case["source"] == "responder" or case["source"].startswith("derived: ")


def test_one_positive_per_kind():
    """§6.7.6: each kind has a case accepted as declared, with no failing property."""
    positives = {c["expected"]["coverage"]["declared_kind"] for c in SET_CASES if not c["expected"]["fails"]}
    assert positives == set(DECLARATION_MEMBERS)


def test_test_keys_derive_from_their_labels():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    for k in DATA["test_keys"]["keys"].values():
        priv = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(k["seed_label"].encode()).digest())
        assert priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() == k["public"]


def test_responder_cases_carry_the_run_octets_unchanged():
    run = json.loads((ROOT / "vectors" / DATA["run"]["path"]).read_text(encoding="utf-8"))
    carried = {(e["request"]["octets_text"], e["reply"]["octets_text"]) for e in run["exchanges"]}
    for case in SET_CASES:
        if case["source"] == "responder":
            assert all((x["request"]["octets_text"], x["reply"]["octets_text"]) in carried
                       for x in case["inputs"]["exchanges"]), case["id"]
            assert jcs(case["inputs"]["definition"]).decode() == run["definitions"]["basic"], case["id"]


@pytest.mark.parametrize("case", SET_CASES, ids=[c["id"] for c in SET_CASES])
def test_set_case(case):
    assert run_set(case) == comparable(case["expected"])


@pytest.mark.parametrize("case", SET_CASES, ids=[c["id"] for c in SET_CASES])
def test_named_property_fails(case):
    got = run_set(case)
    assert set(case["expected"]["fails"]) <= failing(got)
    assert got["accepted"] is (not case["expected"]["fails"])


@pytest.mark.parametrize("case", HALVES_CASES, ids=[c["id"] for c in HALVES_CASES])
def test_halves_case(case):
    got = run_halves(case)
    assert got == case["expected"]["halves"]
    assert got["signatures"] == ["PASS", "PASS"] and got["agree"]
    assert ({"issuer_independence"} if got["issuer_independence"] == "FAIL" else set()) == set(
        case["expected"]["fails"])


def test_a_valid_signature_never_implies_completeness():
    """§6.7: in every negative set, the evaluator finds every envelope's signature and trust PASS
    and every envelope accepted, and still does not accept the set as its declared kind."""
    negatives = [c for c in SET_CASES if c["expected"]["fails"]]
    assert negatives
    for case in negatives:
        got = run_set(case)
        assert all(x["accepted"] and x["properties"]["envelope_signature"] == "PASS"
                   and x["properties"]["responder_trust"] == "PASS" for x in got["exchanges"]), case["id"]
        assert not got["accepted"], case["id"]


def test_cherry_picked_passes_every_history_property():
    """The cherry-picked History is a well-formed History of the holder's selection: only the
    coverage declaration shows it is not the live set."""
    (case,) = [c for c in CASES if c["id"] == "cherry-picked"]
    assert set(case["expected"]["history_properties"].values()) == {"PASS"}
    assert all(x["accepted"] for x in case["expected"]["exchanges"])
    (positive,) = [c for c in CASES if c["id"] == "stream-interval"]
    pdec, cdec = (c["inputs"]["definition"]["coverage_declaration"] for c in (positive, case))
    assert pdec == cdec
    assert len(case["inputs"]["definition"]["selection"]) == len(pdec["live_set"]) - 1


def test_no_completeness_requirement_is_satisfied_from_stream_interval_in_v0():
    """§6.7.3: a stream_interval set stays UNKNOWN in v0, because the commitment is NOT_CHECKED."""
    for case in SET_CASES:
        becomes = case["expected"]["coverage"]["satisfied_becomes"]["r-complete"]
        kind = case["expected"]["coverage"]["declared_kind"]
        if kind == "stream_interval":
            assert becomes in {"UNKNOWN", "INSUFFICIENT"}, case["id"]
        if kind == "holder_selected":
            assert becomes == "INSUFFICIENT", case["id"]


def test_spec_lists_every_case():
    section = SPEC_TEXT.split("#### 6.7.6", 1)[1].split("\n## ", 1)[0]
    listed = set(re.findall(r"^\| `([a-z0-9-]+)` \|", section, re.M))
    assert listed <= {c["id"] for c in CASES}
    assert {c["id"] for c in CASES} - listed == {
        "source-authoritative-deal-unlisted", "source-authoritative-forged-population",
        "source-authoritative-other-subject",
        "stream-interval-anchor-mismatch", "stream-interval-unknown-rule"}


# ---------------------------------------------------------------------------
# Negative checks: each defective evaluator must disagree with some case
# ---------------------------------------------------------------------------


def _replace(prop: str, check: Callable[[dict, dict, list[dict]], str]) -> Evaluator:
    def evaluate(case: dict, dec: Any, envs: list[dict]) -> dict:
        props = coverage_properties(case, dec, envs)
        if prop in props:
            props[prop] = check(case, dec, envs)
        return props
    return evaluate


def _answered_streams_only(case: dict, dec: dict, envs: list[dict]) -> str:
    live = {e["stream"]: e for e in dec["live_set"]}
    named = {e["artifact"]["evidence_stream"] for e in envs}
    return "PASS" if named <= set(live) else "FAIL"


def _listed_answered(case: dict, dec: dict, envs: list[dict]) -> str:
    """Checks that every listed deal is answered, never that every answered deal is listed."""
    items = set(population_object(case)[1]["items"])
    return "PASS" if items <= {e["subject"]["correlation"] for e in envs} else "FAIL"


def _deals_only(case: dict, dec: dict, envs: list[dict]) -> str:
    """Counts the live set's streams as answered when any envelope names them, never their records."""
    named = {e["artifact"]["evidence_stream"] for e in envs}
    return "PASS" if named == {e["stream"] for e in dec["live_set"]} else "FAIL"


DEFECTIVE: dict[str, Evaluator] = {
    "population trusts the declaration": _replace("coverage_declaration_population", lambda c, d, e: "PASS"),
    "stream population checks answered streams only": _replace(
        "coverage_declaration_population",
        lambda c, d, e: _answered_streams_only(c, d, e) if d["kind"] == "stream_interval"
        else source_population(c, e)),
    "stream population counts streams, not records": _replace(
        "coverage_declaration_population",
        lambda c, d, e: _deals_only(c, d, e) if d["kind"] == "stream_interval" else source_population(c, e)),
    "source population checks listed deals are answered only": _replace(
        "coverage_declaration_population",
        lambda c, d, e: _listed_answered(c, d, e) if d["kind"] == "source_authoritative"
        else ("PASS" if stream_population(d, e) else "FAIL")),
    "source signature not checked": _replace(
        "coverage_declaration_source",
        lambda c, d, e: "PASS" if sha(c["inputs"]["population"]["octets_text"].encode()) == d["population"]
        else "FAIL"),
    "commitment reported PASS": _replace("coverage_declaration_commitment", lambda c, d, e: "PASS"),
    "anchor not checked": _replace("coverage_declaration_anchor", lambda c, d, e: "PASS"),
    "source population ignores the subject": _replace(
        "coverage_declaration_population",
        lambda c, d, e: ("PASS" if sorted(population_object(c)[1]["items"]) == sorted(
            x["subject"]["correlation"] for x in e) else "FAIL") if d["kind"] == "source_authoritative"
        else ("PASS" if stream_population(d, e) else "FAIL")),
}


def _form_any_rule(case: dict, dec: Any, envs: list[dict]) -> dict:
    """Accepts any rule token: the form check of every other member, and then the other properties."""
    if isinstance(dec, dict) and dec.get("kind") == "stream_interval" and isinstance(dec.get("rule"), str):
        dec = dict(dec, rule="all_records")
    return coverage_properties(case, dec, envs)


DEFECTIVE["form accepts any rule"] = _form_any_rule


def test_every_defective_evaluator_is_caught():
    for name, evaluate in DEFECTIVE.items():
        assert any(run_set(c, evaluate) != run_set(c) for c in SET_CASES), name


def test_a_signature_is_not_a_declaration():
    """An evaluator that reads every validly signed History as stream_interval disagrees."""
    def as_stream_interval(case: dict, dec: Any, envs: list[dict]) -> dict:
        return coverage_properties(case, dec, envs) if dec.get("kind") != "holder_selected" else {
            "coverage_declaration_form": "PASS", "coverage_declaration_anchor": "PASS",
            "coverage_declaration_population": "PASS", "coverage_declaration_commitment": "NOT_CHECKED"}
    assert any(run_set(c, as_stream_interval) != run_set(c) for c in SET_CASES)


def test_aggregate_rule_is_caught():
    """An aggregate rule that takes the strongest kind, or that never downgrades, disagrees with
    some case."""
    with_aggregate = [c for c in SET_CASES if "aggregate" in c["inputs"]]
    for name, defective in {"always stream_interval": lambda k, p: "stream_interval",
                            "kind whatever the properties": lambda k, p: k,
                            "always holder_selected": lambda k, p: "holder_selected"}.items():
        assert any(run_set(c, aggregate_rule=defective) != run_set(c) for c in with_aggregate), name


def test_independence_from_distinct_keys_is_caught():
    """Distinct keys never give PASS (§6.7.4); an evaluator that says they do, or that calls an
    unbound pair redundant, disagrees."""
    assert any(run_halves(c, lambda a, b: "PASS" if a["producer"] != b["producer"] else "FAIL")
               != c["expected"]["halves"] for c in HALVES_CASES)
    assert any(run_halves(c, lambda a, b: "FAIL") != c["expected"]["halves"] for c in HALVES_CASES)
    assert any(run_halves(c, lambda a, b: "NOT_CHECKED") != c["expected"]["halves"] for c in HALVES_CASES)


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
        assert top[f"coverage-declaration-v0/{name}"] == sha((VECTORS / name).read_bytes()), name
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text())["corpora"]
    assert corpora["coverage_declaration_v0"] == "coverage-declaration-v0/manifest.json"
    assert "generate_coverage_declaration_v0_vectors.py" in (
        ROOT / "python" / "scripts" / "generate_all_vectors.py").read_text()


def test_does_not_import_the_generator():
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    modules = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    modules += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in modules if m.startswith("generate_")]


def test_halves_signatures_verify_from_the_octets():
    for case in HALVES_CASES:
        for h in case["inputs"]["halves"]:
            r = json.loads(h["octets_text"])
            assert h["octets_text"].encode() == jcs(r)
            assert ed25519_ok(r["producer"], r["sig"], jcs({k: v for k, v in r.items() if k != "sig"}))


def test_artifacts_decode():
    """Every reply's artifact is base64url of JCS octets (IP §4)."""
    for case in SET_CASES:
        for x in case["inputs"]["exchanges"]:
            a = json.loads(x["reply"]["octets_text"])["artifact"]
            octets = base64.urlsafe_b64decode(a + "=" * (-len(a) % 4))
            assert octets == jcs(json.loads(octets))
