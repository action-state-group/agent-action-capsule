# SPDX-License-Identifier: BSD-3-Clause
"""The Outcome level vectors of the personal-agent History profile (``vectors/personal-history-outcome-v0/``).

Every case is run from its inputs alone:

- Each exchange goes through the reference verifier for ``evidence-interop/0``
  (``agent_action_capsule.interop_profile``), and the test applies the level's §8.1.
- The level's History properties (§8.2), claim properties (§8.3), requirement results (§8.4) and
  deal commitment openings (§7) come from an evaluator written here from the level text.
- A native object's ``native_check`` is taken from the x402 adapter corpus, not computed here: the
  evaluator finds the corpus case whose wrapped objects the claim cites, requires the case's
  recorded lookup to be the one the relying party observed, and reads the statuses that case states
  for the checks the adapter predicate requires. The x402 corpus's own test checks those statuses.

All of it is compared with the case's whole ``expected`` block, in which the generator states the
properties by hand. Nothing here imports the generator. The test regenerates the corpus twice and requires both
runs to be byte-identical to the committed files. It also runs defective evaluators, each of which
must disagree with at least one case.
"""
from __future__ import annotations

import ast
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
VECTORS = ROOT / "vectors" / "personal-history-outcome-v0"
BASIC_VECTORS = ROOT / "vectors" / "personal-history-basic-v0"
X402 = ROOT / "vectors" / "adapters" / "x402"
GENERATOR = ROOT / "python" / "scripts" / "generate_personal_history_outcome_v0_vectors.py"
HAND_WRITTEN = ("README.md",)
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
CONTRACT = DATA["contract"]["document"]
SPEC_TEXT = (ROOT / DATA["spec"]).read_text(encoding="utf-8")

# §3, §4.
NAME = "personal_history_outcome/1"
MEMBERS = {"name", "kind", "subject_form", "selection", "reads", "coverage_declaration", "holder_role", "sources",
           "predicates", "recipient"}
READS = ["commit_alg", "committed_at", "consent", "deal_commitment", "epistemic_type", "event_time_claim",
         "outcome", "record_type"]
FIXED = {"kind": "projection", "subject_form": "correlation", "reads": READS}
ROLES = {"seller", "buyer"}
SOURCES = {"holder_record", "counterparty_half", "native_object", "judge_verdict"}
ARTIFACT_MEMBERS = {"anchor", "derivation", "evidence_stream", "records", "subject"}
JUDGE_VERDICTS = {"met", "not_met", "not_evaluable"}
RECORD_KINDS = {"step_completed", "step_failed", "outcome_recorded", "judge_consent"}
COMMIT_ALG = "sha256-jcs-nonce256"
MUST_PASS = ("profile_version", "envelope_signature", "responder_trust", "issued_at_form", "request_binding",
             "subject_binding", "artifact_digest", "anchor_match")
# §5: the members of an outcome claim, per source.
CLAIM_MEMBERS = {"holder_record": {"predicate", "source"},
                 "counterparty_half": {"predicate", "source", "evidence"},
                 "judge_verdict": {"predicate", "source", "evidence"},
                 "native_object": {"predicate", "source", "evidence", "adapter", "adapter_predicate"}}
# IP §6.7.1.
DECLARATION_MEMBERS = {"holder_selected": {"kind"}, "stream_interval": {"kind", "rule", "interval", "live_set"},
                       "source_authoritative": {"kind", "source", "method", "population"}}
# spec/adapters/x402-v0.md §8 (d): the checks each predicate requires PASS on.
X402_REQUIRES = {
    "X1": ["payload_form", "payer_signature"],
    "X2": ["payload_form", "payer_signature", "authorization_terms"],
    "X3": ["payload_form", "payer_signature", "settle_response_form", "settlement_onchain", "authorization_window"],
    "X4": ["receipt_signature", "receipt_signer_authorized"],
    "X5": ["receipt_signature", "receipt_signer_authorized", "delivery_binding"],
}
# §5.3: a payment shown for a deal also needs the payer and asset bound by the relying party's policy.
X402_ALSO = ["payer_trust", "asset_trust"]
# The Basic level corpus as it stood when this level was cut (its multi-stream revision included).
BASIC_RELEASED = {
    "README.md": "054bc0339a2003b38c8bcda49bb6f6f4cccd141aa583f62d0f2072191dca606e",
    "manifest.json": "fbf0e11e13735d12f6100cedf7eb76b305eb71384c2d02f9d54d838ff563abce",
    "producer/main.go": "e9054656ad2431de9c5cf9bed89cdb2316314039db0eb077148e3e8a20f7c38e",
    "responder-run.json": "f7d77d56d81ca187cb9a8118f8a15aae5407f5a96aca1c5525a5f5d2e827b848",
    "vectors.json": "f1f0e1b95c7dd32f2ddc584d4c55bc9a643a58f550a941651bfd5d3e4c59a4b9",
}
HEX64 = re.compile(r"[0-9a-f]{64}")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def is_hex64(v: Any) -> bool:
    return isinstance(v, str) and HEX64.fullmatch(v) is not None


def ed25519_ok(key_hex: Any, sig_hex: Any, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(bytes.fromhex(sig_hex), data)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def octets(o: dict) -> bytes:
    return o["octets_text"].encode("utf-8") if "octets_text" in o else bytes.fromhex(o["octets_hex"])


def predicate_table() -> dict:
    """§6.1: the table, as the level text publishes it."""
    section = SPEC_TEXT.split("### 6.1", 1)[1].split("\n### ", 1)[0]
    return json.loads(section.split("```json\n", 1)[1].split("```", 1)[0])


TABLE = predicate_table()
TABLE_DIGEST = sha(jcs(TABLE))
PREDICATES = {p["id"]: p for p in TABLE["predicates"]}


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
# The envelopes and the History properties (§8.1, §8.2)
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
    if not isinstance(d, dict) or set(d) != MEMBERS or d["name"] != NAME:
        return False
    if any(d[k] != v for k, v in FIXED.items()) or d["holder_role"] not in ROLES or not is_hex64(d["predicates"]):
        return False
    sel, src, rec = d["selection"], d["sources"], d["recipient"]
    return (isinstance(sel, list) and bool(sel) and all(isinstance(s, str) and s for s in sel)
            and sel == sorted(set(sel)) and isinstance(src, list) and bool(src) and set(src) <= SOURCES
            and src == sorted(set(src)) and isinstance(rec, str) and bool(rec))


def declaration_form(dec: Any) -> bool:
    """IP §6.7.2 ``coverage_declaration_form``, with §3's restriction to the rule ``all_records``."""
    if not isinstance(dec, dict) or dec.get("kind") not in DECLARATION_MEMBERS \
            or set(dec) != DECLARATION_MEMBERS[dec["kind"]]:
        return False
    if dec["kind"] == "stream_interval":
        return dec["rule"] == "all_records" and isinstance(dec["live_set"], list) and bool(dec["live_set"])
    if dec["kind"] == "source_authoritative":
        return is_hex64(dec["source"]) and isinstance(dec["method"], str) and is_hex64(dec["population"])
    return True


def artifact_form(envs: list[dict]) -> bool:
    allowed = {"digest", "leaf_index", *READS}
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
                not isinstance(r, dict) or not {"digest", "leaf_index"} <= set(r) <= allowed for r in recs):
            return False
    return True


def record_kind_ok(r: dict) -> bool:
    """§4: the closed kinds, ``outcome`` exactly on outcome records, ``consent`` exactly on consent
    records, and the commitment's two members together."""
    kind = r.get("record_type")
    return (kind in RECORD_KINDS and ("outcome" in r) == (kind == "outcome_recorded")
            and ("consent" in r) == (kind == "judge_consent")
            and ("commit_alg" in r) == ("deal_commitment" in r)
            and r.get("commit_alg", COMMIT_ALG) == COMMIT_ALG)


def deal_commitments_ok(envs: list[dict]) -> bool:
    return all(sum("deal_commitment" in r for r in e["artifact"]["records"]) <= 1 for e in envs)


def history_properties(definition: dict, envs: list[dict]) -> dict:
    selection = definition.get("selection", [])
    digest = sha(jcs(definition))
    subjects = [e["subject"] for e in envs]
    answered = Counter(s.get("correlation") for s in subjects)
    ok = {
        "definition_form": definition_form(definition),
        "definition_binding": all(e.get("derivation") == digest for e in envs),
        "predicate_binding": definition.get("predicates") == TABLE_DIGEST,
        "coverage_declaration_form": declaration_form(definition.get("coverage_declaration")),
        "selection_coverage": all(list(s) == ["correlation"] and s["correlation"] in selection for s in subjects)
        and all(answered[r] == 1 for r in selection),
        "single_signer": len({e["responder"] for e in envs}) == 1,
        "single_anchor": len({jcs(e["anchor"]) for e in envs}) == 1,
        "artifact_form": artifact_form(envs),
        "record_kinds": all(record_kind_ok(r) for e in envs for r in e["artifact"]["records"])
        and deal_commitments_ok(envs),
    }
    return {k: "PASS" if v else "FAIL" for k, v in ok.items()}


# ---------------------------------------------------------------------------
# Outcome claims (§5, §8.3)
# ---------------------------------------------------------------------------


def outcome_form(o: Any) -> bool:
    if not isinstance(o, dict) or o.get("source") not in CLAIM_MEMBERS or set(o) != CLAIM_MEMBERS[o["source"]]:
        return False
    p = PREDICATES.get(o["predicate"])
    if p is None or o["source"] not in p["sources"]:
        return False
    ev = o.get("evidence")
    return ev is None or (isinstance(ev, list) and bool(ev) and all(is_hex64(d) for d in ev) and ev == sorted(set(ev)))


def held(case: dict) -> dict[str, bytes]:
    return {sha(octets(o)): octets(o) for o in case["inputs"]["evidence"]}


def signed_ok(obj: dict, member: str) -> bool:
    return ed25519_ok(obj.get(member), obj.get("sig"), jcs({k: v for k, v in obj.items() if k != "sig"}))


def half_properties(case: dict, o: dict, deal: str, holder: str, objects: dict) -> dict:
    trusted = set(case["pins"]["outcome_roles"]["counterparty"])
    h = json.loads(objects[o["evidence"][0]]) if len(o.get("evidence", [])) == 1 else None
    if not isinstance(h, dict):
        return dict.fromkeys(["half_signature", "half_signer_trust", "half_subject", "half_states",
                              "issuer_independence"], "NOT_CHECKED")
    return {"half_signature": "PASS" if signed_ok(h, "producer") else "FAIL",
            "half_signer_trust": "PASS" if h.get("producer") in trusted else "FAIL",
            "half_subject": "PASS" if h.get("subject_ref") == deal else "FAIL",
            "half_states": "PASS" if h.get("claim") == o["predicate"] else "FAIL",
            # IP §6.7.4: same key is FAIL; distinct keys alone are NOT_CHECKED.
            "issuer_independence": "FAIL" if h.get("producer") == holder else "NOT_CHECKED"}


def x402_case(digests: list[str]) -> dict | None:
    for c in json.loads((X402 / "cases.json").read_text())["cases"]:
        if sorted(w["digest"] for w in c["inputs"]["wrapped"]) == digests:
            return c
    return None


def native_check(case: dict, o: dict, objects: dict) -> str:
    """§5.3: the adapter's own result. Only x402-v0 is implemented here; any other adapter, or an
    object not held, is NOT_CHECKED."""
    if o.get("adapter") != "x402-v0" or not all(d in objects for d in o.get("evidence", [])):
        return "NOT_CHECKED"
    c = x402_case(o["evidence"])
    requires = X402_REQUIRES.get(o.get("adapter_predicate"))
    obs = case["pins"].get("native_observations", {}).get("x402-v0")
    if c is None or requires is None or obs is None:
        return "NOT_CHECKED"
    recorded = json.loads((X402 / c["inputs"]["lookup"]).read_text())
    # The lookup the relying party observed is the case's, with finality stated (the pending
    # adapter revision's form), so the result holds under both adapter texts.
    if {k: v for k, v in obs["lookup"].items() if k != "final"} != {k: v for k, v in recorded.items() if k != "final"} \
            or obs["lookup"].get("final") is not True:
        return "NOT_CHECKED"
    statuses = {r["detail"]["check"]: r["status"] for r in c["expect"]["reports"]}
    got = [statuses.get(k) for k in requires + X402_ALSO]
    if all(s == "PASS" for s in got):
        return "PASS"
    return "FAIL" if "FAIL" in got else "NOT_CHECKED"


def native_properties(case: dict, o: dict, objects: dict) -> dict:
    maps = {"adapter": o.get("adapter"), "predicate": o.get("adapter_predicate")} in PREDICATES.get(
        o.get("predicate"), {}).get("native", [])
    return {"adapter_predicate_maps": "PASS" if maps else "FAIL", "native_check": native_check(case, o, objects)}


def judge_properties(case: dict, o: dict, deal: str, rec: dict, deal_records: list[dict],
                     objects: dict) -> tuple[dict, str | None]:
    trusted = set(case["pins"]["outcome_roles"]["judge"])
    j = json.loads(objects[o["evidence"][0]]) if len(o.get("evidence", [])) == 1 else None
    if not isinstance(j, dict):
        return dict.fromkeys(["judge_signature", "judge_signer_trust", "judge_subject", "judge_grounds",
                              "consent_precedes_judgment", "judge_verdict_allowed"], "NOT_CHECKED"), None
    report = j.get("record", {})
    mine = [c for c in report.get("cases", []) if c.get("case_id") == o["predicate"]]
    digests = {r["digest"] for r in deal_records}
    acts = [a.get("digest") for c in mine for a in c.get("acts", [])]
    consents = [r for r in deal_records if r.get("record_type") == "judge_consent"
                and r["consent"] == {"judge": j.get("judge"), "contract_ref": report.get("contract_ref")}
                and r["leaf_index"] < rec["leaf_index"]]
    props = {"judge_signature": "PASS" if signed_ok(j, "judge") else "FAIL",
             "judge_signer_trust": "PASS" if j.get("judge") in trusted else "FAIL",
             "judge_subject": "PASS" if j.get("subject_ref") == deal else "FAIL",
             "judge_grounds": "PASS" if len(mine) == 1 and acts and set(acts) <= digests else "FAIL",
             "consent_precedes_judgment": "PASS" if consents else "FAIL",
             # §5.4: this level's requirements carry no out_of_scope switch, so any other verdict fails.
             "judge_verdict_allowed": "NOT_CHECKED" if len(mine) != 1 else (
                 "PASS" if mine[0].get("verdict") in JUDGE_VERDICTS else "FAIL")}
    return props, (mine[0]["verdict"] if len(mine) == 1 else None)


def claim_properties(case: dict, definition: dict, env: dict, rec: dict) -> tuple[dict, str | None]:
    o = rec["outcome"]
    deal = env["subject"]["correlation"]
    objects = held(case)
    props = {"outcome_form": "PASS" if outcome_form(o) else "FAIL",
             "outcome_source_allowed": "PASS" if o.get("source") in definition["sources"] else "FAIL"}
    source = o.get("source")
    if source == "holder_record":
        return props, None
    props["outcome_evidence"] = "PASS" if all(d in objects for d in o.get("evidence", [])) else "NOT_PRESENT"
    if source == "counterparty_half":
        return props | half_properties(case, o, deal, env["responder"], objects), "met"
    if source == "native_object":
        return props | native_properties(case, o, objects), None
    jp, verdict = judge_properties(case, o, deal, rec, env["artifact"]["records"], objects)
    return props | jp, verdict


def counts(props: dict) -> bool:
    return all(s == "PASS" or (p == "issuer_independence" and s == "NOT_CHECKED") for p, s in props.items())


ClaimEvaluator = Callable[[dict, dict, dict, dict], tuple[dict, "str | None"]]


def run_claims(case: dict, definition: dict, envs: list[dict], evaluate: ClaimEvaluator = claim_properties,
               binding: Callable[[str], str] | None = None) -> list[dict]:
    out = []
    for env in envs:
        for rec in env["artifact"]["records"]:
            if rec.get("record_type") != "outcome_recorded":
                continue
            props, verdict = evaluate(case, definition, env, rec)
            source = rec["outcome"]["source"]
            subject = {"counterparty_half": "half_subject", "judge_verdict": "judge_subject"}.get(source)
            b = binding(source) if binding else (
                "carried" if subject is not None and props.get(subject) == "PASS" else "holder_only")
            ok = counts(props)
            out.append({"deal": env["subject"]["correlation"], "record": rec["digest"],
                        "predicate": rec["outcome"]["predicate"], "source": source, "properties": props,
                        "counts": ok, "deal_binding": b, "verdict": verdict if ok and b == "carried" else None})
    return out


def requirement_results(case: dict, deals: list[str], claims: list[dict]) -> dict:
    """§8.4."""
    out: dict[str, dict] = {}
    for req in case["pins"]["outcome_requirements"]:
        per = {}
        for deal in deals:
            mine = [c for c in claims if c["deal"] == deal and c["predicate"] == req["predicate"]
                    and c["source"] in req["sources"]]
            verdicts = {c["verdict"] for c in mine if c["counts"] and c["deal_binding"] == "carried"}
            if not mine:
                status = "GAP"
            elif len(verdicts) == 1 and verdicts <= {"met", "not_met"}:
                status = "SATISFIED"
            elif verdicts or any(c["counts"] for c in mine) or any(
                    set(c["properties"].values()) <= {"PASS", "NOT_CHECKED", "INCONCLUSIVE"} for c in mine):
                status = "UNKNOWN"
            else:
                status = "INSUFFICIENT"
            per[deal] = {"status": status, "sufficiency": status,
                         "verdict": next(iter(verdicts)) if status == "SATISFIED" else "not_evaluable"}
        out[req["id"]] = per
    return out


def opening_results(case: dict, envs: list[dict]) -> dict:
    """§7: recompute each deal's commitment from its opening. A deal with no commitment is not reported."""
    openings = case["inputs"]["openings"]
    out = {}
    for env in envs:
        deal = env["subject"]["correlation"]
        committed = [r["deal_commitment"] for r in env["artifact"]["records"] if "deal_commitment" in r]
        if not committed:
            continue
        c = committed[0]
        o = openings.get(deal)
        if o is None:
            out[deal] = "NOT_PRESENT"
        else:
            nonce_ok = isinstance(o.get("nonce"), str) and HEX64.fullmatch(o["nonce"]) is not None
            out[deal] = "PASS" if nonce_ok and set(o) == {"nonce", "text"} and sha(jcs(o)) == c else "FAIL"
    return out


def run_case(case: dict, evaluate: ClaimEvaluator = claim_properties, *,
             binding: Callable[[str], str] | None = None,
             requirements: Callable[[dict, list[str], list[dict]], dict] = requirement_results,
             openings: Callable[[dict, list[dict]], dict] = opening_results) -> dict:
    exchanges = run_exchanges(case)
    envs = [x.pop("_env") for x in exchanges]
    accepted_envs = [e for e, x in zip(envs, exchanges) if x["accepted"]]
    definition = case["inputs"]["definition"]
    hprops = history_properties(definition, accepted_envs)
    accepted = all(x["accepted"] for x in exchanges) and all(v == "PASS" for v in hprops.values())
    claims = run_claims(case, definition, accepted_envs, evaluate, binding) if accepted else None
    deals = [e["subject"]["correlation"] for e in accepted_envs]
    return {"exchanges": exchanges, "history_properties": hprops, "accepted": accepted, "claims": claims,
            "requirements": requirements(case, deals, claims) if accepted else None,
            "deal_commitment_opening": openings(case, accepted_envs)}


def comparable(expected: dict) -> dict:
    e = copy.deepcopy(expected)
    e.pop("fails")
    return e


def failing(result: dict) -> set:
    return ({p for x in result["exchanges"] for p, s in x["properties"].items() if s == "FAIL"}
            | {p for p, s in result["history_properties"].items() if s == "FAIL"}
            | {p for c in result["claims"] or [] for p, s in c["properties"].items() if s == "FAIL"}
            | ({"deal_commitment_opening"} if "FAIL" in result["deal_commitment_opening"].values() else set()))


# ---------------------------------------------------------------------------
# The vectors
# ---------------------------------------------------------------------------


def test_corpus_shape_and_pins():
    assert DATA["count"] == len(CASES) == 25
    assert DATA["history"] == NAME
    assert sha(DATA["contract"]["document_jcs"].encode()) == DATA["contract"]["contract_digest"]
    run = ROOT / "vectors" / DATA["run"]["path"]
    assert sha(run.read_bytes()) == DATA["run"]["sha256"]
    for case in CASES:
        assert case["pins"]["contract_digest"] == DATA["contract"]["contract_digest"]
        assert case["source"].startswith("derived: ")


def test_predicate_table_is_the_published_one():
    """§6.1: the corpus's table is the one the level text publishes, and its digest is the one the
    text states."""
    assert DATA["predicates"]["document"] == TABLE
    assert DATA["predicates"]["document_jcs"].encode() == jcs(TABLE)
    assert DATA["predicates"]["digest"] == TABLE_DIGEST
    assert f"`{TABLE_DIGEST}`" in SPEC_TEXT
    assert [p["id"] for p in TABLE["predicates"]] == ["cancelled", "completed", "delivered", "disputed", "paid"]


def test_one_positive_per_source_and_one_not_evaluable():
    """The acceptance of u413: one accepted case per source whose claim counts, and one case whose
    requirement is not_evaluable with a counting claim on the deal."""
    positives = {c["expected"]["claims"][0]["source"] for c in CASES
                 if c["id"] in ("holder-record", "counterparty-half", "native-object", "judge-verdict")
                 and c["expected"]["claims"][0]["counts"] and not c["expected"]["fails"]}
    assert positives == SOURCES
    (ne,) = [c for c in CASES if c["id"] == "not-evaluable-delivered-from-payment-evidence"]
    d1 = ne["expected"]["claims"][0]["deal"]
    assert ne["expected"]["requirements"]["r-paid"][d1]["verdict"] == "met"
    assert ne["expected"]["requirements"]["r-delivered"][d1] == {"status": "GAP", "sufficiency": "GAP",
                                                                  "verdict": "not_evaluable"}


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(case):
    assert run_case(case) == comparable(case["expected"])


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_named_property_fails(case):
    got = run_case(case)
    assert set(case["expected"]["fails"]) == failing(got)


def test_no_met_from_the_holders_word_alone():
    """§8.4, from the evaluator's own results: a holder_only claim never carries a verdict, and a
    requirement whose matching counting claims are all holder_only is not_evaluable."""
    checked = 0
    for case in CASES:
        got = run_case(case)
        for c in got["claims"] or []:
            if c["deal_binding"] == "holder_only":
                assert c["verdict"] is None, case["id"]
        for r in case["pins"]["outcome_requirements"]:
            for deal, res in (got["requirements"] or {}).get(r["id"], {}).items():
                mine = [c for c in got["claims"] if c["deal"] == deal and c["predicate"] == r["predicate"]
                        and c["source"] in r["sources"] and c["counts"]]
                if mine and all(c["deal_binding"] == "holder_only" for c in mine):
                    assert res["verdict"] == "not_evaluable", case["id"]
                    checked += 1
    assert checked >= 2


def test_native_case_uses_released_octets_and_a_final_lookup():
    """§12: the native object is the x402 positive case's octets, unchanged, and the lookup states
    finality, as the pending adapter revision requires. (That revision is not on main, so this test
    checks the inputs it depends on, not its semantics.)"""
    case = next(c for c in json.loads((X402 / "cases.json").read_text())["cases"] if c["name"] == "positive")
    files = {w["digest"]: (X402 / w["octets"]).read_bytes() for w in case["inputs"]["wrapped"]}
    assert len(files) == 2
    native = [c for c in CASES if c["pins"].get("native_observations")]
    assert len(native) == 4
    for c in native:
        assert c["pins"]["native_observations"]["x402-v0"]["lookup"]["final"] is True
        held_objects = held(c)
        if c["id"] == "native-object-not-held":
            assert not set(files) & set(held_objects)
            continue
        for d, raw in files.items():
            assert held_objects[d] == raw, c["id"]


def test_basic_vectors_unchanged():
    """The Basic level's corpus is byte-identical to its release: every file has the digest the
    release pinned, and no file was added."""
    files = sorted(p.relative_to(BASIC_VECTORS).as_posix() for p in BASIC_VECTORS.rglob("*") if p.is_file())
    assert set(files) - {"SHA256SUMS"} == set(BASIC_RELEASED)
    for name, digest in BASIC_RELEASED.items():
        assert sha((BASIC_VECTORS / name).read_bytes()) == digest, name


def test_spec_names_every_case():
    section = SPEC_TEXT.split("## 12.", 1)[1].split("\n## ", 1)[0]
    listed = set(re.findall(r"`([a-z0-9-]+)`", section))
    assert {c["id"] for c in CASES} <= listed


def test_test_keys_derive_from_their_labels():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    for k in DATA["test_keys"]["keys"].values():
        priv = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(k["seed_label"].encode()).digest())
        assert priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() == k["public"]


# ---------------------------------------------------------------------------
# Negative checks: each defective evaluator must disagree with some case
# ---------------------------------------------------------------------------


def _override(**fixed: str) -> ClaimEvaluator:
    def evaluate(case: dict, definition: dict, env: dict, rec: dict) -> tuple[dict, str | None]:
        props, verdict = claim_properties(case, definition, env, rec)
        return {k: fixed.get(k, v) for k, v in props.items()}, verdict
    return evaluate


def _requirements_payment_answers_delivery(case: dict, deals: list[str], claims: list[dict]) -> dict:
    """Reads a counting paid claim as evidence of delivery (the rule of §6.3 broken)."""
    widened = claims + [dict(c, predicate="delivered") for c in claims if c["predicate"] == "paid"]
    return requirement_results(case, deals, widened)


DEFECTIVE: dict[str, dict] = {
    "source allowed not checked": {"evaluate": _override(outcome_source_allowed="PASS")},
    "consent order not checked": {"evaluate": _override(consent_precedes_judgment="PASS")},
    "judge grounds not checked": {"evaluate": _override(judge_grounds="PASS")},
    "judge signature not checked": {"evaluate": _override(judge_signature="PASS")},
    "judge verdict not checked": {"evaluate": _override(judge_verdict_allowed="PASS")},
    "half claim not read": {"evaluate": _override(half_states="PASS")},
    "half subject not read": {"evaluate": _override(half_subject="PASS")},
    "same-key half corroborates": {"evaluate": _override(issuer_independence="NOT_CHECKED")},
    "judge role not checked": {"evaluate": _override(judge_signer_trust="PASS", consent_precedes_judgment="PASS")},
    "half signature not checked": {"evaluate": _override(half_signature="PASS")},
    "binding by source label": {"binding": lambda source: (
        "carried" if source in ("counterparty_half", "judge_verdict") else "holder_only")},
    "adapter predicate not mapped": {"evaluate": _override(adapter_predicate_maps="PASS", outcome_form="PASS")},
    "native object trusted unheld": {"evaluate": _override(outcome_evidence="PASS", native_check="PASS")},
    "holder's record carries the deal": {"binding": lambda source: "carried"},
    "payment answers delivery": {"requirements": _requirements_payment_answers_delivery},
    "opening not checked": {"openings": lambda case, envs: dict.fromkeys(
        (e["subject"]["correlation"] for e in envs), "PASS")},
}


def test_every_defective_evaluator_is_caught():
    for name, kw in DEFECTIVE.items():
        assert any(run_case(c, **kw) != run_case(c) for c in CASES), name


def test_disputed_is_never_an_outcome_claim():
    """§6.4: a disputed claim fails its form whatever its source."""
    (case,) = [c for c in CASES if c["id"] == "disputed-as-outcome-claim"]
    (claim,) = case["expected"]["claims"]
    assert claim["properties"]["outcome_form"] == "FAIL" and not claim["counts"]
    assert PREDICATES["disputed"]["sources"] == []


def test_out_of_scope_verdict_is_never_mapped():
    """§5.4: this level's requirements carry no out_of_scope switch, so a judge's out_of_scope case
    gives a claim that does not count, never one read as another verdict."""
    (case,) = [c for c in CASES if c["id"] == "judge-verdict-out-of-scope"]
    (claim,) = case["expected"]["claims"]
    assert claim["properties"]["judge_verdict_allowed"] == "FAIL" and not claim["counts"]
    assert claim["verdict"] is None
    assert case["expected"]["requirements"]["r-completed"][claim["deal"]]["status"] == "INSUFFICIENT"
    for c in CASES:
        for cl in c["expected"]["claims"] or []:
            if cl["source"] == "judge_verdict" and c["id"] != case["id"]:
                assert cl["properties"]["judge_verdict_allowed"] == "PASS", c["id"]


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
        assert top[f"personal-history-outcome-v0/{name}"] == sha((VECTORS / name).read_bytes()), name
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text())["corpora"]
    assert corpora["personal_history_outcome_v0"] == "personal-history-outcome-v0/manifest.json"
    assert "generate_personal_history_outcome_v0_vectors.py" in (
        ROOT / "python" / "scripts" / "generate_all_vectors.py").read_text()


def test_does_not_import_the_generator():
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    modules = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    modules += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in modules if m.startswith("generate_")]
