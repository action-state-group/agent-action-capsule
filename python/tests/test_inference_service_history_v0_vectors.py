# SPDX-License-Identifier: BSD-3-Clause
"""The Inference-Service History Profile vectors (``vectors/inference-service-history-v0/``).

Every case is run from its inputs alone:

- Each request and reply goes through the reference verifier for ``evidence-interop/0``
  (``agent_action_capsule.interop_profile``).
- The History properties of the profile's §8.3, its coverage report (§4.2), what a verifier
  shows of witness receipts (§5.2) and of exchanges (§7.2), and ``period_fixed`` (§6.3) come from
  an evaluator written here.

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
from collections.abc import Callable
from datetime import datetime, timedelta
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
VECTORS = ROOT / "vectors" / "inference-service-history-v0"
GENERATOR = ROOT / "python" / "scripts" / "generate_inference_service_history_v0_vectors.py"
HAND_WRITTEN = ("README.md",)
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
HISTORY_CASES = [c for c in CASES if c["kind"] == "history"]
PAIR_CASES = [c for c in CASES if c["kind"] == "pair"]
REFUSAL_CASES = [c for c in CASES if c["kind"] == "refusal"]
CONTRACT = DATA["contract"]["document"]
SPEC_TEXT = (ROOT / DATA["spec"]).read_text(encoding="utf-8")

RELATIVE_TO = ("the node's stream at the anchor, under all_records; completeness not established: "
               "counts not checked against records")
# §4.1, §4.4: the definition members per level, and the values the profile fixes.
COMMON = {"profile", "name", "kind", "level", "embeds", "subjects", "members", "reads", "excludes",
          "coverage_declaration", "spec"}
LEVEL_MEMBERS = {"standard": COMMON | {"period_policy"}, "detailed": COMMON | {"recipient"}}
LEVEL_KIND = {"standard": {"kind": "stream_interval", "rule": "all_records"}, "detailed": {"kind": "holder_selected"}}
POLICY_MEMBERS = {"epoch", "floor", "length_s", "min_length_s", "suppression"}
# §5.1, §7.1.
UNITS = {"exchanges_served", "exchanges_requested", "exchanges_unattributed", "checkpoints", "witness_receipts",
         "referee_verdicts", "records"}
RANK = {"self_reported": 0, "peer_confirmed": 1, "corroborated": 2}
PEER_SHOWN = "peer-confirmed; not corroborating (independence not established)"
ROLE_UNIT = {"served": "exchanges_served", "requested": "exchanges_requested"}
# §8.2.
FIXED = {"anchor", "declared", "derivation", "evidence_stream", "history_card", "history_card_digest", "subject"}
MUST_PASS = ("profile_version", "envelope_signature", "responder_trust", "issued_at_form", "request_binding",
             "subject_binding", "artifact_digest", "anchor_match")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def digest(v: Any) -> str:
    return sha(jcs(v))


def ed25519_ok(key_hex: Any, sig_hex: Any, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(bytes.fromhex(sig_hex), data)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def signed_ok(o: dict, key_member: str) -> bool:
    return ed25519_ok(o.get(key_member), o.get("sig"), jcs({k: v for k, v in o.items() if k != "sig"}))


def when(t: str) -> datetime:
    return datetime.fromisoformat(t.replace("Z", "+00:00"))


def message(o: dict) -> Message:
    return Message(o["octets_text"].encode("utf-8"), o["media_type"])


def run_reply(case: dict, h: dict) -> tuple[dict, Any]:
    """IP's result for one request and reply, as the History profile §8.1 reads it."""
    pins = case["pins"]
    v = InteropVerifier(TrustPolicy.from_dict(pins["trust_policy"]),
                        VerificationPolicy.from_dict(pins["verification_policy"]), pins["evaluation_time"],
                        contract=CONTRACT)
    (ex,) = v.verify([Exchange(message(h["request"]), [message(h["reply"])])], requirements=["r-service"]).exchanges
    (r,) = ex.replies
    props = {p.property: p.status for p in r.properties}
    reqs = {}
    for q, x in r.requirements.items():
        reqs[q] = {"row": x.row, "status": x.status, "sufficiency": x.sufficiency, "verdict": x.verdict}
        if x.note is not None:
            reqs[q]["note"] = x.note
    out: dict[str, Any] = {"message_type": r.message_type}
    if r.message_type == "refusal":
        out.update(reason=json.loads(h["reply"]["octets_text"])["reason"], properties=props, requirements=reqs,
                   claim={"evidence": r.evidence, "proofs": r.proofs})
        return out, None
    env = json.loads(h["reply"]["octets_text"])
    accepted = (all(props[k] == "PASS" for k in MUST_PASS) and props["anchor_inclusion"] == "NOT_CHECKED"
                and "verification" not in env)
    out.update(subject=env["subject"], properties=props, accepted=accepted, requirements=reqs,
               claim={"evidence": r.evidence, "proofs": r.proofs})
    return out, {**env, "artifact": json.loads(r.artifact)}


# ---------------------------------------------------------------------------
# The History properties (§8.3)
# ---------------------------------------------------------------------------


def definition_form(d: Any) -> bool:
    if not isinstance(d, dict) or d.get("level") not in LEVEL_MEMBERS or set(d) != LEVEL_MEMBERS[d["level"]]:
        return False
    if (d["profile"], d["kind"], d["embeds"], d["subjects"]) != ("inference-service-history/0", "projection",
                                                                  ["history_card/1"], ["full_history"]):
        return False
    if not re.fullmatch(r"[a-z0-9_]+/[0-9]+", d["name"]) or d["coverage_declaration"] != LEVEL_KIND[d["level"]]:
        return False
    members = d["members"]
    names = [m.get("name") for m in members]
    if len(set(names)) != len(names) or not any(m["name"] == "history_card" and m.get("required") is True
                                                and m.get("derivation") == "history_card/1" for m in members):
        return False
    union: list[str] = []
    for m in members:
        if not set(m) <= {"name", "required", "derivation", "reads", "units", "claims"}:
            return False
        if not m.get("units") or any(u.get("unit") not in UNITS for u in m["units"]):
            return False
        union += [r for r in m["reads"] if r not in union]
    if d["reads"] != union:
        return False
    if d["level"] == "standard":
        p = d["period_policy"]
        return ("requester identity" in d["excludes"] and isinstance(p, dict) and set(p) == POLICY_MEMBERS
                and p["suppression"] == "complementary" and p["length_s"] >= p["min_length_s"] > 0 and p["floor"] >= 1)
    return isinstance(d["recipient"], str) and bool(d["recipient"])


def artifact_form(d: dict, env: dict) -> bool:
    a = env["artifact"]
    names = {m["name"] for m in d["members"]}
    declared = a.get("declared")
    if not isinstance(declared, list) or declared != sorted(set(declared)) or not set(declared) <= names:
        return False
    if not {m["name"] for m in d["members"] if m["required"]} <= set(declared):
        return False
    extra = {"coverage_declaration"} if d["level"] == "standard" else set()
    if set(a) != FIXED | extra | set(declared):
        return False
    if (a["anchor"], a["derivation"], a["subject"]) != (env["anchor"]["digest"], env["derivation"], env["subject"]):
        return False
    if "exchanges" in a:
        for e in a["exchanges"]:
            half = json.loads(e["half"]["octets_text"])
            if (half.get("producer") != env["responder"] or not signed_ok(half, "producer")
                    or half.get("client_nonce") != e["client_nonce"] or half.get("role") not in ROLE_UNIT):
                return False
    return True


def card_content(case: dict, env: dict) -> bool:
    """§5.2: the card's checkpoints are signed by a log key, in order, and end at the anchor; every
    receipt covers its checkpoint. Receipts under a witness key the pins do not hold are not counted."""
    a = env["artifact"]
    c = a["history_card"]
    if digest(c) != a["history_card_digest"] or c["anchor"] != a["anchor"] or c["derivation"] != "history_card/1":
        return False
    log_keys = case["pins"]["service_history"]["log_keys"]
    prev = None
    for h in c["history"]:
        cp = h["checkpoint"]
        if cp["key_id"] not in log_keys or not signed_ok(cp, "key_id"):
            return False
        if prev is not None and (cp["log_size"] < prev["log_size"] or when(cp["timestamp"]) <= when(prev["timestamp"])):
            return False
        for r in h["receipts"]:
            if r["checkpoint"] != digest(cp) or not signed_ok(r, "witness"):
                return False
        prev = cp
    return digest(c["history"][-1]["checkpoint"]) == a["anchor"]


def witness_shown(case: dict, env: dict) -> dict:
    keys = case["pins"]["service_history"]["witness_keys"]
    history = env["artifact"]["history_card"]["history"]
    counted, not_counted = 0, []
    for i, h in enumerate(history):
        for r in h["receipts"]:
            if r["witness"] in keys:
                counted += 1
            else:
                not_counted.append({"checkpoint": i, "reason": "witness key not configured"})
    return {"checkpoints": len(history), "witness_receipts_counted": counted, "witness_receipts_not_counted": not_counted}


def cells(env: dict) -> list[dict]:
    pc = env["artifact"].get("period_counts")
    return [c for p in pc["periods"] for c in p["cells"]] if pc else []


def units_ok(d: dict, env: dict) -> bool:
    by_member = {m["name"]: {u["unit"] for u in m["units"]} for m in d["members"]}
    a = env["artifact"]
    if any(c["unit"] not in UNITS or c["unit"] not in by_member.get("period_counts", set()) for c in cells(env)):
        return False
    for e in a.get("exchanges", []):
        role = json.loads(e["half"]["octets_text"])["role"]
        if e["unit"] != ROLE_UNIT[role] or e["unit"] not in by_member["exchanges"]:
            return False
    return True


def derive(case: dict, env: dict, e: dict) -> tuple[str, str, str | None]:
    """§7.2: what one exchange's evidence supports, how it is shown, and issuer independence."""
    if "peer_half" not in e:
        return "self_reported", "one-sided", None
    peer = json.loads(e["peer_half"]["octets_text"])
    half = json.loads(e["half"]["octets_text"])
    if not signed_ok(peer, "producer"):
        return "self_reported", "peer half not verified under a trusted key", None
    if peer["producer"] == env["responder"]:
        return "self_reported", "redundant, not corroborating", "FAIL"
    if peer["producer"] not in case["pins"]["service_history"]["peer_keys"]:
        return "self_reported", "peer half not verified under a trusted key", None
    cites = {r["digest"] for r in half.get("references", []) if r.get("citation_purpose") == "counterparty_half"}
    joined = (peer.get("client_nonce") == half["client_nonce"] and sha(e["peer_half"]["octets_text"].encode()) in cites
              and {peer.get("role"), half["role"]} == {"served", "requested"})
    if not joined:
        return "self_reported", "not joinable", None
    return "peer_confirmed", PEER_SHOWN, "NOT_CHECKED"


Derive = Callable[[dict, dict, dict], tuple[str, str, str | None]]


def exchanges_shown(case: dict, env: dict, derive_fn: Derive) -> list[dict]:
    out = []
    for e in env["artifact"].get("exchanges", []):
        label, as_, independence = derive_fn(case, env, e)
        s: dict[str, Any] = {"client_nonce": e["client_nonce"], "claimed": e["label"], "derived": label, "shown_as": as_}
        if independence is not None:
            s["issuer_independence"] = independence
        out.append(s)
    return out


def labels_ok(case: dict, env: dict, derive_fn: Derive) -> bool:
    """§7.3: no label is stronger than its evidence. A Standard count is the node's own statement."""
    if any(c["label"] not in RANK or RANK[c["label"]] > 0 for c in cells(env)):
        return False
    return all(e["label"] in RANK and RANK[e["label"]] <= RANK[s["derived"]]
               for e, s in zip(env["artifact"].get("exchanges", []), exchanges_shown(case, env, derive_fn)))


def periods_ok(d: dict, env: dict) -> bool:
    """§6.1: periods aligned to the epoch, the policy's length, sorted, not overlapping, closed at the anchor."""
    p = d["period_policy"]
    pc = env["artifact"]["period_counts"]
    if pc["policy"] != digest(p):
        return False
    epoch, length = when(p["epoch"]), timedelta(seconds=p["length_s"])
    anchor_time = when(env["artifact"]["history_card"]["history"][-1]["checkpoint"]["timestamp"])
    prev_to = None
    for period in pc["periods"]:
        start, end = when(period["from"]), when(period["to"])
        if (start - epoch) % length or end - start != length or end > anchor_time:
            return False
        if prev_to is not None and start < prev_to:
            return False
        prev_to = end
    return True


def anchor_ok(d: dict, env: dict) -> bool:
    """§6.1 item 2: the anchor's checkpoint time is a period boundary."""
    p = d["period_policy"]
    anchor_time = when(env["artifact"]["history_card"]["history"][-1]["checkpoint"]["timestamp"])
    return not (anchor_time - when(p["epoch"])) % timedelta(seconds=p["length_s"])


def floor_ok(d: dict, env: dict) -> bool:
    """§6.2: a published cell is at least the floor; a suppressed cell has no value; a unit's total and
    all but one of its cells never stand published beside one suppressed cell."""
    floor = d["period_policy"]["floor"]
    for period in env["artifact"]["period_counts"]["periods"]:
        for c in period["cells"]:
            if ("suppressed" in c) != (c["value"] is None) or c.get("suppressed", "below_floor") not in (
                    "below_floor", "complementary"):
                return False
            if c["value"] is not None and c["value"] < floor:
                return False
        for unit in {c["unit"] for c in period["cells"]}:
            parts = [c for c in period["cells"] if c["unit"] == unit and c["dimension"] is not None]
            totals = [c for c in period["cells"] if c["unit"] == unit and c["dimension"] is None]
            hidden = [c for c in parts if c["value"] is None]
            if totals and totals[0]["value"] is not None and len(hidden) == 1:
                return False
    return True


def coverage_report(d: dict, env: dict) -> dict:
    if d["level"] == "detailed":
        return {"declared_kind": "holder_selected", "properties": {"coverage_declaration_form": "PASS"},
                "relative_to": "not asserted"}
    dec = env["artifact"]["coverage_declaration"]
    form = (set(dec) == {"kind", "rule", "interval", "live_set"} and dec["kind"] == d["coverage_declaration"]["kind"]
            and dec["rule"] == d["coverage_declaration"]["rule"] and set(dec["interval"]) == {"from", "to"}
            and len(dec["live_set"]) == 1 and set(dec["live_set"][0]) == {"stream", "checkpoint", "start", "count"}
            and dec["live_set"][0]["stream"] == env["artifact"]["evidence_stream"]
            and (dec["interval"]["from"] is not None or dec["live_set"][0]["start"] == 0))
    if not form:
        return {"declared_kind": "stream_interval", "properties": {"coverage_declaration_form": "FAIL"},
                "relative_to": RELATIVE_TO}
    anchor = dec["interval"]["to"] == env["anchor"]["digest"] and dec["interval"]["from"] != dec["interval"]["to"]
    return {"declared_kind": "stream_interval",
            "properties": {"coverage_declaration_form": "PASS", "coverage_declaration_anchor": "PASS" if anchor else "FAIL",
                           # §4.2, SH-4: a count of records carries no records to compare.
                           "coverage_declaration_population": "NOT_CHECKED",
                           "coverage_declaration_commitment": "NOT_CHECKED"},
            "relative_to": RELATIVE_TO}


def history_properties(case: dict, d: dict, env: dict, derive_fn: Derive = derive) -> dict:
    form = definition_form(d)
    props = {"definition_form": "PASS" if form else "FAIL",
             "definition_binding": "PASS" if env["derivation"] == digest(d) else "FAIL"}
    if not form:
        return props
    shape = artifact_form(d, env)
    props["artifact_form"] = "PASS" if shape else "FAIL"
    if not shape:
        return props
    props["history_card_content"] = "PASS" if card_content(case, env) else "FAIL"
    props["units"] = "PASS" if units_ok(d, env) else "FAIL"
    props["labels"] = "PASS" if labels_ok(case, env, derive_fn) else "FAIL"
    if d["level"] == "standard":
        props["period_alignment"] = "PASS" if periods_ok(d, env) else "FAIL"
        props["period_anchor"] = "PASS" if anchor_ok(d, env) else "FAIL"
        props["period_floor"] = "PASS" if floor_ok(d, env) else "FAIL"
    return props


Evaluator = Callable[[dict, dict, dict], dict]


def run_history(case: dict, evaluate: Evaluator = history_properties, derive_fn: Derive = derive) -> dict:
    h = case["inputs"]
    result, env = run_reply(case, h)
    d = h["definition"]
    hprops = evaluate(case, d, env)
    cov = coverage_report(d, env)
    shows: dict[str, Any] = {"witness": witness_shown(case, env)}
    if d["level"] == "detailed":
        shows["exchanges"] = exchanges_shown(case, env, derive_fn)
    accepted = (result["accepted"] and all(v == "PASS" for v in hprops.values())
                and "FAIL" not in cov["properties"].values())
    return {"exchange": result, "history_properties": hprops, "coverage": cov, "shows": shows, "accepted": accepted}


def period_fixed(envs: list[dict]) -> str:
    """§6.1: a period answered at two anchors carries the same cells at both."""
    seen: dict[tuple[str, str], str] = {}
    for env in envs:
        for p in env["artifact"]["period_counts"]["periods"]:
            key, value = (p["from"], p["to"]), jcs(p["cells"]).decode()
            if seen.setdefault(key, value) != value:
                return "FAIL"
    return "PASS"


def run_pair(case: dict, fixed: Callable[[list[dict]], str] = period_fixed) -> dict:
    results, envs = zip(*(run_reply(case, h) for h in case["inputs"]["histories"]))
    status = fixed(list(envs))
    accepted = all(r["accepted"] for r in results) and status == "PASS" and all(
        all(v == "PASS" for v in history_properties(case, h["definition"], e).values())
        for h, e in zip(case["inputs"]["histories"], envs))
    return {"exchanges": list(results), "period_fixed": status, "accepted": accepted}


def comparable(expected: dict) -> dict:
    e = copy.deepcopy(expected)
    e.pop("fails", None)
    return e


def failing(result: dict) -> set:
    return ({p for p, s in result["exchange"]["properties"].items() if s == "FAIL"}
            | {p for p, s in result["history_properties"].items() if s == "FAIL"}
            | {p for p, s in result["coverage"]["properties"].items() if s == "FAIL"})


# ---------------------------------------------------------------------------
# The vectors
# ---------------------------------------------------------------------------


def test_corpus_shape_and_pins():
    assert DATA["count"] == len(CASES) == 23
    assert (len(HISTORY_CASES), len(PAIR_CASES), len(REFUSAL_CASES)) == (17, 2, 4)
    assert sha(DATA["contract"]["document_jcs"].encode()) == DATA["contract"]["contract_digest"]
    assert digest(DATA["period_policy"]["document"]) == DATA["period_policy"]["digest"]
    assert set(DATA["units"]) == UNITS and DATA["labels"] == list(RANK)
    for case in CASES:
        assert case["pins"]["contract_digest"] == DATA["contract"]["contract_digest"]
        assert case["source"] == "constructed" or case["source"].startswith("constructed: ")


def test_acceptance_families_are_present():
    """The four families the profile's acceptance names (§9.4)."""
    ids = {c["id"] for c in CASES}
    assert {"standard-served-only", "detailed-peer-confirmed", "refused-range-interval",
            "mutant-overlapping-period", "mutant-labelled-corroborated"} <= ids
    (detailed,) = [c for c in CASES if c["id"] == "detailed-peer-confirmed"]
    derived = {s["derived"] for s in detailed["expected"]["shows"]["exchanges"]}
    assert derived == {"peer_confirmed", "self_reported"}


def test_test_keys_derive_from_their_labels():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    for k in DATA["test_keys"]["keys"].values():
        priv = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(k["seed_label"].encode()).digest())
        assert priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() == k["public"]


@pytest.mark.parametrize("case", HISTORY_CASES, ids=[c["id"] for c in HISTORY_CASES])
def test_history_case(case):
    assert run_history(case) == comparable(case["expected"])


@pytest.mark.parametrize("case", HISTORY_CASES, ids=[c["id"] for c in HISTORY_CASES])
def test_named_property_fails(case):
    got = run_history(case)
    assert set(case["expected"]["fails"]) == failing(got)
    assert got["accepted"] is (not case["expected"]["fails"])


@pytest.mark.parametrize("case", PAIR_CASES, ids=[c["id"] for c in PAIR_CASES])
def test_pair_case(case):
    assert run_pair(case) == comparable(case["expected"])


@pytest.mark.parametrize("case", REFUSAL_CASES, ids=[c["id"] for c in REFUSAL_CASES])
def test_refusal_case(case):
    got, _ = run_reply(case, case["inputs"])
    assert got == case["expected"]


def test_interval_refusal_is_the_same_for_every_requester():
    """§6.1 item 5: two requesters asking the same interval get the same token."""
    reasons = {json.loads(c["inputs"]["reply"]["octets_text"])["reason"]
               for c in REFUSAL_CASES if c["id"].startswith("refused-range-interval")}
    assert reasons == {"policy_declined"}


def test_a_valid_signature_never_makes_a_label():
    """§7.3: in every labelling negative the envelope is accepted, and the History still is not."""
    for case in HISTORY_CASES:
        if "labels" in case["expected"]["fails"]:
            got = run_history(case)
            assert got["exchange"]["accepted"] and not got["accepted"], case["id"]


def test_no_v0_evaluation_derives_corroborated():
    for case in HISTORY_CASES:
        for s in case["expected"]["shows"].get("exchanges", []):
            assert s["derived"] != "corroborated" and s.get("issuer_independence") != "PASS", case["id"]


def test_served_only_counts_no_requested_exchange():
    (case,) = [c for c in CASES if c["id"] == "standard-served-only"]
    _, env = run_reply(case, case["inputs"])
    assert {c["unit"] for c in cells(env)} == {"exchanges_served"}


def test_spec_lists_every_case():
    section = SPEC_TEXT.split("### 9.4", 1)[1].split("\n## ", 1)[0]
    listed = set(re.findall(r"^\| `([a-z0-9-]+)` \|", section, re.M))
    assert listed == {c["id"] for c in CASES}


# ---------------------------------------------------------------------------
# Negative checks: each defective evaluator must disagree with some case
# ---------------------------------------------------------------------------


def _without(prop: str) -> Evaluator:
    def evaluate(case: dict, d: dict, env: dict) -> dict:
        props = history_properties(case, d, env)
        if prop in props:
            props[prop] = "PASS"
        return props
    return evaluate


def _no_complement(case: dict, d: dict, env: dict) -> dict:
    """Checks the floor per cell and never the complementary rule."""
    props = history_properties(case, d, env)
    if "period_floor" in props:
        floor = d["period_policy"]["floor"]
        props["period_floor"] = "PASS" if all(c["value"] is None or c["value"] >= floor for c in cells(env)) else "FAIL"
    return props


def _overlap_allowed(case: dict, d: dict, env: dict) -> dict:
    """Checks each period on its own, never against the one before it."""
    props = history_properties(case, d, env)
    if "period_alignment" in props:
        length = timedelta(seconds=d["period_policy"]["length_s"])
        anchor_time = when(env["artifact"]["history_card"]["history"][-1]["checkpoint"]["timestamp"])
        ok = all(when(x["to"]) - when(x["from"]) == length and when(x["to"]) <= anchor_time
                 for x in env["artifact"]["period_counts"]["periods"])
        props["period_alignment"] = "PASS" if ok else "FAIL"
    return props


DEFECTIVE: dict[str, Evaluator] = {
    "units not checked": _without("units"),
    "labels not checked": _without("labels"),
    "alignment not checked": _without("period_alignment"),
    "anchor not checked": _without("period_anchor"),
    "floor not checked": _without("period_floor"),
    "floor without complementary suppression": _no_complement,
    "periods checked alone": _overlap_allowed,
}


def _distinct_keys_corroborate(case: dict, env: dict, e: dict) -> tuple[str, str, str | None]:
    label, as_, independence = derive(case, env, e)
    return ("corroborated", "corroborated", "PASS") if label == "peer_confirmed" else (label, as_, independence)


def _signature_is_confirmation(case: dict, env: dict, e: dict) -> tuple[str, str, str | None]:
    """Takes any validly signed peer half as confirmation: no key, trust or join check."""
    if "peer_half" in e and signed_ok(json.loads(e["peer_half"]["octets_text"]), "producer"):
        return "peer_confirmed", PEER_SHOWN, "NOT_CHECKED"
    return derive(case, env, e)


def _nonce_only(case: dict, env: dict, e: dict) -> tuple[str, str, str | None]:
    """Joins on the client nonce and the peer key, never on the citation."""
    if "peer_half" in e:
        peer = json.loads(e["peer_half"]["octets_text"])
        if (peer["producer"] in case["pins"]["service_history"]["peer_keys"]
                and peer["client_nonce"] == e["client_nonce"]):
            return "peer_confirmed", PEER_SHOWN, "NOT_CHECKED"
    return derive(case, env, e)


DEFECTIVE_DERIVE: dict[str, Derive] = {
    "distinct keys corroborate": _distinct_keys_corroborate,
    "a signature is a confirmation": _signature_is_confirmation,
    "joined on the nonce, not the citation": _nonce_only,
}


def test_every_defective_evaluator_is_caught():
    for name, evaluate in DEFECTIVE.items():
        assert any(run_history(c, evaluate) != run_history(c) for c in HISTORY_CASES), name
    for name, fn in DEFECTIVE_DERIVE.items():
        assert any(run_history(c, derive_fn=fn) != run_history(c) for c in HISTORY_CASES), name


def test_period_fixed_is_caught():
    assert any(run_pair(c, lambda envs: "PASS") != run_pair(c) for c in PAIR_CASES)


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
    for name, d in listed.items():
        assert sha((VECTORS / name).read_bytes()) == d, name
    top = dict(reversed(line.split("  ", 1)) for line in (ROOT / "vectors" / "SHA256SUMS").read_text().splitlines())
    for name in set(_files(VECTORS)) - {"SHA256SUMS"}:
        assert top[f"inference-service-history-v0/{name}"] == sha((VECTORS / name).read_bytes()), name
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text())["corpora"]
    assert corpora["inference_service_history_v0"] == "inference-service-history-v0/manifest.json"
    assert "generate_inference_service_history_v0_vectors.py" in (
        ROOT / "python" / "scripts" / "generate_all_vectors.py").read_text()


def test_does_not_import_the_generator():
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    modules = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    modules += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in modules if m.startswith("generate_")]


def test_artifacts_decode_and_halves_are_jcs():
    """Every reply's artifact is base64url of JCS octets (IP §4); every half is carried as JCS."""
    for case in HISTORY_CASES + [h for c in PAIR_CASES for h in c["inputs"]["histories"]]:
        h = case.get("inputs", case)
        a = json.loads(h["reply"]["octets_text"])["artifact"]
        octets = base64.urlsafe_b64decode(a + "=" * (-len(a) % 4))
        assert octets == jcs(json.loads(octets))
        for e in json.loads(octets).get("exchanges", []):
            for k in ("half", "peer_half"):
                if k in e:
                    assert e[k]["octets_text"].encode() == jcs(json.loads(e[k]["octets_text"]))
