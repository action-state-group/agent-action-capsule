# SPDX-License-Identifier: BSD-3-Clause
"""The Personal-Agent History Profile v0 Basic level vectors (``vectors/personal-history-basic-v0/``).

Every case is run from its inputs alone. Each exchange goes through the reference verifier for
``evidence-interop/0`` (``agent_action_capsule.interop_profile``), and the test applies §6.1 to
its result. The seven History properties of §6.2 and the deal states of §5 are derived by an
evaluator written here from the profile text. Both are compared with the case's whole
``expected`` block, which the generator states by hand.

Nothing here imports the generator. The test regenerates the corpus twice and requires both runs to
be byte-identical to the committed files. It checks that every mutant of the profile's §6.4 table
has a case that fails the property the table names, and it runs defective History evaluators, each
of which must disagree with at least one case.
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

from agent_action_capsule.canonical import jcs  # noqa: E402
from agent_action_capsule.interop_profile import (  # noqa: E402
    Exchange,
    InteropVerifier,
    Message,
    TrustPolicy,
    VerificationPolicy,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "personal-history-basic-v0"
GENERATOR = ROOT / "python" / "scripts" / "generate_personal_history_basic_v0_vectors.py"
HAND_WRITTEN = ("README.md", "producer/main.go")
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
HISTORY_CASES = [c for c in CASES if "definition" in c["inputs"]]
CONTRACT = DATA["contract"]["document"]
SPEC_TEXT = (ROOT / DATA["spec"]).read_text(encoding="utf-8")

# §4.1 and §3, as the profile states them.
MEMBERS = {"name", "kind", "subject_form", "selection", "reads", "completeness", "recipient"}
FIXED = {"name": "personal_history_basic/1", "kind": "projection", "subject_form": "correlation",
         "reads": ["committed_at", "epistemic_type", "event_time_claim", "record_type"],
         "completeness": "not_asserted"}
ARTIFACT_MEMBERS = {"anchor", "derivation", "evidence_stream", "records", "subject"}
KINDS = {"step_completed", "step_failed"}
# §6.1: the envelope properties that must be PASS, and anchor_inclusion's one status.
MUST_PASS = ("profile_version", "envelope_signature", "responder_trust", "issued_at_form", "request_binding",
             "subject_binding", "artifact_digest", "anchor_match")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


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


def artifact_value(octets: bytes | None) -> Any:
    """The Artifact's value, or None unless its octets are exactly UTF-8 of JCS of one JSON value
    (§4.3): a duplicate member, trailing data or any other encoding could carry bytes that
    artifact_form never reads."""
    if octets is None:
        return None

    def no_duplicates(pairs: list) -> dict:
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate member")
        return dict(pairs)

    try:
        value = json.loads(octets, object_pairs_hook=no_duplicates)
        return value if jcs(value) == octets else None
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# §6.1 over the reference verifier
# ---------------------------------------------------------------------------


def run_exchanges(case: dict) -> list[dict]:
    """Each exchange through the reference verifier, rendered as the corpus states it, with the
    envelope value and Artifact kept for §6.2 under ``_env``."""
    exchanges = [Exchange(message(x["request"]), [message(x["reply"])]) for x in case["inputs"]["exchanges"]]
    result = verifier(case).verify(exchanges, requirements=[r["id"] for r in CONTRACT["requirements"]])
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
                    "_env": {**env, "artifact": artifact_value(r.artifact)}})
    return out


# ---------------------------------------------------------------------------
# §6.2 and §5, written here from the profile
# ---------------------------------------------------------------------------


def definition_form(d: Any) -> bool:
    if not isinstance(d, dict) or set(d) != MEMBERS or any(d[k] != v for k, v in FIXED.items()):
        return False
    sel, rec = d["selection"], d["recipient"]
    return (isinstance(sel, list) and bool(sel) and all(isinstance(s, str) and s for s in sel)
            and sel == sorted(set(sel)) and isinstance(rec, str) and bool(rec))


def artifact_form(envs: list[dict], reads: set) -> bool:
    """Checked per envelope: each artifact names its own stream, and envelopes may name different ones (§2)."""
    for env in envs:
        a = env["artifact"]
        if not isinstance(a, dict) or set(a) != ARTIFACT_MEMBERS:
            return False
        if not (isinstance(a["anchor"], str) and re.fullmatch(r"[0-9a-f]{64}", a["anchor"])) \
                or a["anchor"] != env["anchor"].get("digest") or a["derivation"] != env.get("derivation") \
                or a["subject"] != env["subject"]:
            return False
        recs = a["records"]
        if not isinstance(recs, list) or not recs:
            return False
        for r in recs:
            if not isinstance(r, dict) or not {"digest", "leaf_index"} <= set(r) \
                    or not set(r) <= {"digest", "leaf_index"} | reads:
                return False
            # Each value in its form, so no permitted member carries an object the holder chose.
            if not (isinstance(r["digest"], str) and re.fullmatch(r"[0-9a-f]{64}", r["digest"])) \
                    or type(r["leaf_index"]) is not int or not 0 <= r["leaf_index"] <= 2**53 - 1 \
                    or not all(isinstance(v, str) for k, v in r.items() if k not in ("digest", "leaf_index")):
                return False
        if not isinstance(a["evidence_stream"], str) or not a["evidence_stream"]:
            return False
    return True


def history_properties(definition: Any, envs: list[dict]) -> dict:
    """§6.2 over the envelopes §6.1 accepted."""
    selection = definition.get("selection", []) if isinstance(definition, dict) else []
    reads = set(definition.get("reads", [])) if isinstance(definition, dict) else set()
    digest = sha(jcs(definition))
    subjects = [e["subject"] for e in envs]
    answered = Counter(s.get("correlation") for s in subjects if isinstance(s, dict))
    ok = {
        "definition_form": definition_form(definition),
        "definition_binding": all(e.get("derivation") == digest for e in envs),
        "selection_coverage": all(isinstance(s, dict) and list(s) == ["correlation"] and s["correlation"] in selection
                                  for s in subjects) and all(answered[r] == 1 for r in selection),
        "single_signer": len({e["responder"] for e in envs}) == 1,
        "single_anchor": len({jcs(e["anchor"]) for e in envs}) == 1,
        "artifact_form": artifact_form(envs, reads),
        "record_kinds": all(isinstance(e["artifact"], dict) and isinstance(e["artifact"].get("records"), list)
                            and all(isinstance(r, dict) and isinstance(r.get("record_type"), str)
                                    and r["record_type"] in KINDS for r in e["artifact"]["records"])
                            for e in envs),
    }
    return {k: "PASS" if v else "FAIL" for k, v in ok.items()}


def deal_states(envs: list[dict]) -> dict:
    """§5: one state per selected deal, counted in selected deals."""
    per = {}
    for e in envs:
        kinds = {r["record_type"] for r in e["artifact"]["records"]}
        per[e["subject"]["correlation"]] = ("with a recorded failed step" if "step_failed" in kinds else
                                            "with recorded completed steps only" if "step_completed" in kinds else
                                            "with no recorded step")
    states = ("with a recorded failed step", "with recorded completed steps only", "with no recorded step")
    return {"selected_deals": len(per), "per_deal": dict(sorted(per.items())),
            "counts": {s: list(per.values()).count(s) for s in states}}


Evaluator = Callable[[Any, list[dict]], dict]


def run_history(case: dict, evaluate: Evaluator = history_properties) -> dict:
    exchanges = run_exchanges(case)
    envs = [x.pop("_env") for x in exchanges]
    accepted_envs = [e for e, x in zip(envs, exchanges) if x["accepted"]]
    hprops = evaluate(case["inputs"]["definition"], accepted_envs)
    accepted = all(x["accepted"] for x in exchanges) and all(v == "PASS" for v in hprops.values())
    out = {"exchanges": exchanges, "history_properties": hprops, "accepted": accepted}
    if accepted:
        out["deal_states"] = deal_states(accepted_envs)
    return out


def comparable(expected: dict) -> dict:
    """``fails`` names the property §6.4 says the mutant fails; ``test_named_property_fails`` checks it."""
    e = copy.deepcopy(expected)
    e.pop("fails")
    return e


def failing(result: dict) -> set:
    """Every envelope and History property a History result reports FAIL."""
    return ({p for x in result["exchanges"] for p, s in x["properties"].items() if s == "FAIL"}
            | {p for p, s in result["history_properties"].items() if s == "FAIL"})


# ---------------------------------------------------------------------------
# The vectors
# ---------------------------------------------------------------------------


def test_corpus_shape_and_pins():
    assert DATA["count"] == len(CASES) == 14
    assert len(HISTORY_CASES) == 13
    assert sha(DATA["contract"]["document_jcs"].encode()) == DATA["contract"]["contract_digest"]
    assert DATA["contract"]["document_jcs"].encode() == jcs(CONTRACT)
    responder = DATA["responder"]
    assert re.fullmatch(r"[0-9a-f]{40}", responder["commit"])
    assert sha((VECTORS / responder["run"]).read_bytes()) == responder["run_sha256"]
    for case in CASES:
        pins = case["pins"]
        assert pins["contract_digest"] == DATA["contract"]["contract_digest"]
        assert pins["verification_policy"] == {"online": False, "profiles_implemented": ["evidence-interop/0"],
                                               "kinds_implemented": ["cll-checkpoint", "cll-inclusion-proof",
                                                                     "cll-consistency-proof"]}
        assert case["source"] == "responder" or case["source"].startswith("derived: ")


def test_test_keys_derive_from_their_labels():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    for k in DATA["test_keys"]["keys"].values():
        priv = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(k["seed_label"].encode()).digest())
        assert priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() == k["public"]


def test_responder_cases_carry_the_run_octets_unchanged():
    run = json.loads((VECTORS / DATA["responder"]["run"]).read_text(encoding="utf-8"))
    carried = {(e["request"]["octets_text"], e["reply"]["octets_text"]) for e in run["exchanges"]}
    for case in CASES:
        inp = case["inputs"]
        pairs = [(x["request"], x["reply"]) for x in inp.get("exchanges", [inp] if "reply" in inp else [])]
        if case["source"] == "responder":
            assert all((q["octets_text"], r["octets_text"]) in carried for q, r in pairs), case["id"]
            if "definition" in inp:
                assert jcs(inp["definition"]).decode() in run["definitions"].values(), case["id"]
    # The positive History is three of the four deals in the run's stream.
    (positive,) = [c for c in CASES if c["id"] == "history-basic"]
    assert positive["inputs"]["definition"]["selection"] == run["selection"] == sorted(run["selection"])
    assert len(run["deals"]) == 4 and len(run["selection"]) == 3


@pytest.mark.parametrize("case", HISTORY_CASES, ids=[c["id"] for c in HISTORY_CASES])
def test_history_case(case):
    assert run_history(case) == comparable(case["expected"])


@pytest.mark.parametrize("case", HISTORY_CASES, ids=[c["id"] for c in HISTORY_CASES])
def test_named_property_fails(case):
    got = run_history(case)
    assert set(case["expected"]["fails"]) <= failing(got)
    assert got["accepted"] is (not case["expected"]["fails"])


def test_basic_level_never_yields_met_or_not_met():
    """§6.1: every requirement a Basic level answer is the only evidence for is UNKNOWN/not_evaluable."""
    (positive,) = [c for c in CASES if c["id"] == "history-basic"]
    for x in run_exchanges(positive):
        assert x["requirements"] == {"r-deal-steps": {"row": "envelope-4", "status": "UNKNOWN",
                                                      "sufficiency": "UNKNOWN", "verdict": "not_evaluable"}}
        assert x["properties"]["anchor_inclusion"] == "NOT_CHECKED"
    for case in HISTORY_CASES:
        for x in case["expected"]["exchanges"]:
            assert x["requirements"]["r-deal-steps"]["verdict"] == "not_evaluable"


def test_refusal_to_another_requester():
    (case,) = [c for c in CASES if "definition" not in c["inputs"]]
    inp = case["inputs"]
    result = verifier(case).verify([Exchange(message(inp["request"]), [message(inp["reply"])])],
                                   requirements=["r-deal-steps"])
    (r,) = result.exchanges[0].replies
    reason = json.loads(inp["reply"]["octets_text"])["reason"]
    got = {"message_type": r.message_type, "reason": reason, "properties": {p.property: p.status for p in r.properties},
           "requirements": render_requirements(r.requirements), "claim": {"evidence": r.evidence, "proofs": r.proofs}}
    assert got == case["expected"]
    assert json.loads(inp["request"]["octets_text"])["derivation"] == sha(
        jcs(HISTORY_CASES[0]["inputs"]["definition"]))
    assert inp["requester"] != HISTORY_CASES[0]["inputs"]["definition"]["recipient"]


# The rows of §6.4's mutant table, in its order, and the case for each.
TABLE_CASES = [
    "mutant-step-kind-in-transit", "mutant-deal-added-to-definition", "mutant-envelope-for-deal-not-selected",
    "mutant-selected-deal-not-answered", "mutant-second-trusted-key", "mutant-deal-at-another-anchor",
    "mutant-record-kind-outside-list", "mutant-member-outside-reads", "mutant-definition-reads-widened",
]


def test_every_section_6_4_mutant_has_a_case():
    section = SPEC_TEXT.split("### 6.4", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"^\| (?!Mutant|---)(.+?) \| (.+?) \|$", section, re.M)
    assert len(rows) == len(TABLE_CASES) == 9
    by_id = {c["id"]: c for c in CASES}
    for (_, fails), cid in zip(rows, TABLE_CASES):
        named = re.match(r"(?:IP )?`(\w+)`", fails).group(1)
        assert named in by_id[cid]["expected"]["fails"], (cid, fails)


# ---------------------------------------------------------------------------
# Negative checks: each defective evaluator must disagree with some case
# ---------------------------------------------------------------------------


def _replace(prop: str, check: Callable[[Any, list[dict]], bool]) -> Evaluator:
    def evaluate(definition: Any, envs: list[dict]) -> dict:
        props = history_properties(definition, envs)
        props[prop] = "PASS" if check(definition, envs) else "FAIL"
        return props
    return evaluate


DEFECTIVE: dict[str, Evaluator] = {
    "definition_form ignores reads": _replace(
        "definition_form", lambda d, _: isinstance(d, dict) and set(d) == MEMBERS),
    "definition_binding not checked": _replace("definition_binding", lambda d, e: True),
    "selection_coverage ignores deals not selected": _replace(
        "selection_coverage", lambda d, e: all(any(x["subject"].get("correlation") == r for x in e)
                                               for r in d["selection"])),
    "selection_coverage ignores unanswered deals": _replace(
        "selection_coverage", lambda d, e: all(x["subject"].get("correlation") in d["selection"] for x in e)),
    "single_signer not checked": _replace("single_signer", lambda d, e: True),
    "single_anchor not checked": _replace("single_anchor", lambda d, e: True),
    "artifact_form allows any member": _replace(
        "artifact_form", lambda d, e: all(isinstance(x["artifact"], dict) for x in e)),
    "record_kinds allows any kind": _replace("record_kinds", lambda d, e: True),
    "artifact_form requires one stream across the History": _replace(
        "artifact_form", lambda d, e: artifact_form(e, set(d["reads"]))
        and len({x["artifact"]["evidence_stream"] for x in e}) <= 1),
    "single_anchor compared within each stream only": _replace(
        "single_anchor", lambda d, e: all(len({jcs(x["anchor"]) for x in e if x["artifact"]["evidence_stream"] == s}) == 1
                                          for s in {x["artifact"]["evidence_stream"] for x in e})),
}


def test_multi_stream_history_spans_streams_at_one_anchor():
    """§2: the positive names a different stream per deal, one holder key and one anchor that is
    no checkpoint of the run's one stream; the mixed-anchor mutant keeps the positive's definition
    and two of its exchanges byte for byte, and answers the third at another anchor."""
    by_id = {c["id"]: c for c in CASES}
    envs = [json.loads(x["reply"]["octets_text"]) for x in by_id["multi-stream-one-tick"]["inputs"]["exchanges"]]
    arts = [json.loads(base64.urlsafe_b64decode(e["artifact"] + "=" * (-len(e["artifact"]) % 4))) for e in envs]
    assert len({a["evidence_stream"] for a in arts}) == len(envs) == 3
    assert len({e["responder"] for e in envs}) == 1
    (tick,) = {e["anchor"]["digest"] for e in envs}
    assert tick not in {cp["expected_pin"] for cp in DATA["holder_stream"]["checkpoints"]}
    positive, mutant = by_id["multi-stream-one-tick"]["inputs"], by_id["mutant-multi-stream-mixed-anchor"]["inputs"]
    assert mutant["definition"] == positive["definition"]
    assert len(mutant["exchanges"]) == len(positive["exchanges"])
    kept = [x == y for x, y in zip(mutant["exchanges"], positive["exchanges"])]
    assert kept.count(False) == 1
    moved = json.loads(mutant["exchanges"][kept.index(False)]["reply"]["octets_text"])
    assert moved["anchor"]["digest"] != tick


def test_every_defective_evaluator_is_caught():
    for name, evaluate in DEFECTIVE.items():
        assert any(run_history(c, evaluate) != run_history(c) for c in HISTORY_CASES), name


def test_accepting_every_envelope_is_caught():
    """§6.2 counts only envelopes §6.1 accepted. An evaluator that counts every envelope differs."""
    def everything(case: dict) -> dict:
        exchanges = run_exchanges(case)
        envs = [x.pop("_env") for x in exchanges]
        return history_properties(case["inputs"]["definition"], envs)
    assert any(everything(c) != c["expected"]["history_properties"] for c in HISTORY_CASES)


# ---------------------------------------------------------------------------
# Reproducibility and registration
# ---------------------------------------------------------------------------


def _generate(out: Path) -> None:
    for name in HAND_WRITTEN:
        (out / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(VECTORS / name, out / name)
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(out), "--run", str(VECTORS / "responder-run.json")],
                   check=True)


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
    for name in set(_files(VECTORS)) - {"SHA256SUMS"}:  # the top-level list leaves out checksum files
        assert top[f"personal-history-basic-v0/{name}"] == sha((VECTORS / name).read_bytes()), name
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text())["corpora"]
    assert corpora["personal_history_basic_v0"] == "personal-history-basic-v0/manifest.json"
    assert "generate_personal_history_basic_v0_vectors.py" in (
        ROOT / "python" / "scripts" / "generate_all_vectors.py").read_text()


def test_does_not_import_the_generator():
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    modules = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    modules += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in modules if m.startswith("generate_")]


def test_artifact_bytes_and_values_beside_the_form_fail():
    """An Artifact is exactly the JCS of one object (§4.3), and each entry's values are in their
    forms: bytes or values a holder could re-sign but artifact_form would never read fail it."""
    (positive,) = [c for c in CASES if c["id"] == "history-basic"]
    envs = [x["_env"] for x in run_exchanges(positive)]
    octets = jcs(envs[0]["artifact"])
    assert artifact_value(octets) == envs[0]["artifact"]
    for bad in (octets + b' {"counterparty":"private value"}', octets + b" ",
                octets.replace(b'{"anchor"', b'{"anchor":"x","anchor"', 1),
                octets.replace(b'{"anchor"', b'{ "anchor"', 1)):
        assert artifact_value(bad) is None
    reads = set(positive["inputs"]["definition"]["reads"])
    assert artifact_form(envs, reads)
    for member, value in (("leaf_index", {"counterparty": "private value"}), ("leaf_index", "1"),
                          ("digest", "private value"), ("committed_at", {"counterparty": "private value"})):
        changed = copy.deepcopy(envs)
        changed[0]["artifact"]["records"][0][member] = value
        assert not artifact_form(changed, reads), member


def _resigned(case: dict, artifact: bytes) -> dict:
    """The case with its first reply's Artifact replaced, its digest recomputed and the envelope
    re-signed by the holder's test key, as a holder could."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(DATA["test_keys"]["keys"]["holder"]["seed_label"].encode()).digest())
    case = copy.deepcopy(case)
    reply = case["inputs"]["exchanges"][0]["reply"]
    env = json.loads(reply["octets_text"])
    env["artifact_digest"] = sha(artifact)
    signed = {k: env[k] for k in ("profile", "request_digest", "subject", "derivation", "anchor", "artifact_digest",
                                  "verification", "responder", "issued_at") if k in env}
    env["sig"] = key.sign(jcs(signed)).hex()
    env["artifact"] = base64.urlsafe_b64encode(artifact).rstrip(b"=").decode()
    reply["octets_text"] = jcs(env).decode()
    return case


def test_resigned_artifact_mutants_fail_artifact_form_end_to_end():
    """Each re-signed mutant passes every envelope check and fails artifact_form through the whole
    evaluation, with no evaluator error."""
    (positive,) = [c for c in CASES if c["id"] == "history-basic"]
    env = json.loads(positive["inputs"]["exchanges"][0]["reply"]["octets_text"])
    octets = base64.urlsafe_b64decode(env["artifact"] + "=" * (-len(env["artifact"]) % 4))
    assert run_history(_resigned(positive, octets))["accepted"], "re-signing the same Artifact changes nothing"
    value = json.loads(octets)

    def with_entry(member: str, v: Any) -> bytes:
        changed = copy.deepcopy(value)
        changed["records"][0][member] = v
        return jcs(changed)

    for name, bad in {
        "trailing object": octets + b'{"counterparty":"private value"}',
        "trailing space": octets + b" ",
        "duplicate member": octets.replace(b'{"anchor"', b'{"anchor":"x","anchor"', 1),
        "object in leaf_index": with_entry("leaf_index", {"counterparty": "private value"}),
        "object in a read": with_entry("committed_at", {"counterparty": "private value"}),
        "object in record_type": with_entry("record_type", {"counterparty": "private value"}),
    }.items():
        got = run_history(_resigned(positive, bad))
        assert got["exchanges"][0]["accepted"], name
        assert not got["accepted"], name
        # The whole report, as the Go test states it for the same mutants: an unreadable Artifact
        # fails record_kinds too; one whose entries are readable but malformed fails artifact_form
        # only.
        want = dict.fromkeys(got["history_properties"], "PASS")
        want["artifact_form"] = "FAIL"
        if not name.startswith("object in") or name == "object in record_type":
            want["record_kinds"] = "FAIL"
        assert got["history_properties"] == want, name
