# SPDX-License-Identifier: BSD-3-Clause
"""The reference verifier for ``evidence-interop/0`` against the conformance vectors and the
profile's worked examples.

Every case of ``vectors/interop-profile-v0/vectors.json`` is run through the library verifier
(``agent_action_capsule.interop_profile``) from its inputs alone, and the result is compared with
the case's whole ``expected`` block. Only one thing in that block is not compared: the corpus's
own labels for statements (``name``), which no verifier can know. Cases are dispatched by the
shape of their inputs, never by their id.

The verifier does not import the vector generator; ``test_verifier_imports`` scans for it.
"""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import random
import re
import socket
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from agent_action_capsule.canonical import jcs, json_digest  # noqa: E402
from agent_action_capsule.interop_profile import (  # noqa: E402
    Exchange,
    ForeignObject,
    HeldRecord,
    InteropVerifier,
    Message,
    TrustPolicy,
    VerificationPolicy,
    evaluate_acceptance,
    evaluate_lifecycle,
)
from agent_action_capsule.interop_profile import carriage as carriage_mod  # noqa: E402
from agent_action_capsule.interop_profile import cll as cll_mod  # noqa: E402
from agent_action_capsule.interop_profile import exchange as exchange_mod  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "python" / "agent_action_capsule" / "interop_profile"
DATA = json.loads((ROOT / "vectors" / "interop-profile-v0" / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
CONTRACT = DATA["contract"]["document"]
# The second set: its own contract, whose requirements carry the facts §8.3 copies.
FACTS = json.loads((ROOT / "vectors" / "interop-profile-v0-requirement-facts" / "vectors.json")
                   .read_text(encoding="utf-8"))
PROFILE_TEXT = (ROOT / "spec" / "interop-profile-v0.md").read_text(encoding="utf-8")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def octets(o: dict) -> bytes:
    return o["octets_text"].encode("utf-8") if "octets_text" in o else bytes.fromhex(o["octets_hex"])


def message(o: dict) -> Message:
    return Message(octets(o), o["media_type"])


def policies(case: dict) -> tuple[TrustPolicy, VerificationPolicy, str]:
    pins = case["pins"]
    return (TrustPolicy.from_dict(pins["trust_policy"]), VerificationPolicy.from_dict(pins["verification_policy"]),
            pins["evaluation_time"])


# ---------------------------------------------------------------------------
# Rendering the verifier's results in the corpus's expected shape
# ---------------------------------------------------------------------------


def render_requirements(reqs: dict) -> dict:
    out = {}
    for q, r in reqs.items():
        entry = {"row": r.row, "status": r.status, "sufficiency": r.sufficiency, "verdict": r.verdict}
        if r.note is not None:
            entry["note"] = r.note
        if r.applies_from is not None:
            entry["applies_from"] = r.applies_from
        if r.out_of_scope_allowed:
            entry["out_of_scope_allowed"] = True
        out[q] = entry
    return out


def render_reply(r, with_native: bool) -> dict:
    out: dict[str, Any] = {"message_type": r.message_type,
                           "properties": {p.property: p.status for p in r.properties}}
    if with_native:
        out["native_check"] = r.native_check.status if r.native_check is not None else None
    out["requirements"] = render_requirements(r.requirements)
    out["claim"] = {"evidence": r.evidence, "proofs": r.proofs}
    allowed = {tuple(x.presentation_kinds_allowed) for x in r.requirements.values() if x.presentation_kinds_allowed}
    if allowed:
        (kinds,) = allowed
        out["presentation_kinds_allowed"] = list(kinds)
    return out


def render_absence(a) -> dict:
    if a.form != "conforming":  # not an absence, so no claim (§6.4, §8.2 invariant 3)
        return {"form": a.form, "requirements": render_requirements(a.requirements)}
    return {"form": a.form, "requirements": render_requirements(a.requirements),
            "claim": {"evidence": a.evidence, "proofs": []},
            "presentation_kind_recommended": a.presentation_kind_recommended}


def run_exchange_case(case: dict, contract: dict = CONTRACT) -> dict:
    inp = case["inputs"]
    trust, vpolicy, now = policies(case)
    verifier = InteropVerifier(trust, vpolicy, now, contract=contract)
    requests = [inp["request"]] if "request" in inp else inp["requests"]
    exchanges = [Exchange(message(r)) for r in requests]
    # The corpus pairs reply i with request i where it holds several requests, else with the one.
    for i, rep in enumerate(inp["replies"]):
        exchanges[min(i, len(exchanges) - 1)].replies = [*exchanges[min(i, len(exchanges) - 1)].replies, message(rep)]
    if "absence_record" in inp:
        exchanges[0].absence_record = message(inp["absence_record"])
    relations = inp.get("requirement_relations")
    foreign = inp.get("foreign_object")
    named = inp.get("requirements") or (list(relations) if relations else ["r-record"])
    result = verifier.verify(exchanges, requirements=named,
                             requirement_relations=relations,
                             foreign_object=ForeignObject(foreign["path"], foreign["media_type"]) if foreign else None)
    out: dict[str, Any] = {}
    replies = []
    for k, ex in enumerate(result.exchanges):
        for r in ex.replies:
            rendered = render_reply(r, foreign is not None)
            if "requests" in inp:
                rendered["request_index"] = k
            replies.append(rendered)
    out["replies"] = replies
    if "request" in inp:
        out["request_digest"] = result.exchanges[0].request_digest
    else:
        out["request_digests"] = [ex.request_digest for ex in result.exchanges]
        artifacts = [r.artifact for ex in result.exchanges for r in ex.replies]
        out["artifact_octets_identical"] = len(set(artifacts)) == 1
        out["artifact_digest"] = sha(artifacts[0])
    if any(r["message_type"] == "envelope" for r in replies):
        out["set_properties"] = {"caller_invariance": result.caller_invariance.status}
    if result.exchanges[0].absence is not None:
        out["absence"] = render_absence(result.exchanges[0].absence)
    return out


def run_carriage_case(case: dict) -> dict:
    inp = case["inputs"]
    trust, vpolicy, now = policies(case)
    request = message(inp["request"])
    mt = request.media_type
    digests, classes, replies = {}, {}, []
    if "native" in inp:
        digests["native"] = sha(bytes.fromhex(inp["native"]["request_frame_hex"]))
        classes["native"] = "reply"
        replies.append(bytes.fromhex(inp["native"]["response_frame_hex"]))
    if "a2a" in inp:
        sent = carriage_mod.a2a_request_octets(inp["a2a"]["message"])
        if sent is not None:
            digests["a2a"] = sha(sent[0])
        got = carriage_mod.classify_a2a_task(inp["a2a"]["task"], mt)
        classes["a2a"] = got.outcome
        replies += got.replies
    if "mcp" in inp:
        sent = carriage_mod.mcp_request_octets(inp["mcp"]["call"])
        if sent is not None:
            digests["mcp"] = sha(sent[0])
        got = carriage_mod.classify_mcp_result(inp["mcp"]["result"], mt)
        classes["mcp"] = got.outcome
        replies += got.replies
    exchange = Exchange(request, [Message(r, mt) for r in replies],
                        message(inp["absence_record"]) if "absence_record" in inp else None)
    result = InteropVerifier(trust, vpolicy, now, contract=CONTRACT).verify([exchange], requirements=["r-record"])
    ex = result.exchanges[0]
    out: dict[str, Any] = {"request_digest": ex.request_digest, "carriage_request_digests": digests,
                           "classification": classes, "replies": [render_reply(r, False) for r in ex.replies]}
    if ex.replies:
        out["set_properties"] = {"caller_invariance": result.caller_invariance.status}
    if ex.absence is not None:
        out["absence"] = render_absence(ex.absence)
    if "manifests" in inp:
        a2a_m = inp["manifests"]["a2a_extension"]["params"]
        mcp_m = inp["manifests"]["mcp_evidence_manifest"]["structuredContent"]
        out["manifest_properties"] = {
            "a2a_extension": {"manifest_form": carriage_mod.manifest_form(a2a_m, vpolicy.profiles_implemented).status},
            "mcp_evidence_manifest": {
                "manifest_form": carriage_mod.manifest_form(mcp_m, vpolicy.profiles_implemented).status},
            "manifest_consistency": carriage_mod.manifest_consistency([a2a_m, mcp_m]).status}
    return out


def run_acceptance_case(case: dict) -> dict:
    inp = case["inputs"]
    trust, vpolicy, now = policies(case)
    enc = lambda xs: [x.encode("utf-8") for x in xs]  # noqa: E731
    res = evaluate_acceptance(CONTRACT, inp["transaction"], inp["proposer"], inp["acceptor"],
                              enc(inp["acceptance_records"]), enc(inp["execution_records"]),
                              enc(inp["acceptance_receipts"]), trust, now,
                              profiles_implemented=vpolicy.profiles_implemented)
    out: dict[str, Any] = {
        "finding": res.finding,
        "candidates": [{"record_digest": c.record_digest, "properties": {p.property: p.status for p in c.properties}}
                       for c in res.candidates],
        "receipts": [{"receipt_digest": r.receipt_digest, "properties": {p.property: p.status for p in r.properties}}
                     for r in res.receipts]}
    if res.claim_fields is not None:
        out["claim"] = res.claim_fields
    return out


def run_lifecycle_case(case: dict) -> dict:
    inp = case["inputs"]
    trust, vpolicy, now = policies(case)
    records = [HeldRecord(inp["target_record"].encode("utf-8"), "producer_record")] + \
        [HeldRecord(s.encode("utf-8"), "lifecycle_statement") for s in inp["statements"]]
    res = evaluate_lifecycle(records, trust, now, vpolicy.profiles_implemented)
    root = json_digest(json.loads(inp["target_record"]))
    d = res.display(root)
    return {
        "target_digest": root,
        "statements": [{"statement_digest": s.statement_digest,
                        "properties": {k: v.status for k, v in s.properties.items()}, "finding": s.finding}
                       for s in res.statements],
        "display": {"historical_claim": d.historical_claim, "latest_supported_state": d.latest_supported_state,
                    "forked_at": d.forked_at, "branches": d.branches, "challenges": d.challenges}}


def run_case(case: dict) -> dict:
    inp = case["inputs"]
    if "acceptance_records" in inp:
        return run_acceptance_case(case)
    if "statements" in inp:
        return run_lifecycle_case(case)
    if any(k in inp for k in ("native", "a2a", "mcp", "manifests")):
        return run_carriage_case(case)
    return run_exchange_case(case)


def comparable(expected: dict) -> dict:
    e = copy.deepcopy(expected)
    for s in e.get("statements", []):
        s.pop("name", None)
    return e


# ---------------------------------------------------------------------------
# The vectors
# ---------------------------------------------------------------------------


def test_corpus_size_and_contract_pin():
    assert DATA["count"] == len(CASES) == 53
    verifier = InteropVerifier(TrustPolicy(), VerificationPolicy(), "2026-10-12T00:00:00Z", contract=CONTRACT)
    assert verifier.contract_digest == DATA["contract"]["contract_digest"]
    assert verifier.contract_ref == DATA["contract"]["contract_ref"]
    for case in CASES:
        assert case["pins"]["contract_digest"] == verifier.contract_digest


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_verifier_reproduces_every_expected_value(case):
    assert run_case(case) == comparable(case["expected"])


def test_requirement_facts_set_pins_its_own_contract():
    contract = FACTS["contract"]["document"]
    assert FACTS["count"] == len(FACTS["cases"]) == 2
    verifier = InteropVerifier(TrustPolicy(), VerificationPolicy(), "2026-10-12T00:00:00Z", contract=contract)
    assert verifier.contract_digest == FACTS["contract"]["contract_digest"] != DATA["contract"]["contract_digest"]
    for case in FACTS["cases"]:
        assert case["pins"]["contract_digest"] == verifier.contract_digest


@pytest.mark.parametrize("case", FACTS["cases"], ids=lambda c: c["id"])
def test_verifier_reproduces_the_requirement_facts_set(case):
    """§8.3: each dated requirement's block carries applies_from, the undated one's none."""
    assert run_exchange_case(case, FACTS["contract"]["document"]) == case["expected"]
    for reply in case["expected"]["replies"]:
        dated = {q for q, b in reply["requirements"].items() if "applies_from" in b}
        assert dated == {"r-obligation-dated", "r-outcome-dated"}


def test_no_claim_from_the_verifier_breaks_the_met_rule():
    """§8.2 invariant 1 over everything the verifier produced for the corpus."""
    seen = 0
    for case in CASES:
        out = run_case(case)
        blocks = [r["requirements"] for r in out.get("replies", [])]
        if "absence" in out:
            blocks.append(out["absence"]["requirements"])
        for block in blocks:
            for r in block.values():
                seen += 1
                if r["verdict"] in ("met", "not_met"):
                    assert r["sufficiency"] == "SATISFIED"
    assert seen == 41  # the claims the corpus states


# ---------------------------------------------------------------------------
# Mutants: three checks broken in the verifier, each caught by the corpus (R4)
# ---------------------------------------------------------------------------


def _corpus_disagrees() -> list[str]:
    return [c["id"] for c in CASES if run_case(c) != comparable(c["expected"])]


def test_mutant_inclusion_path_not_checked(monkeypatch):
    """§6.2.1 step 12 skipped: every recomputed root is taken as a committed peak."""
    real = cll_mod._mmr.included_root
    monkeypatch.setattr(cll_mod._mmr, "included_root", lambda i, node, proof: b"\x00" * 32)
    assert "valid-exchange" in _corpus_disagrees()
    monkeypatch.setattr(cll_mod._mmr, "included_root", real)

    class AnyPeak(list):
        def __contains__(self, item):
            return True
    original = cll_mod._peak_list
    monkeypatch.setattr(cll_mod, "_peak_list", lambda raw: AnyPeak(original(raw)))
    assert "inclusion-proof-forged-and-signed" in _corpus_disagrees()


def test_mutant_request_binding_ignored(monkeypatch):
    """request_binding never FAILs: the wrong-request-digest and MCP re-hash cases must catch it."""
    original = InteropVerifier._envelope_properties

    def binding_skipped(self, *a, **k):
        props, material = original(self, *a, **k)
        if props["request_binding"].status == "FAIL":
            props["request_binding"] = exchange_mod.PropertyReport("request_binding", "PASS", "mutant")
        return props, material
    monkeypatch.setattr(InteropVerifier, "_envelope_properties", binding_skipped)
    assert {"wrong-request-digest", "carriage-mcp-rehashes-json"} <= set(_corpus_disagrees())


def test_mutant_is_check_read_as_supports(monkeypatch):
    """FR-28: a requirement that IS the failed check read as one it only supports."""
    original = InteropVerifier._envelope_row

    def swapped(required, contradicted, native, relation):
        return original(required, contradicted, native, "supports" if relation == "is_check" else relation)
    monkeypatch.setattr(InteropVerifier, "_envelope_row", staticmethod(swapped))
    assert _corpus_disagrees() == ["foreign-native-check-fails"]


# ---------------------------------------------------------------------------
# The worked examples of §10, §10.1 and §11.4
# ---------------------------------------------------------------------------


def _block_after(marker: str, fence: str = "```") -> str:
    start = PROFILE_TEXT.index(marker)
    open_at = PROFILE_TEXT.index(fence, start)
    body_at = PROFILE_TEXT.index("\n", open_at) + 1
    return PROFILE_TEXT[body_at:PROFILE_TEXT.index("```", body_at)].strip()


RESPONDER = "e84fed8190a6116016bf68ef2fc1780a919e9ed2d9f88efb895a954ffd7f0117"
SECTION_10_TRUST = TrustPolicy(
    responder_keys=frozenset({RESPONDER}),
    log_keys=frozenset({("https://producer.example", "evidence-stream-1",
                         "c82acf66ef2bdc106017544b91873dfbdc92f0963b099d49b0f621bedf76e2af")}))


def _section_10() -> dict:
    request_a = _block_after("**Request A, JSON binding**").encode("utf-8")
    request_b = bytes.fromhex(_block_after("**Request B, CBOR stream binding.**"))
    env_a = json.loads(_block_after("The complete response object for request A"))
    env_b = dict(env_a, issued_at="2026-10-12T00:00:06Z",
                 request_digest="ba7fee76b7afe9f3ec5ce46975865e06040492f0da733b28cbc86bd2be609d5e",
                 sig="986dca488661a2519c11d8285e6d85871f164b30c5bd9b9211df25e6038d98197684f93bcbf989ebee0f38"
                     "b596cdee757c73ee8c9db89766e9bb29ae812b810c")
    return {"request_a": request_a, "request_b": request_b, "env_a": env_a, "env_b": env_b}


def test_section_10_envelopes_refusal_and_absence():
    s = _section_10()
    assert sha(s["request_a"]) == "8620853807eecfc80e6056bb64aab0c2493aa9625a687f7780222e3b5aa0bd96"
    assert sha(s["request_b"]) == "ba7fee76b7afe9f3ec5ce46975865e06040492f0da733b28cbc86bd2be609d5e"
    # Envelope B travels over the CBOR stream binding in the profile's words, but its JSON form is
    # what §10 prints; the signature is over JCS either way (§5.1).
    verifier = InteropVerifier(SECTION_10_TRUST, VerificationPolicy(), "2026-10-12T01:00:00Z", contract=CONTRACT)
    result = verifier.verify(
        [Exchange(Message(s["request_a"], "application/json"), [Message(jcs(s["env_a"]), "application/json")]),
         Exchange(Message(s["request_a"], "application/json"), [Message(jcs(s["env_b"]), "application/json")])],
        requirements=["r-record"])
    a, b = result.exchanges[0].replies[0], result.exchanges[1].replies[0]
    assert a.status("envelope_signature") == "PASS"
    assert a.status("anchor_inclusion") == "NOT_PRESENT"  # §10: no material, so row 3
    assert a.requirements["r-record"].row == "envelope-3"
    assert (a.requirements["r-record"].status, a.requirements["r-record"].sufficiency) == ("INSUFFICIENT",) * 2
    assert b.status("envelope_signature") == "PASS" and b.status("request_binding") == "FAIL"
    assert result.caller_invariance.status == "PASS"  # one artifact digest for the pair (§6.2)

    refusal_body = json.loads(_block_after("**Refusal.** Had the responder"))
    refusal = dict(refusal_body, key_id=RESPONDER,
                   sig="b2725d52678fb9a652e9033c5c0756936b2f5567f4b94b239210f14938932fa044fc90a7962d086789add8170"
                       "397a80847cc8dcaaf5f3a455b8044e4f56d570c")
    absence = _block_after("**Absence record.**").encode("utf-8")
    result = verifier.verify(
        [Exchange(Message(s["request_a"], "application/json"), [Message(jcs(refusal), "application/json")]),
         Exchange(Message(s["request_b"], "application/cbor"), [], Message(absence, "application/json"))],
        requirements=["r-record"])
    ref = result.exchanges[0].replies[0]
    assert {p.property: p.status for p in ref.properties} == {
        "refusal_signature": "PASS", "responder_trust": "PASS", "responder_key_current": "NOT_CHECKED",
        "request_binding": "PASS", "reason_registered": "PASS", "issued_at_form": "PASS"}
    assert ref.requirements["r-record"].status == "NOT_FOUND"
    gone = result.exchanges[1].absence
    assert gone.form == "conforming"
    assert gone.evidence == [{"digest_alg": "SHA-256",
                              "digest": "82108c5666f4d2049d620cd9c799289bbb9f5f9bfe2801d7f51fd821df6848d5"}]


def _section_10_1() -> tuple[bytes, dict]:
    request_c = _block_after("**Request C, JSON binding.**").encode("utf-8")
    env_c = json.loads(_block_after("The complete response object for request C"))
    return request_c, env_c


def _verify_c(env: dict) -> Any:
    request_c, _ = _section_10_1()
    verifier = InteropVerifier(SECTION_10_TRUST, VerificationPolicy(), "2026-10-12T01:00:00Z", contract=CONTRACT)
    out = verifier.verify([Exchange(Message(request_c, "application/json"), [Message(jcs(env), "application/json")])],
                          requirements=["r-record"])
    return out.exchanges[0].replies[0], out


def test_section_10_1_pass_path_matches_the_table():
    _, env_c = _section_10_1()
    reply, out = _verify_c(env_c)
    table = {"profile_version": "PASS", "envelope_signature": "PASS", "responder_trust": "PASS",
             "issued_at_form": "PASS", "request_binding": "PASS", "subject_binding": "PASS",
             "artifact_digest": "PASS", "verification_binding": "PASS", "anchor_match": "PASS",
             "anchor_inclusion": "PASS", "responder_key_current": "NOT_CHECKED"}
    assert {p.property: p.status for p in reply.properties} == table
    assert out.caller_invariance.status == "NOT_CHECKED"
    method = next(p.method for p in reply.properties if p.property == "anchor_inclusion")
    assert method == "CLL-01 checkpoint (Ed25519) + MMR-02 inclusion + MMR-02 consistency"
    assert reply.requirements["r-record"].row == "envelope-7"
    assert reply.proofs == [{"kind": "inclusion_proof", "digest_alg": "SHA-256",
                             "digest": "013ac5a3bdff9cf62a3ea2816b3cd197151930f6dd49d67d9286f12c3c47527a"}]


def _responder_key() -> Ed25519PrivateKey:
    seed = hashlib.sha256(b"draft-mih-agent-evidence-request-00 conformance vectors: primary responder key").digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def test_section_10_1_closing_sentences():
    """"Changing any octet of the inclusion proof makes verification_binding FAIL. Re-signing the
    envelope over the changed digest instead makes anchor_inclusion FAIL at step 12." """
    _, env_c = _section_10_1()
    proof = bytearray(base64.urlsafe_b64decode(env_c["verification_content"][1] + "=="))
    proof[-1] ^= 0x01
    changed = base64.urlsafe_b64encode(bytes(proof)).decode().rstrip("=")
    env = copy.deepcopy(env_c)
    env["verification_content"][1] = changed
    reply, _ = _verify_c(env)
    assert reply.status("verification_binding") == "FAIL"
    env["verification"][1]["digest"] = sha(bytes(proof))
    body = {k: env[k] for k in exchange_mod._ENVELOPE_SIGNED if k in env}
    env["sig"] = _responder_key().sign(jcs(body)).hex()
    reply, _ = _verify_c(env)
    assert reply.status("envelope_signature") == "PASS"
    report = next(p for p in reply.properties if p.property == "anchor_inclusion")
    assert report.status == "FAIL" and report.detail.startswith("step 12")


def test_section_11_4_examples_one_request_digest():
    a2a = json.loads(re.sub(r"^.*?\n\n", "", _block_after("**Example (informative).** Request B of §10"),
                            flags=re.S))
    mcp = json.loads(_block_after("**Example (informative).** The same request B, as a `tools/call`"))
    sent_a2a = carriage_mod.a2a_request_octets(a2a["params"]["message"])
    sent_mcp = carriage_mod.mcp_request_octets(mcp["params"])
    assert sent_a2a is not None and sent_mcp is not None
    assert len(sent_a2a[0]) == 228 and sent_a2a == sent_mcp
    assert sha(sent_a2a[0]) == "ba7fee76b7afe9f3ec5ce46975865e06040492f0da733b28cbc86bd2be609d5e"


# ---------------------------------------------------------------------------
# Offline, no clock, as of the event and as of evaluation (NFR-7, FR-31)
# ---------------------------------------------------------------------------


def test_offline_the_whole_corpus_opens_no_socket(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("the verifier opened a socket")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    for case in CASES:
        run_case(case)


def test_verifier_imports():
    """Stdlib, the package's own canonical module and ``cryptography`` only: nothing from the
    vector generator, evidencebook or any other company code, and no clock or network module."""
    # An explicit allowlist (``sys.stdlib_module_names`` needs Python 3.10; CI also runs 3.9).
    allowed = {"__future__", "base64", "binascii", "collections", "dataclasses", "datetime", "hashlib", "json",
               "re", "struct", "typing", "cryptography"}
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    assert node.level == 1 or node.module == "canonical", f"{path.name}: {ast.dump(node)}"
                    continue
                names = [node.module]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                assert top in allowed, f"{path.name} imports {name}"
        text = path.read_text(encoding="utf-8")
        for needle in ("evidencebook", "generate_interop_profile_v0_vectors", ".now(", "utcnow", "today("):
            assert needle not in text, f"{path.name} mentions {needle}"
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names] + \
        [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in imported if "generate" in m or "evidencebook" in m]


def _valid_exchange() -> tuple[dict, Exchange]:
    case = next(c for c in CASES if c["id"] == "valid-exchange")
    return case, Exchange(message(case["inputs"]["request"]), [message(case["inputs"]["replies"][0])])


def test_responder_trust_is_as_of_the_envelope_not_now():
    """FR-31: a key retired after the envelope was issued still passes responder_trust, which is
    as of issued_at; a key retired before it fails."""
    case, ex = _valid_exchange()
    pin = dict(case["pins"]["trust_policy"])
    for not_after, expected in (("2026-10-12T00:30:00Z", "PASS"), ("2026-10-12T00:00:05Z", "FAIL")):
        pin["key_validity"] = {RESPONDER: {"not_after": not_after}}
        verifier = InteropVerifier(TrustPolicy.from_dict(pin), VerificationPolicy(), "2026-10-13T00:00:00Z",
                                   contract=CONTRACT)
        reply = verifier.verify([ex], requirements=["r-record"]).exchanges[0].replies[0]
        assert reply.status("responder_trust") == expected


def test_responder_key_current_only_through_the_callers_resolver():
    _, ex = _valid_exchange()
    asked = []

    def resolver(key: str, at: str) -> tuple[str, str]:
        asked.append((key, at))
        return "FAIL", "caller's revocation list"
    online = VerificationPolicy(online=True, key_status=resolver)
    reply = InteropVerifier(SECTION_10_TRUST, online, "2026-10-20T00:00:00Z", contract=CONTRACT) \
        .verify([ex], requirements=["r-record"]).exchanges[0].replies[0]
    assert asked == [(RESPONDER, "2026-10-20T00:00:00Z")]
    assert reply.status("responder_key_current") == "FAIL"
    # Not required (§7.2): it never changes the row.
    assert reply.requirements["r-record"].row == "envelope-7"
    offline = InteropVerifier(SECTION_10_TRUST, VerificationPolicy(), "2026-10-20T00:00:00Z", contract=CONTRACT)
    assert offline.verify([ex], requirements=["r-record"]).exchanges[0].replies[0] \
        .status("responder_key_current") == "NOT_CHECKED"


def test_acceptance_trust_is_as_of_evaluation():
    """§11.1.7: the acceptor key retired before the evaluation time is no longer accepted."""
    case = next(c for c in CASES if c["id"] == "acceptance-backdated-E-control")
    pin = dict(case["pins"]["trust_policy"], key_validity={case["inputs"]["acceptor"]: {"not_after": "2026-10-12T00:30:00Z"}})
    inp = case["inputs"]
    enc = lambda xs: [x.encode() for x in xs]  # noqa: E731
    res = evaluate_acceptance(CONTRACT, inp["transaction"], inp["proposer"], inp["acceptor"],
                              enc(inp["acceptance_records"]), enc(inp["execution_records"]),
                              enc(inp["acceptance_receipts"]), TrustPolicy.from_dict(pin), "2026-10-12T01:00:00Z")
    assert res.candidates[0].status("acceptance_signer_trust") == "FAIL"
    assert res.finding == "not_accepted"


def test_evaluation_time_is_required():
    with pytest.raises(ValueError):
        InteropVerifier(TrustPolicy(), VerificationPolicy(), "now")


# ---------------------------------------------------------------------------
# Hostile input: never an exception, never a stronger result
# ---------------------------------------------------------------------------


def test_mutated_replies_never_raise_and_never_reach_row_7_changed():
    case, ex = _valid_exchange()
    trust, vpolicy, now = policies(case)
    verifier = InteropVerifier(trust, vpolicy, now, contract=CONTRACT)
    original = ex.replies[0].octets
    baseline = json.loads(original)
    rng = random.Random(20261012)
    reached_row_7 = 0
    for _ in range(400):
        data = bytearray(original)
        i = rng.randrange(len(data))
        data[i] = rng.randrange(256)
        result = verifier.verify([Exchange(ex.request, [Message(bytes(data), "application/json")])],
                                 requirements=["r-record"])
        reply = result.exchanges[0].replies[0]
        if reply.message_type == "envelope" and reply.requirements["r-record"].row == "envelope-7":
            reached_row_7 += 1
            # Only a change the decoded value does not see (base64url padding bits) may keep row 7.
            changed = json.loads(bytes(data))
            assert {k: v for k, v in changed.items() if k not in ("artifact", "verification_content")} == \
                {k: v for k, v in baseline.items() if k not in ("artifact", "verification_content")}
            assert reply.artifact == base64.urlsafe_b64decode(baseline["artifact"] + "==")
    assert reached_row_7 < 40


@pytest.mark.parametrize("data", [b"", b"[]", b"null", b"{", b'{"reason": 1, "artifact_digest": 2}',
                                  b'{"artifact_digest": "x"}', b'{"reason": "no_such_subject"}',
                                  b'{"artifact_digest": "x", "profile": "evidence-interop/0", "subject": 3,'
                                  b' "anchor": [], "verification": [1], "verification_content": [2]}'])
def test_garbage_replies_are_classified_not_raised(data):
    case, ex = _valid_exchange()
    trust, vpolicy, now = policies(case)
    for mt in ("application/json", "application/cbor", "text/plain"):
        result = InteropVerifier(trust, vpolicy, now, contract=CONTRACT).verify(
            [Exchange(ex.request, [Message(data, mt)])], requirements=["r-record"])
        reply = result.exchanges[0].replies[0]
        for r in reply.requirements.values():
            assert r.row != "envelope-7" and r.verdict == "not_evaluable"


def test_duplicate_member_fails_the_signature():
    """§5.2: a reply with a duplicate member name is not well-formed; its signature property FAILs."""
    case, ex = _valid_exchange()
    text = ex.replies[0].octets.decode()
    dup = text[:-1] + ',"issued_at":"2026-10-12T00:00:11Z"}'
    trust, vpolicy, now = policies(case)
    reply = InteropVerifier(trust, vpolicy, now, contract=CONTRACT).verify(
        [Exchange(ex.request, [Message(dup.encode(), "application/json")])], requirements=["r-record"]
    ).exchanges[0].replies[0]
    assert reply.status("envelope_signature") == "FAIL"
    assert reply.requirements["r-record"].row == "envelope-2"


def test_pending_emits_no_claim():
    case, ex = _valid_exchange()
    trust, vpolicy, now = policies(case)
    result = InteropVerifier(trust, vpolicy, now, contract=CONTRACT).verify([Exchange(ex.request)],
                                                                           requirements=["r-record"])
    assert result.exchanges[0].pending and result.exchanges[0].replies == []


def test_uncertainty_on_missing_changes_only_missing_rows():
    """§8: on_missing applies to the missing rows of an abstract outcome requirement."""
    contract = copy.deepcopy(CONTRACT)
    contract["requirements"][0]["uncertainty"] = {"on_missing": "insufficient"}
    absent = next(c for c in CASES if c["id"] == "missing-evidence-recorded-absence")
    trust, vpolicy, now = policies(absent)
    ex = Exchange(message(absent["inputs"]["request"]), [], message(absent["inputs"]["absence_record"]))
    a = InteropVerifier(trust, vpolicy, now, contract=contract).verify([ex], requirements=["r-record"]) \
        .exchanges[0].absence.requirements["r-record"]
    assert (a.status, a.sufficiency, a.verdict) == ("INSUFFICIENT", "INSUFFICIENT", "not_evaluable")
    tampered = next(c for c in CASES if c["id"] == "tampered-artifact")
    ex = Exchange(message(tampered["inputs"]["request"]), [message(tampered["inputs"]["replies"][0])])
    r = InteropVerifier(trust, vpolicy, now, contract=contract).verify([ex], requirements=["r-record"]) \
        .exchanges[0].replies[0].requirements["r-record"]
    assert (r.row, r.status) == ("envelope-2", "INSUFFICIENT")


def _with_record(req: dict) -> dict:
    """The corpus contract with ``r-record`` replaced by ``req``, keeping its id."""
    contract = copy.deepcopy(CONTRACT)
    contract["requirements"][0] = {**req, "id": "r-record"}
    return contract


def test_content_evaluator_cannot_break_the_met_rule():
    case, ex = _valid_exchange()
    trust, vpolicy, now = policies(case)
    verifier = InteropVerifier(trust, vpolicy, now, contract=CONTRACT)
    ok = verifier.verify([ex], requirements=["r-record"], content_evaluator=lambda req, art, nc: ("SATISFIED", "met"))
    r = ok.exchanges[0].replies[0].requirements["r-record"]
    assert (r.status, r.sufficiency, r.verdict) == ("SATISFIED", "SATISFIED", "met")
    with pytest.raises(ValueError):
        verifier.verify([ex], requirements=["r-record"], content_evaluator=lambda req, art, nc: ("UNKNOWN", "met"))


SWITCHED = {"out_of_scope_allowed": True}  # a native outcome carrying the switch


@pytest.mark.parametrize("contract_req,status,verdict", [
    (None, "INSUFFICIENT", "met"),
    (None, "UNKNOWN", "not_met"),
    (None, "SATISFIED", "not_evaluable"),
    (None, "SATISFIED", "passed"),
    (None, "UNKNOWN", "passed"),
    (None, "SATISFIED", None),
    (None, "SATISFIED", "out_of_scope"),
    (SWITCHED, "NOT_FOUND", "out_of_scope"),
    (SWITCHED, "SATISFIED", "not_evaluable"),
])
def test_content_evaluator_verdict_must_pair(contract_req, status, verdict):
    """§8.2 invariant 1 is the full relation: SATISFIED pairs with met, not_met or, where the
    requirement carries the switch, out_of_scope; every other sufficiency pairs with not_evaluable
    only; no other verdict exists."""
    case, ex = _valid_exchange()
    trust, vpolicy, now = policies(case)
    contract = CONTRACT if contract_req is None else _with_record(contract_req)
    with pytest.raises(ValueError, match="§8.2 invariant 1"):
        InteropVerifier(trust, vpolicy, now, contract=contract).verify(
            [ex], requirements=["r-record"], content_evaluator=lambda req, art, nc: (status, verdict))


@pytest.mark.parametrize("status,verdict", [
    ("SATISFIED", "met"), ("SATISFIED", "not_met"), ("SATISFIED", "out_of_scope"),
    ("NOT_FOUND", "not_evaluable"), ("INSUFFICIENT", "not_evaluable"), ("UNKNOWN", "not_evaluable"),
])
def test_content_evaluator_verdicts_that_pair(status, verdict):
    case, ex = _valid_exchange()
    trust, vpolicy, now = policies(case)
    r = InteropVerifier(trust, vpolicy, now, contract=_with_record(SWITCHED)).verify(
        [ex], requirements=["r-record"], content_evaluator=lambda req, art, nc: (status, verdict)
    ).exchanges[0].replies[0].requirements["r-record"]
    assert (r.status, r.verdict, r.out_of_scope_allowed) == (status, verdict, True)


@pytest.mark.parametrize("req,applies_from,allowed", [
    (None, None, False),
    ({"profile": "obligation", "evidence_rule": {}, "clause": {"effective_from": "2027-08-02"}}, "2027-08-02", False),
    ({"clause": {"effective_from": "2028-02-29"}}, "2028-02-29", False),
    ({"profile": "outcome", "clause": {"effective_from": "2027-08-02"}}, "2027-08-02", False),
    (SWITCHED, None, True),
    ({"profile": "obligation", "evidence_rule": {}, "out_of_scope_allowed": True}, None, True),
    ({"out_of_scope_allowed": False}, None, False),
    ({"out_of_scope_allowed": "true"}, None, False),
    ({"profile": "process", "out_of_scope_allowed": True}, None, False),
    ({"profile": "outcome", "out_of_scope_allowed": True}, None, False),
])
def test_requirement_facts_are_copied(req, applies_from, allowed):
    """§8.3: the claim carries the requirement's effective_from as applies_from, whatever its shape,
    and a native requirement's out_of_scope_allowed. The same member on an open stub or an
    abstract shape grants nothing."""
    case, ex = _valid_exchange()
    trust, vpolicy, now = policies(case)
    verifier = InteropVerifier(trust, vpolicy, now, contract=CONTRACT if req is None else _with_record(req))
    r = verifier.verify([ex], requirements=["r-record"]).exchanges[0].replies[0].requirements["r-record"]
    assert (r.status, r.verdict) == ("UNKNOWN", "not_evaluable")
    assert (r.applies_from, r.out_of_scope_allowed) == (applies_from, allowed)
    claim = r.claim()
    assert claim.get("applies_from") == applies_from and ("applies_from" in claim) == (applies_from is not None)
    assert claim.get("out_of_scope_allowed") == (True if allowed else None)
    if allowed:
        verifier.verify([ex], requirements=["r-record"],
                        content_evaluator=lambda q, art, nc: ("SATISFIED", "out_of_scope"))
    else:
        with pytest.raises(ValueError, match="§8.2 invariant 1"):
            verifier.verify([ex], requirements=["r-record"],
                            content_evaluator=lambda q, art, nc: ("SATISFIED", "out_of_scope"))


def test_out_of_scope_follows_each_requirements_switch():
    """§8.2 invariant 1 per requirement: in one contract, out_of_scope is accepted on the switched-on
    native requirement and refused on the unswitched one beside it. A pairing failure fails the
    whole run, so this takes two runs."""
    native = {"statement": "s", "evidence_rule": "e", "forward_verdict": "DETERMINISTIC",
              "backward_verdict": "DETERMINISTIC"}
    contract = copy.deepcopy(CONTRACT)
    contract["requirements"][0] = {**native, "id": "r-record", "out_of_scope_allowed": True}
    contract["requirements"][1] = {**native, "id": "r-carried-signature"}
    case, ex = _valid_exchange()
    trust, vpolicy, now = policies(case)
    verifier = InteropVerifier(trust, vpolicy, now, contract=contract)
    ids = ["r-record", "r-carried-signature"]
    mixed = verifier.verify([ex], requirements=ids, content_evaluator=lambda q, art, nc: (
        "SATISFIED", "out_of_scope" if q["id"] == "r-record" else "met"))
    got = mixed.exchanges[0].replies[0].requirements
    assert (got["r-record"].verdict, got["r-record"].out_of_scope_allowed) == ("out_of_scope", True)
    assert (got["r-carried-signature"].verdict, got["r-carried-signature"].out_of_scope_allowed) == ("met", False)
    with pytest.raises(ValueError, match="r-carried-signature.*§8.2 invariant 1"):
        verifier.verify([ex], requirements=ids, content_evaluator=lambda q, art, nc: ("SATISFIED", "out_of_scope"))


@pytest.mark.parametrize("bad", ["2027-02-30", "2027-13-01", "2027-2-03", "20270203", "2027-02-03T00:00:00Z",
                                 "0000-01-01", "２０２７-02-03", 20270203, None])
def test_non_calendar_effective_from_is_not_evaluated(bad):
    """§11.3.7: an effective_from that is not a calendar date means the contract version is not
    evaluated, the same as two requirements sharing an id."""
    for profile in ({}, {"profile": "process"}):
        with pytest.raises(ValueError, match="not a calendar date"):
            InteropVerifier(TrustPolicy(), VerificationPolicy(), "2026-10-12T00:00:00Z",
                            contract=_with_record({**profile, "clause": {"effective_from": bad}}))


def test_duplicate_requirement_ids_are_not_evaluated():
    contract = copy.deepcopy(CONTRACT)
    contract["requirements"].append(dict(contract["requirements"][0]))
    with pytest.raises(ValueError):
        InteropVerifier(TrustPolicy(), VerificationPolicy(), "2026-10-12T00:00:00Z", contract=contract)


# ---------------------------------------------------------------------------
# §6.2.1 step by step, from the §10.1 bytes re-signed with the public test seeds. The corpus
# exercises steps 2, 4 and 12; these cover the others, each asserting which step decides.
# ---------------------------------------------------------------------------


def _log_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"evidence-interop/0 worked example: CLL log key").digest())


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _rebuild_c(checkpoint=None, consistency=None, entries=None, coverage=None, record=None, freshness=None,
               resign_checkpoint=True, derivation=None):
    """Envelope C of §10.1 with one thing changed, every digest recomputed and every signature
    remade, so that only the change can decide ``anchor_inclusion``."""
    cbor2 = pytest.importorskip("cbor2")
    _, env = _section_10_1()
    env = copy.deepcopy(env)
    items = [base64.urlsafe_b64decode(x + "==") for x in env["verification_content"]]
    tag = cbor2.loads(items[0])
    protected, unprotected, payload, signature = tag.value
    prot, claims = cbor2.loads(protected), cbor2.loads(payload)
    if checkpoint is not None:
        unprotected = checkpoint(prot, claims, unprotected) or unprotected
    protected, payload = cbor2.dumps(prot, canonical=True), cbor2.dumps(claims, canonical=True)
    if resign_checkpoint:
        signature = _log_key().sign(cbor2.dumps(["Signature1", protected, b"", payload]))
    else:
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    items[0] = cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, payload, signature]), canonical=True)
    if consistency is not None:
        items[2] = consistency(cbor2, items[2])
    kinds = ["cll-checkpoint", "cll-inclusion-proof", "cll-consistency-proof"]
    pairs = list(zip(kinds, items))
    if entries is not None:
        pairs = entries(pairs)
    env["verification"] = [{"digest": sha(x), "kind": k} for k, x in pairs]
    env["verification_content"] = [_b64u(x) for _, x in pairs]
    env["anchor"] = {"digest": sha(items[0])}
    if freshness is not None:
        env["anchor"]["freshness"] = freshness
    request = {"coverage": coverage or {"expected_pin": env["anchor"]["digest"]}, "nonce": "rebuilt",
               "profile": "evidence-interop/0", "subject": {"record": record or env["artifact_digest"]}}
    env["subject"] = request["subject"]
    if derivation is not None:
        request["derivation"] = env["derivation"] = derivation
    request_octets = jcs(request)
    env["request_digest"] = sha(request_octets)
    env["sig"] = _responder_key().sign(jcs({k: env[k] for k in exchange_mod._ENVELOPE_SIGNED if k in env})).hex()
    verifier = InteropVerifier(SECTION_10_TRUST, VerificationPolicy(), "2026-10-12T01:00:00Z", contract=CONTRACT)
    reply = verifier.verify([Exchange(Message(request_octets, "application/json"),
                                      [Message(jcs(env), "application/json")])], requirements=["r-record"]
                            ).exchanges[0].replies[0]
    return reply, next(p for p in reply.properties if p.property == "anchor_inclusion")


def _set(d, k, v):
    d[k] = v


@pytest.mark.parametrize("change, status, step", [
    ({}, "PASS", "steps 1 to 14"),
    ({"derivation": "33" * 32}, "NOT_CHECKED", "step 1"),
    ({"entries": lambda p: p + [p[1]]}, "FAIL", "step 3"),
    ({"entries": lambda p: p + [("cll-witness", b"\x00")]}, "NOT_CHECKED", "step 3"),
    ({"entries": lambda p: [p[0], p[2]]}, "NOT_PRESENT", "step 3"),
    ({"record": "11" * 32}, "NOT_CHECKED", "step 5"),
    ({"checkpoint": lambda h, c, u: {4: b"x"}}, "FAIL", "step 7"),
    ({"checkpoint": lambda h, c, u: _set(c, "kind", "other")}, "FAIL", "step 7"),
    ({"checkpoint": lambda h, c, u: _set(c, "prev_size", 9)}, "FAIL", "step 7"),
    ({"checkpoint": lambda h, c, u: _set(h, 2, [99])}, "NOT_CHECKED", "step 8"),
    ({"checkpoint": lambda h, c, u: _set(h, 1, -7)}, "NOT_CHECKED", "step 8"),
    ({"checkpoint": lambda h, c, u: _set(h[15], 1, "https://other.example")}, "FAIL", "step 9"),
    ({"resign_checkpoint": False}, "FAIL", "step 10"),
    ({"coverage": {"min_freshness": 5}, "freshness": 7}, "PASS", "steps 1 to 14"),
    ({"coverage": {"min_freshness": 5}, "freshness": 6}, "FAIL", "step 11"),
    ({"coverage": {"min_freshness": "2026-10-11T00:00:00Z"}, "freshness": "2026-10-12T00:00:00Z"}, "PASS",
     "steps 1 to 14"),
    ({"coverage": {"min_freshness": "2026-10-11T00:00:00Z"}, "freshness": "2026-10-12T00:00:01Z"}, "FAIL",
     "step 11"),
    ({"consistency": lambda cbor2, raw: cbor2.dumps(cbor2.loads(raw)[:3] + [cbor2.loads(raw)[3][::-1]])},
     "FAIL", "step 13"),
    ({"consistency": lambda cbor2, raw: cbor2.dumps([5] + cbor2.loads(raw)[1:])}, "FAIL", "step 13"),
])
def test_anchor_inclusion_each_step_decides(change, status, step):
    _, report = _rebuild_c(**change)
    assert report.status == status
    assert report.detail.startswith(step), report.detail


def test_anchor_not_the_checkpoint_fails_step_6():
    """Step 6: the cll-checkpoint entry must be the anchor. Not in the corpus; this kills the
    mutant that drops the comparison."""
    reply, report = _rebuild_c(checkpoint=None)
    assert report.status == "PASS"
    _, env = _section_10_1()
    env = copy.deepcopy(env)
    other = "22" * 32
    env["anchor"] = {"digest": other}
    request = {"coverage": {"expected_pin": other}, "nonce": "step 6", "profile": "evidence-interop/0",
               "subject": env["subject"]}
    env["request_digest"] = sha(jcs(request))
    env["sig"] = _responder_key().sign(jcs({k: env[k] for k in exchange_mod._ENVELOPE_SIGNED if k in env})).hex()
    verifier = InteropVerifier(SECTION_10_TRUST, VerificationPolicy(), "2026-10-12T01:00:00Z", contract=CONTRACT)
    reply = verifier.verify([Exchange(Message(jcs(request), "application/json"), [Message(jcs(env), "application/json")])],
                            requirements=["r-record"]).exchanges[0].replies[0]
    assert reply.status("anchor_match") == "PASS"
    report = next(p for p in reply.properties if p.property == "anchor_inclusion")
    assert (report.status, report.detail[:6]) == ("FAIL", "step 6")


# ---------------------------------------------------------------------------
# Poison: every member of every input family replaced by values of the wrong type. The verifier
# must classify or fail each one; it must never raise. (Cold-read B1, B2.)
# ---------------------------------------------------------------------------

POISON = [[1], {"k": [1]}, None, True, -1, 2**60, "x", ""]


def _poisoned(obj: Any):
    """Each variant of ``obj`` with one member (at any depth) replaced by one poison value."""
    if isinstance(obj, dict):
        for k in list(obj):
            for p in POISON:
                yield {**obj, k: p}
            for sub in _poisoned(obj[k]):
                yield {**obj, k: sub}
    elif isinstance(obj, list):
        for i in range(len(obj)):
            for p in POISON:
                yield obj[:i] + [p] + obj[i + 1:]
            for sub in _poisoned(obj[i]):
                yield obj[:i] + [sub] + obj[i + 1:]


def _json(o: Any) -> bytes:
    return json.dumps(o).encode()


def test_poisoned_cbor_envelopes_never_raise():
    cbor2 = pytest.importorskip("cbor2")
    case = next(c for c in CASES if c["id"] == "carriage-invariance")
    trust, vpolicy, now = policies(case)
    verifier = InteropVerifier(trust, vpolicy, now, contract=CONTRACT)
    request = message(case["inputs"]["request"])
    env = cbor2.loads(bytes.fromhex(case["inputs"]["native"]["response_frame_hex"]))
    variants = list(_poisoned(env)) + [{**env, 1: 2}, {**env, "derivation": {1: "x"}}, {**env, "reason": {1: 2}}]
    for v in variants:
        raw = cbor2.dumps(v)
        result = verifier.verify([Exchange(request, [Message(raw, "application/cbor")] * 2)], requirements=["r-record"])
        for r in result.exchanges[0].replies:
            for q in r.requirements.values():
                assert q.row != "envelope-7" or r.status("envelope_signature") == "PASS"
    absence = cbor2.dumps({1: 2})
    verifier.verify([Exchange(request, [], Message(absence, "application/cbor"))], requirements=["r-record"])


def test_poisoned_acceptance_inputs_never_raise():
    case = next(c for c in CASES if c["id"] == "acceptance-backdated-E-control")
    inp = case["inputs"]
    trust, vpolicy, now = policies(case)
    records = [json.loads(t) for t in inp["acceptance_records"]]
    receipts = [json.loads(t) for t in inp["acceptance_receipts"]]
    execs = [json.loads(t) for t in inp["execution_records"]]
    enc = lambda xs: [_json(x) for x in xs]  # noqa: E731
    for i, rec in enumerate(records):
        for v in _poisoned(rec):
            res = evaluate_acceptance(CONTRACT, inp["transaction"], inp["proposer"], inp["acceptor"],
                                      enc(records[:i] + [v] + records[i + 1:]), enc(execs), enc(receipts), trust, now)
            assert res.finding in ("not_accepted", "accepted_before_action", "accepted_execution_cites")
    for v in _poisoned(receipts[0]):
        evaluate_acceptance(CONTRACT, inp["transaction"], inp["proposer"], inp["acceptor"], enc(records),
                            enc(execs), enc([v]), trust, now)
    for v in _poisoned(execs[0]):
        res = evaluate_acceptance(CONTRACT, inp["transaction"], inp["proposer"], inp["acceptor"], enc(records),
                                  enc([v]), enc(receipts), trust, now)
        # A changed execution record carries no valid signature, so it gives no time for the
        # action and cannot support the ordering.
        assert res.finding != "accepted_before_action"


def test_poisoned_lifecycle_statements_never_raise():
    case = next(c for c in CASES if c["id"] == "lifecycle-H-non-issuer-disputes")
    inp = case["inputs"]
    trust, vpolicy, now = policies(case)
    target = HeldRecord(inp["target_record"].encode(), "producer_record")
    root = json_digest(json.loads(inp["target_record"]))
    for v in _poisoned(json.loads(inp["statements"][0])):
        res = evaluate_lifecycle([target, HeldRecord(_json(v), "lifecycle_statement")], trust, now)
        res.display(root)
        assert all(s.finding != "lifecycle_effective" for s in res.statements)


def test_poisoned_carriage_wrappers_never_raise():
    case = next(c for c in CASES if c["id"] == "carriage-invariance")
    inp = case["inputs"]
    no_reply = {k: v for k, v in inp["a2a"]["task"].items() if k != "artifacts"}
    for v in list(_poisoned(inp["a2a"]["task"])) + list(_poisoned(no_reply)) + [[1], "x", None]:
        carriage_mod.classify_a2a_task(v, "application/cbor")
    for v in list(_poisoned(inp["a2a"]["message"])) + [[1], None]:
        carriage_mod.a2a_request_octets(v)
    for v in list(_poisoned(inp["mcp"]["result"])) + [[1], None]:
        carriage_mod.classify_mcp_result(v, "application/cbor")
    for v in list(_poisoned(inp["mcp"]["call"])) + [[1], None]:
        carriage_mod.mcp_request_octets(v)
    manifest = inp["manifests"]["a2a_extension"]["params"]
    implemented = frozenset({"evidence-interop/0"})
    for v in _poisoned(manifest):
        carriage_mod.manifest_form(v, implemented)
        carriage_mod.manifest_consistency([manifest, v])
    for bad in ({**manifest, "refusal_policy": ["uniform"]}, {**manifest, "retention": ["a"]},
                {**manifest, "drafts": [1]}, {**manifest, "profiles": "evidence-interop/0"}):
        assert carriage_mod.manifest_form(bad, implemented).status == "FAIL"


# ---------------------------------------------------------------------------
# Regressions from the cold read
# ---------------------------------------------------------------------------


def _acceptance_with(case_id: str, exec_changes=None, extra_execs=(), trust_pin=None, receipts=None):
    case = next(c for c in CASES if c["id"] == case_id)
    inp = case["inputs"]
    pin = trust_pin or case["pins"]["trust_policy"]
    keys = {"Q": "evidence-interop/0 conformance vectors: key Q", "P": "evidence-interop/0 conformance vectors: key P",
            "I": "evidence-interop/0 conformance vectors: key I"}

    def signer(label: str) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(keys[label].encode()).digest())

    def signed(label: str, body: dict) -> bytes:
        body = {k: v for k, v in body.items() if k != "sig"}
        return jcs({**body, "sig": signer(label).sign(jcs(body)).hex()})

    execs = []
    for t in inp["execution_records"]:
        e = json.loads(t)
        if exec_changes:
            e = signed("Q", {**e, **exec_changes})
        else:
            e = t.encode()
        execs.append(e)
    for label, body in extra_execs:
        execs.append(signed(label, body))
    rcpts = inp["acceptance_receipts"] if receipts is None else receipts(signed, json.loads(inp["acceptance_receipts"][0]))
    rcpts = [r.encode() if isinstance(r, str) else r for r in rcpts]
    return evaluate_acceptance(CONTRACT, inp["transaction"], inp["proposer"], inp["acceptor"],
                               [t.encode() for t in inp["acceptance_records"]], execs, rcpts,
                               TrustPolicy.from_dict(pin), case["pins"]["evaluation_time"])


def test_b3_action_time_is_rounded_down_before_rule_2():
    """§11.1.5: an action at 00:05:00.5 is 00:05:00, which the record's issued_at is not before."""
    res = _acceptance_with("acceptance-backdated-E-control",
                           receipts=lambda signed, rc: [signed("P", {**rc, "received_at": "2026-10-12T00:04:59Z"})],
                           exec_changes={"action_at": "2026-10-12T00:05:00.5Z"})
    assert res.candidates[0].status("acceptance_ordering") == "FAIL"
    assert res.finding == "accepted_after_action"


def test_n4_fractional_receipt_time_is_rounded_up_not_dropped():
    res = _acceptance_with("acceptance-backdated-E-control",
                           receipts=lambda signed, rc: [signed("P", {**rc, "received_at": "2026-10-12T00:09:59.2Z"})])
    assert res.candidates[0].status("acceptance_ordering") == "INCONCLUSIVE"  # 00:10:00 is not before 00:10:00
    res = _acceptance_with("acceptance-backdated-E-control",
                           receipts=lambda signed, rc: [signed("P", {**rc, "received_at": "2026-10-12T00:09:58.2Z"})])
    assert res.candidates[0].status("acceptance_ordering") == "PASS"


def test_s1_a_second_key_of_the_acceptor_gives_its_own_time():
    """A record by a key the policy maps to the acceptor's party is the acceptor's own claim:
    its earlier time makes the backdated acceptance self-admitted (rule 2)."""
    case = next(c for c in CASES if c["id"] == "acceptance-backdated-E-control")
    pin = copy.deepcopy(case["pins"]["trust_policy"])
    i_key = DATA["test_keys"]["keys"]["I"]["public"]
    pin["parties"][i_key] = pin["parties"][case["inputs"]["acceptor"]]
    first = json.loads(case["inputs"]["execution_records"][0])
    res = _acceptance_with("acceptance-backdated-E-control", trust_pin=pin,
                           extra_execs=[("I", {**first, "issuer": i_key, "action_at": "2026-10-12T00:01:00Z"})])
    assert res.candidates[0].status("acceptance_ordering") == "FAIL"
    assert res.finding == "accepted_after_action"


def test_s2_another_partys_attestation_is_a_time_not_an_execution_record():
    case = next(c for c in CASES if c["id"] == "acceptance-backdated-G-policy-requires-other-party")
    pin = copy.deepcopy(case["pins"]["trust_policy"])
    i_key = DATA["test_keys"]["keys"]["I"]["public"]
    pin["parties"][i_key] = "party-witness"
    first = json.loads(case["inputs"]["execution_records"][0])
    res = _acceptance_with("acceptance-backdated-G-policy-requires-other-party", trust_pin=pin,
                           extra_execs=[("I", {**first, "issuer": i_key, "links": [], "action_at": "2026-10-12T00:12:00Z"})])
    assert res.candidates[0].status("execution_cites_acceptance") == "PASS"
    assert res.candidates[0].status("acceptance_ordering") == "PASS"  # receipt 00:06 < action 00:10
    assert res.finding == "accepted_before_action"


def test_b4_is_check_without_a_native_result_is_unknown():
    case = next(c for c in CASES if c["id"] == "foreign-native-check-passes")
    inp = case["inputs"]
    trust, vpolicy, now = policies(case)
    verifier = InteropVerifier(trust, vpolicy, now, contract=CONTRACT)
    result = verifier.verify([Exchange(message(inp["request"]), [message(inp["replies"][0])])],
                             requirements=list(inp["requirement_relations"]),
                             requirement_relations=inp["requirement_relations"],
                             foreign_object=ForeignObject(inp["foreign_object"]["path"], "application/x-unknown"),
                             content_evaluator=lambda req, art, nc: ("SATISFIED", "met"))
    reply = result.exchanges[0].replies[0]
    assert reply.native_check.status == "NOT_CHECKED"
    r = reply.requirements["r-carried-signature"]
    assert (r.status, r.sufficiency, r.verdict) == ("UNKNOWN", "UNKNOWN", "not_evaluable")


def test_s3_a2a_replies_without_ids_are_each_a_reply():
    case = next(c for c in CASES if c["id"] == "carriage-a2a-two-artifacts")
    task = copy.deepcopy(case["inputs"]["a2a"]["task"])
    for a in task["artifacts"]:
        del a["artifactId"]
    assert len(carriage_mod.classify_a2a_task(task, "application/cbor").replies) == 2
    same = copy.deepcopy(case["inputs"]["a2a"]["task"])
    same["artifacts"][1]["artifactId"] = same["artifacts"][0]["artifactId"]
    got = carriage_mod.classify_a2a_task(same, "application/cbor")
    assert len(got.replies) == 2 and got.rejected
    again = copy.deepcopy(case["inputs"]["a2a"]["task"])
    again["artifacts"][1] = again["artifacts"][0]
    assert len(carriage_mod.classify_a2a_task(again, "application/cbor").replies) == 1


def test_s4_an_early_absence_record_is_pending_not_a_claim():
    case = next(c for c in CASES if c["id"] == "missing-evidence-recorded-absence")
    trust, vpolicy, now = policies(case)
    rec = json.loads(case["inputs"]["absence_record"]["octets_text"])
    rec["recorded_at"] = "2026-10-12T00:01:00Z"  # before window.closed
    result = InteropVerifier(trust, vpolicy, now, contract=CONTRACT).verify(
        [Exchange(message(case["inputs"]["request"]), [], Message(jcs(rec), "application/json"))],
        requirements=["r-record"])
    ex = result.exchanges[0]
    assert ex.absence.form == "not_conforming" and ex.absence.requirements == {} and ex.pending


def test_n1_contract_number_outside_the_domain_gets_no_digest():
    contract = copy.deepcopy(CONTRACT)
    contract["requirements"][2]["robustness"] = -1
    with pytest.raises(ValueError):
        InteropVerifier(TrustPolicy(), VerificationPolicy(), "2026-10-12T00:00:00Z", contract=contract)
    dup = copy.deepcopy(CONTRACT)
    dup["requirements"].append(dict(dup["requirements"][0]))
    with pytest.raises(ValueError):
        evaluate_acceptance(dup, {"scheme": "example", "id": "T"}, "00" * 32, "11" * 32, [], [], [], TrustPolicy(),
                            "2026-10-12T00:00:00Z")
