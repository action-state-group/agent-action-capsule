# SPDX-License-Identifier: BSD-3-Clause
"""The draft-mih-agent-evidence-request vectors are reproducible and self-consistent.

These checks do not implement the interaction. They re-run the generator and
require byte-identical output, check every hash the vectors pin, decode each
CBOR frame with an independent encoder, verify each signed refusal against its
stated expectation, and confirm every cited section exists in the revision the
corpus names.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import cbor2
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agent_action_capsule import evidence_request as er

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "evidence-request"
GENERATOR = ROOT / "python" / "scripts" / "generate_evidence_request_vectors.py"
SPEC = ROOT / "spec"
HAND_WRITTEN = ("README.md", "DIFFS.md")
CORPORA = ("request", "resolution", "carries", "categories", "carriage", "digest", "refusal", "outcomes",
           "invariance", "retention", "unavailable-window", "refusal-02")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load(name: str) -> dict:
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))


def _all_cases() -> list[tuple[str, dict]]:
    return [(name, case) for name in CORPORA for case in _load(name)["cases"]]


REGISTRY = _load("registry")


def test_generator_reproduces_every_file_byte_for_byte(tmp_path):
    for name in HAND_WRITTEN:
        shutil.copyfile(VECTORS / name, tmp_path / name)
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(tmp_path)], check=True)
    committed = sorted(p.name for p in VECTORS.iterdir() if p.is_file())
    regenerated = sorted(p.name for p in tmp_path.iterdir() if p.is_file())
    assert regenerated == committed
    for name in committed:
        assert (tmp_path / name).read_bytes() == (VECTORS / name).read_bytes(), name


def test_sha256sums_and_manifest_pin_every_file():
    listed = {}
    for line in (VECTORS / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        listed[name] = digest
    on_disk = {p.name for p in VECTORS.iterdir() if p.is_file() and p.name != "SHA256SUMS"}
    assert set(listed) == on_disk
    for name, digest in listed.items():
        assert _sha((VECTORS / name).read_bytes()) == digest, name
    manifest = _load("manifest")
    generated = {p.name for p in VECTORS.glob("*.json")} - {"manifest.json"}
    assert {f["path"] for f in manifest["files"]} == generated
    for entry in manifest["files"]:
        assert _sha((VECTORS / entry["path"]).read_bytes()) == entry["sha256"], entry["path"]


def test_top_level_sha256sums_registers_the_directory():
    top = (ROOT / "vectors" / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    entries = dict(reversed(line.split("  ", 1)) for line in top)
    for path in VECTORS.iterdir():
        rel = f"evidence-request/{path.name}"
        if path.name != "SHA256SUMS":
            assert entries.get(rel) == _sha(path.read_bytes()), rel
    assert json.loads((ROOT / "vectors" / "manifest.json").read_text())["corpora"]["evidence_request"] == (
        "evidence-request/manifest.json"
    )


def test_case_structure_ids_and_counts():
    seen = set()
    for name in CORPORA:
        corpus = _load(name)
        assert corpus["provenance"] == "spec-derived"
        assert corpus["count"] == len(corpus["cases"])
        for case in corpus["cases"]:
            assert set(case) >= {"id", "section", "description", "expect"}, case.get("id")
            assert case["id"] not in seen, case["id"]
            seen.add(case["id"])
            assert case["section"] and all(s.startswith("§") for s in case["section"])


def _draft_headings(draft: str) -> dict[str, str]:
    headings = {}
    for line in (SPEC / f"{draft}.txt").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^(\d+(?:\.\d+)*)\.  (\S.*?)\s*$", line)
        if m:
            headings[m.group(1)] = m.group(2)
    return headings


def test_every_cited_section_exists_in_the_draft():
    cited = {(REGISTRY["draft"], ref) for ref in REGISTRY["section"]}
    for name in CORPORA:
        corpus = _load(name)
        cited.update((corpus["draft"], ref) for case in corpus["cases"] for ref in case["section"])
    drafts = {draft for draft, _ in cited}
    assert drafts == {"draft-mih-agent-evidence-request-00", "draft-mih-agent-evidence-request-01",
                      "draft-mih-agent-evidence-request-02"}
    headings = {draft: _draft_headings(draft) for draft in drafts}
    for draft, ref in cited:
        m = re.match(r"^§(\d+(?:\.\d+)*) (.+)$", ref)
        assert m, ref
        assert headings[draft].get(m.group(1)) == m.group(2), (draft, ref)


def test_readme_lists_every_case_and_ambiguity():
    readme = (VECTORS / "README.md").read_text(encoding="utf-8")
    for _, case in _all_cases():
        assert f"`{case['id']}`" in readme, case["id"]
    for key in _load("manifest")["ambiguities"]:
        assert f"**{key}**" in readme, key


def test_registry_pins_the_draft_tokens():
    assert REGISTRY["refusal_reasons"] == [
        "not_authorized", "no_such_subject", "coverage_unsatisfiable", "derivation_unsupported",
        "policy_declined", "deadline_unmet", "request_malformed", "retention_expired",
    ]
    assert REGISTRY["subject_forms"] == ["full_history", "checkpoints", "record", "range", "correlation", "exchange"]
    assert REGISTRY["coverage_members"] == ["expected_pin", "min_freshness"]
    assert REGISTRY["subprotocol"] == "evidence-request/1"
    assert not set(REGISTRY["not_registered_examples"]) & set(REGISTRY["refusal_reasons"])


def _cbor_well_formed(raw: bytes):
    try:
        return True, cbor2.loads(raw)
    except Exception:  # noqa: BLE001 - any decode failure means not well formed
        return False, None


def _json_value(text: str):
    try:
        return True, json.loads(text)
    except ValueError:
        return False, None


@pytest.mark.parametrize("corpus", ["request", "resolution", "categories"])
def test_request_digests_and_cbor_frames(corpus):
    rfc8785 = pytest.importorskip("rfc8785")
    cases = [case for case in _load(corpus)["cases"] if "request_json" in case]
    # categories.json also holds invariance cases; only its request cases are frames.
    assert len(cases) >= 10, corpus
    for case in cases:
        text = case["request_json"]
        assert _sha(text.encode("utf-8")) == case["request_json_digest"], case["id"]
        ok_json, value = _json_value(text)
        if ok_json:
            assert rfc8785.dumps(value) == text.encode("utf-8"), case["id"]
        if "request_cbor_hex" not in case:
            continue
        raw = bytes.fromhex(case["request_cbor_hex"])
        assert _sha(raw) == case["request_cbor_digest"], case["id"]
        ok_cbor, decoded = _cbor_well_formed(raw)
        assert ok_cbor == ok_json, case["id"]
        if ok_cbor:
            assert decoded == value, case["id"]
            assert cbor2.dumps(decoded, canonical=True) == raw, case["id"]


def test_well_formed_requests_carry_the_required_members():
    for case in _load("request")["cases"]:
        ok, value = _json_value(case["request_json"])
        expect = case["expect"]
        if expect["well_formed"]:
            assert ok and isinstance(value, dict) and {"subject", "coverage"} <= set(value), case["id"]
            assert len(value["coverage"]) == 1 and set(value["coverage"]) <= set(REGISTRY["coverage_members"])
            assert len(value["subject"]) == 1 and set(value["subject"]) <= set(REGISTRY["subject_forms"])
        else:
            assert expect["reason"] in REGISTRY["refusal_reasons"], case["id"]


def test_digest_cases():
    for case in _load("digest")["cases"]:
        if "encoding" in case:
            raw = (case["request_json"].encode("utf-8") if case["encoding"] == "json"
                   else bytes.fromhex(case["request_cbor_hex"]))
            assert _sha(raw) == case["expect"]["request_digest"], case["id"]
            if case["encoding"] == "cbor":
                canonical = cbor2.dumps(cbor2.loads(raw), canonical=True)
                assert (canonical == raw) is case["deterministic_encoding"], case["id"]
        else:
            matches = _sha(case["request_json"].encode("utf-8")) == case["refusal_request_digest"]
            assert matches is case["expect"]["identifies_request"], case["id"]
    digests = [c["expect"]["request_digest"] for c in _load("digest")["cases"] if "encoding" in c]
    assert len(set(digests)) == len(digests)


def _signature_valid(obj: dict) -> bool:
    body = {k: obj[k] for k in ("issued_at", "reason", "request_digest") if k in obj}
    signing_body = json.dumps(body, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(obj["key_id"])).verify(
            bytes.fromhex(obj["sig"]), signing_body)
    except (InvalidSignature, ValueError):
        return False
    return True


def test_refusal_signatures_match_their_expectations():
    corpus = _load("refusal")
    for case in corpus["cases"]:
        if "file" in case:
            raw = (VECTORS / case["file"]).read_bytes()
            assert _sha(raw) == case["file_sha256"]
            obj = json.loads(raw)
        else:
            obj = case["refusal"]
        expect = case["expect"]
        assert _signature_valid(obj) is (expect["signature"] == "valid"), case["id"]
        registered = isinstance(obj.get("reason"), str) and obj["reason"] in REGISTRY["refusal_reasons"]
        assert registered is expect["reason_registered"], case["id"]
        if "signing_body" in case:
            assert _signature_valid(obj) and case["signing_body"].startswith('{"issued_at":')
        if "refusal_cbor_hex" in case:
            raw = bytes.fromhex(case["refusal_cbor_hex"])
            assert cbor2.loads(raw) == obj and cbor2.dumps(obj, canonical=True) == raw
    for role in ("primary", "other"):
        key = corpus["keys"][role]
        public = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key["seed_hex"])).public_key()
        assert public.public_bytes(Encoding.Raw, PublicFormat.Raw).hex() == key["public_key_hex"]


def test_imported_refusal_vector_is_the_interop_bytes():
    raw = (VECTORS / "refusal-imported.json").read_bytes()
    assert _sha(raw) == "885d7981f8fd8a22bffd61c5bd10444515e12ea009fa9d70170bb467c7e5a66e"
    assert _signature_valid(json.loads(raw))


def test_three_state_rule_is_never_crossed():
    for case in _load("outcomes")["cases"]:
        state = case["expect"]["state"]
        assert state not in case["expect"]["must_not_record_as"], case["id"]
        received = case["facts"]["received"]
        if received == "refusal":
            assert "recorded_absence" in case["expect"]["must_not_record_as"], case["id"]
        if received in ("nothing", "transport_error", "subprotocol_not_offered"):
            assert "refusal" in case["expect"]["must_not_record_as"], case["id"]
            expected = "pending" if case["facts"]["window"] == "open" else "recorded_absence"
            assert state == expected, case["id"]


def test_invariance_expectations_follow_from_the_bytes():
    for case in _load("invariance")["cases"]:
        obs = case["observations"]
        for o in obs:
            assert _sha(bytes.fromhex(o["artifact_hex"])) == o["artifact_digest"], case["id"]
        anchors = {o["resolved_anchor"] for o in obs}
        artifacts = {o["artifact_hex"] for o in obs}
        if len(anchors) > 1:
            expected = "not_comparable"
        else:
            expected = "holds" if len(artifacts) == 1 else "violated"
        assert case["expect"]["invariance"] == expected, case["id"]


def _layer_correlation_members(record: dict) -> list:
    """§3.1.1, Evidence Layer: subject_ref and each text member of a profile-added correlation map."""
    correlation = record.get("correlation")
    members = list(correlation.values()) if isinstance(correlation, dict) else []
    return [v for v in [record.get("subject_ref"), *members] if isinstance(v, str)]


def _capsule_half_citations(record: dict) -> list:
    """§3.1.1, Capsule: references entries whose citation_purpose is counterparty_half."""
    return [r.get("digest") for r in record.get("references", [])
            if r.get("citation_purpose") == "counterparty_half"]


def test_carries_expectations_follow_from_the_designations():
    # Re-reads the two designations the vectors exercise (Evidence Layer correlation members,
    # Capsule half citation); a vector for any other pairing fails here until this reading grows.
    seen = set()
    for case in _load("carries")["cases"]:
        (form, value), = case["subject"].items()
        record = case["record"]
        if form == "correlation":
            assert case["record_format"] == "evidence-layer", case["id"]
            got = {"carries": value in _layer_correlation_members(record)}
        else:
            assert (form, case["record_format"]) == ("exchange", "capsule"), case["id"]
            got = {"cites": value in _capsule_half_citations(record)}
        assert case["expect"] == got, case["id"]
        seen.add((form, next(iter(got.values()))))
    # One positive and one negative per subject form.
    assert seen == {("correlation", True), ("correlation", False), ("exchange", True), ("exchange", False)}


def test_retention_table_covers_every_reason_both_sides():
    cases = {c["id"]: c for c in _load("retention")["cases"]}
    for reason in REGISTRY["refusal_reasons"]:
        assert f"ret-inside-{reason}" in cases and f"ret-after-{reason}" in cases
    for form in REGISTRY["subject_forms"]:
        assert f"ret-commitment-subject-{form}" in cases


def _categories_well_formed(value) -> bool:
    """-01 §3.9: a map with a text set and a non-empty array of distinct text names."""
    if not isinstance(value, dict) or not {"set", "names"} <= set(value):
        return False
    names = value["names"]
    return (isinstance(value["set"], str) and isinstance(names, list) and bool(names)
            and all(isinstance(n, str) for n in names) and len(set(names)) == len(names))


def test_categories_expectations_follow_from_the_text():
    kinds = {"request": 0, "invariance": 0}
    for case in _load("categories")["cases"]:
        kinds[case["kind"]] += 1
        if case["kind"] == "request":
            value = json.loads(case["request_json"])
            want = ({"well_formed": True} if _categories_well_formed(value["categories"])
                    else {"well_formed": False, "reason": "request_malformed"})
            assert case["expect"] == want, case["id"]
            continue
        obs = case["observations"]
        for o in obs:
            assert _sha(bytes.fromhex(o["artifact_hex"])) == o["artifact_digest"], case["id"]
        # -01 §5: the artifact is a function of subject, anchor, derivation and categories. names are
        # compared as sent; no case differs in order only (note B2).
        inputs = {json.dumps([o["request"]["subject"], o["resolved_anchor"], o["request"].get("derivation"),
                              o["request"].get("categories")], sort_keys=True) for o in obs}
        artifacts = {o["artifact_hex"] for o in obs}
        if len(inputs) > 1:
            expected = "not_comparable"
        else:
            expected = "holds" if len(artifacts) == 1 else "violated"
        assert case["expect"]["invariance"] == expected, case["id"]
    assert kinds["request"] >= 2 and kinds["invariance"] >= 2


def _decode_carried(carriage: str, text: str) -> bytes:
    """-01 §10.2: A2A JSON writes raw parts as base64 with padding; §10.3: MCP as base64url without padding."""
    if carriage == "a2a":
        return base64.b64decode(text, validate=True)
    assert carriage == "mcp" and "=" not in text
    return base64.b64decode(text.translate(str.maketrans("-_", "+/")) + "=" * (-len(text) % 4),
                            validate=True)


def _strict_decodes(carriage: str, text: str) -> bool:
    try:
        _decode_carried(carriage, text)
    except (ValueError, AssertionError):
        return False
    return True


def test_carriage_expectations_follow_from_the_text():
    seen = set()
    digests = set()
    for case in _load("carriage")["cases"]:
        kind, expect = case["kind"], case["expect"]
        if kind == "digest":
            # The vector's request is chosen so that each carriage's text fails the other's decoder.
            other = {"a2a": "mcp", "mcp": "a2a"}[case["carriage"]]
            assert not _strict_decodes(other, case["carried_text"]), case["id"]
            raw = _decode_carried(case["carriage"], case["carried_text"])
            got = case["candidate_digest"] == _sha(raw)
            assert expect == {"is_request_digest": got}, case["id"]
            if got:
                digests.add(case["candidate_digest"])
        elif kind == "binding":
            got = case["envelope_request_digest"] == _sha(bytes.fromhex(case["retained_request_hex"]))
            assert expect == {"answers": got}, case["id"]
        elif kind == "media_type":
            got = case["media_type"] in ("application/cbor", "application/json")
            assert expect == {"accepted": got}, case["id"]
        else:
            assert kind == "classify", case["id"]
            r = case["received"]
            if r["carriage"] == "a2a":
                pending = {"TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED",
                           "TASK_STATE_AUTH_REQUIRED", "TASK_STATE_UNSPECIFIED"}
                art = r["reply_artifact"]
                if art is None:
                    state = "pending" if r["task_state"] in pending else "no_reply"
                else:
                    parts = art["parts"]
                    is_reply = (len(parts) == 1 and parts[0]["kind"] == "raw"
                                and parts[0]["media_type"] == r["request_media_type"])
                    state = "reply" if is_reply else "no_reply"
            else:
                sc = r["structured_content"]
                is_reply = (sc is not None and sc.get("media_type") == r["request_media_type"]
                            and re.fullmatch(r"[A-Za-z0-9_-]+", sc.get("reply", "")) is not None)
                state = "reply" if is_reply else "no_reply"
            assert expect["classified_as"] == state, case["id"]
            if state != "reply":
                assert expect["must_not_classify_as"] == ["refusal"], case["id"]
            got = state == "reply"
        seen.add((kind, got))
    # The A2A and MCP texts of one request give one digest.
    assert len(digests) == 1
    assert seen == {(k, b) for k in ("digest", "binding", "media_type", "classify") for b in (True, False)}


UW_CLASSES = ("flood", "maintenance", "outage", "other_declared")
UW_SHOWN = "no answer; holder states unavailability"


def _uw_receipts(receipts: list) -> list:
    # The corpus's accepted flag stands for the reader's policy on which
    # transparency services are independent of the responder.
    return [er.RegistrationReceipt(r["time"], r["accepted"]) for r in receipts]


def test_unavailable_window_expectations_follow_from_the_text():
    """-02 §4.7, through the library's reader: every statement and display
    case, against every member of its expectation."""
    corpus = _load("unavailable-window")
    assert corpus["reason_classes"] == list(UW_CLASSES) == list(er.UNAVAILABLE_REASON_CLASSES)
    assert corpus["shown_as"] == UW_SHOWN == er.UNAVAILABLE_SHOWN_AS
    assert corpus["signature_profile"]["signed_members"] == list(er.UNAVAILABLE_SIGNED_MEMBERS)
    kinds = set()
    for case in corpus["cases"]:
        kinds.add(case["kind"])
        expect = case["expect"]
        if case["kind"] == "statement":
            reading = er.recognize_unavailable_window(case["statement"], _uw_receipts(case["receipts"]),
                                                      case["responder_key"])
            assert reading.recognized is expect["recognized"], case["id"]
            if reading.recognized:
                assert reading.why is None, case["id"]
                assert reading.registration_time == expect["registration_time"], case["id"]
                assert expect["shown_reason"] == case["statement"]["reason_class"], case["id"]
            else:
                assert reading.why == expect["why"], case["id"]
                assert reading.registration_time is None, case["id"]
            continue
        assert case["kind"] == "display", case["id"]
        absence = case["absence"]
        # -02 §4.7 last paragraph: the retention classification of §9 is unchanged.
        want_retention = ("attributable_absence" if absence.get("retention_commitment") == "in_force"
                          and absence["received"] == "nothing" and absence["closed_at"] else None)
        assert expect.get("retention_classification") == want_retention, case["id"]
        if want_retention is not None:
            assert er.classify_absence(absence["retention_commitment"]) == want_retention, case["id"]
        state = er.record_outcome(absence["received"], window_open=absence["closed_at"] is None,
                                  refusal=er.RefusalCheck(True, True, True))
        shown = er.display_absence(
            state, [(e["id"], e["statement"], _uw_receipts(e["receipts"])) for e in case["statements"]],
            responder_key=case["responder_key"], sent_at=absence["sent_at"], closed_at=absence["closed_at"])
        assert shown.state == expect["state"], case["id"]
        assert shown.shown_as == expect["shown_as"], case["id"]
        assert list(shown.covered_by) == expect["covered_by"], case["id"]
        labels = {sid: {"reason_class": label.reason_class, "registration_time": label.registration_time,
                        "stated_afterwards": label.stated_afterwards, "stated_period": list(label.stated_period)}
                  for sid, label in shown.labels.items()}
        assert labels == expect["labels"], case["id"]
        assert shown.shown_as not in expect["must_not_show_as"], case["id"]
        if absence["received"] != "nothing" or absence["closed_at"] is None:
            # A refusal or a pending request has no absence for a statement to cover (§4.3, §4.5).
            want = "refusal" if absence["received"] == "refusal" else "pending"
            assert expect["state"] == want and expect["shown_as"] == want, case["id"]
            assert expect["covered_by"] == [] and expect["labels"] == {}, case["id"]
            assert {UW_SHOWN, "recorded_absence"} <= set(expect["must_not_show_as"]), case["id"]
            continue
        assert expect["state"] == "recorded_absence", case["id"]
        assert expect["shown_as"] == (UW_SHOWN if expect["covered_by"] else "recorded_absence"), case["id"]
        assert {"refusal", "proof_of_attack"} <= set(expect["must_not_show_as"]), case["id"]
        if expect["covered_by"]:
            assert "absence_without_statement" in expect["must_not_show_as"], case["id"]
    assert kinds == {"statement", "display"}
    ids = {c["id"] for c in corpus["cases"]}
    for cls in UW_CLASSES:
        assert f"uw-class-{cls}" in ids


def test_refusal_02_expectations_follow_from_the_text():
    corpus = _load("refusal-02")
    added = ["capacity_exceeded", "request_unauthenticated"]
    # -02 §13: the eight -00 tokens, then the two -02 adds; -00's registry.json is unchanged.
    assert corpus["refusal_reasons"] == REGISTRY["refusal_reasons"] + added
    assert not set(added) & set(REGISTRY["refusal_reasons"])
    seen = set()
    for case in corpus["cases"]:
        expect, facts = case["expect"], case.get("facts", {})
        if "refusal" in case:
            obj = case["refusal"]
            assert _signature_valid(obj) is (expect["signature"] == "valid"), case["id"]
            assert (obj["reason"] in corpus["refusal_reasons"]) is expect["reason_registered"], case["id"]
            assert expect["conformant"] is (expect["signature"] == "valid" and expect["reason_registered"])
            if "signing_body" in case:
                body = {k: obj[k] for k in ("issued_at", "reason", "request_digest")}
                assert case["signing_body"] == json.dumps(body, separators=(",", ":"), sort_keys=True), case["id"]
            seen.add(("refusal", obj["reason"]))
        elif "commitment" in facts:
            # -02 §9: request_unauthenticated is a property of the request; capacity_exceeded is never a breach.
            assert facts["refusal_reason"] in added and expect["classification"] == "no_breach", case["id"]
            seen.add((facts["commitment"], facts["refusal_reason"]))
        elif facts.get("cause") == "responder_load":
            # -02 §11: load shedding refuses capacity_exceeded, never a policy reason. -02 §3.4: a deadline
            # missed only because of load is capacity_exceeded, not deadline_unmet.
            excluded = ["deadline_unmet"] if facts.get("deadline") else ["policy_declined", "not_authorized"]
            assert expect == {"reason": "capacity_exceeded", "not_reason": excluded}, case["id"]
            seen.add(("load", facts.get("deadline")))
        else:
            # -02 §4.6: the status stays unknown; neither reason is withholding by policy or non-satisfaction.
            assert facts["refusal_reason"] in added, case["id"]
            assert expect == {"status_unknown": True, "withheld_by_policy": False,
                              "evidence_of_non_satisfaction": False}, case["id"]
            seen.add(("map", facts["refusal_reason"]))
    for reason in added:
        assert {("refusal", reason), ("in_force", reason), ("lapsed", reason), ("map", reason)} <= seen, reason
    assert {("load", None), ("load", "would_be_missed")} <= seen
