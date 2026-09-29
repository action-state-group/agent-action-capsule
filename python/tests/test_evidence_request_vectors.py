# SPDX-License-Identifier: BSD-3-Clause
"""The draft-mih-agent-evidence-request-00 vectors are reproducible and self-consistent.

These checks do not implement the interaction. They re-run the generator and
require byte-identical output, check every hash the vectors pin, decode each
CBOR frame with an independent encoder, verify each signed refusal against its
stated expectation, and confirm every cited section exists in the draft.
"""
from __future__ import annotations

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

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "evidence-request"
GENERATOR = ROOT / "python" / "scripts" / "generate_evidence_request_vectors.py"
DRAFT_TXT = ROOT / "spec" / "draft-mih-agent-evidence-request-00.txt"
HAND_WRITTEN = ("README.md", "DIFFS.md")
CORPORA = ("request", "resolution", "digest", "refusal", "outcomes", "invariance", "retention")


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


def _draft_headings() -> dict[str, str]:
    headings = {}
    for line in DRAFT_TXT.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^(\d+(?:\.\d+)*)\.  (\S.*?)\s*$", line)
        if m:
            headings[m.group(1)] = m.group(2)
    return headings


def test_every_cited_section_exists_in_the_draft():
    headings = _draft_headings()
    cited = set(REGISTRY["section"])
    for _, case in _all_cases():
        cited.update(case["section"])
    for ref in cited:
        m = re.match(r"^§(\d+(?:\.\d+)*) (.+)$", ref)
        assert m, ref
        assert headings.get(m.group(1)) == m.group(2), ref


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


@pytest.mark.parametrize("corpus", ["request", "resolution"])
def test_request_digests_and_cbor_frames(corpus):
    rfc8785 = pytest.importorskip("rfc8785")
    for case in _load(corpus)["cases"]:
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


def test_retention_table_covers_every_reason_both_sides():
    cases = {c["id"]: c for c in _load("retention")["cases"]}
    for reason in REGISTRY["refusal_reasons"]:
        assert f"ret-inside-{reason}" in cases and f"ret-after-{reason}" in cases
    for form in REGISTRY["subject_forms"]:
        assert f"ret-commitment-subject-{form}" in cases
