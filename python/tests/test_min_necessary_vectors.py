# SPDX-License-Identifier: BSD-3-Clause
"""The minimum-necessary SD-JWT input vectors are reproducible and agree with the registry entries.

The generator writes the expectations itself. This test re-runs it and requires
byte-identical output, then checks every artifact with code written here from
RFC 9901 and the provisional registry entries (REGISTRY.md §10, §14, §16), and
with this repository's Capsule, Producer Envelope and Evidence Bundle verifiers.
The never-enters test scans every Capsule for the member's identity, in clear
and in every digest form listed below.
"""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_action_capsule import compute_capsule_id
from agent_action_capsule.bundle import verify_bundle
from agent_action_capsule.canonical import jcs
from agent_action_capsule.producer_envelope import verify_producer_envelope
from agent_action_capsule.verify import verify

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "minimum-necessary"
GENERATOR = ROOT / "python" / "scripts" / "generate_min_necessary_vectors.py"
HAND_WRITTEN = ("README.md",)
MANIFEST = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
ISSUER_JWK = MANIFEST["keys"]["record issuer"]["jwk"]
ISSUER = "https://data.example.org"

# The vector list of the source worked example, one directory per vector id.
EXPECTED_CASES = [
    "sdjwt-issue-claim", "sdjwt-issue-note", "sdjwt-issue-eligibility",
    "presentation-P1", "presentation-A1",
    "policy-decision-P1", "policy-decision-A1",
    "capsule-pricing", "capsule-audit",
    "capsule-policy-fail",
    "log-two-records",
    "bundle-internal-audit", "bundle-external-auditor", "bundle-mismatch", "bundle-not-registered",
]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: Any) -> str:
    return _sha(jcs(value))


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _case(name: str) -> dict[str, dict[str, Any]]:
    return {part: json.loads((VECTORS / name / f"{part}.json").read_text(encoding="utf-8"))
            for part in ("input", "expected")}


# ---------------------------------------------------------------------------
# An SD-JWT reader written from RFC 9901, independent of the generator
# ---------------------------------------------------------------------------


def _parse_presentation(presentation: str) -> dict[str, Any]:
    assert presentation.endswith("~"), "no Key Binding JWT: a presentation ends with '~' (RFC 9901 §4)"
    parts = presentation.split("~")
    jwt, disclosures = parts[0], parts[1:-1]
    header_b64, payload_b64, signature_b64 = jwt.split(".")
    header = json.loads(_b64u_decode(header_b64))
    payload = json.loads(_b64u_decode(payload_b64))
    return {"jwt": jwt, "header": header, "payload": payload, "signature": _b64u_decode(signature_b64),
            "signing_input": f"{header_b64}.{payload_b64}".encode("ascii"), "disclosures": disclosures}


def _issuer_signature_valid(parsed: dict[str, Any], jwk: dict[str, str]) -> bool:
    assert parsed["header"]["alg"] == "EdDSA" and jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519"
    try:
        Ed25519PublicKey.from_public_bytes(_b64u_decode(jwk["x"])).verify(parsed["signature"], parsed["signing_input"])
    except InvalidSignature:
        return False
    return True


def _disclosure_digest(disclosure: str) -> str:
    return _b64u(hashlib.sha256(disclosure.encode("ascii")).digest())


def _check_sd_jwt(presentation: str, jwk: dict[str, str], revealed: list[str]) -> dict[str, Any]:
    """The §10 presentation-type rule for one SD-JWT."""
    parsed = _parse_presentation(presentation)
    assert parsed["payload"]["_sd_alg"] == "sha-256"
    names = []
    bound = True
    digests = [_disclosure_digest(d) for d in parsed["disclosures"]]
    assert len(set(digests)) == len(digests), "a Disclosure digest appears once (RFC 9901 §7.1)"
    for disclosure, digest in zip(parsed["disclosures"], digests):
        bound = bound and digest in parsed["payload"]["_sd"]
        decoded = json.loads(_b64u_decode(disclosure))
        assert len(decoded) == 3 and len(_b64u_decode(decoded[0])) == 16
        names.append(decoded[1])
    return {
        "vct": parsed["payload"]["vct"],
        "issuer_signature": "valid" if _issuer_signature_valid(parsed, jwk) else "invalid",
        "disclosures_bound": bound,
        "disclosed": sorted(names),
        "decision_revealed": sorted(revealed),
        "set_equal": sorted(names) == sorted(revealed),
    }


def _check_agent_input(value: dict[str, Any], decision: dict[str, Any], issuers: dict[str, Any]) -> dict[str, Any]:
    assert value["agent_input_version"] == "1" and set(value) == {"agent_input_version", "presentations"}
    by_vct = {s["vct"]: s["revealed"] for s in decision["sources"]}
    results = []
    for presentation in value["presentations"]:
        parsed = _parse_presentation(presentation)
        results.append(_check_sd_jwt(presentation, issuers[parsed["payload"]["iss"]],
                                     by_vct[parsed["payload"]["vct"]]))
    ok = all(r["issuer_signature"] == "valid" and r["disclosures_bound"] and r["set_equal"] for r in results)
    return {"status": "pass" if ok else "fail", "presentations": results}


# ---------------------------------------------------------------------------
# Reproducibility and registration
# ---------------------------------------------------------------------------


def test_case_list_is_the_worked_example_vector_list():
    assert [c["name"] for c in MANIFEST["cases"]] == EXPECTED_CASES
    assert sorted(p.name for p in VECTORS.iterdir() if p.is_dir()) == sorted(EXPECTED_CASES)


def test_generator_reproduces_every_file_byte_for_byte(tmp_path):
    for name in HAND_WRITTEN:
        shutil.copyfile(VECTORS / name, tmp_path / name)
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(tmp_path)], check=True)
    committed = sorted(p.relative_to(VECTORS).as_posix() for p in VECTORS.rglob("*") if p.is_file())
    regenerated = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert regenerated == committed
    for name in committed:
        assert (tmp_path / name).read_bytes() == (VECTORS / name).read_bytes(), name


def test_sha256sums_and_manifest_pin_every_file():
    listed = dict(reversed(line.split("  ", 1)) for line in
                  (VECTORS / "SHA256SUMS").read_text(encoding="utf-8").splitlines())
    on_disk = {p.relative_to(VECTORS).as_posix() for p in VECTORS.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
    assert set(listed) == on_disk
    for name, digest in listed.items():
        assert _sha((VECTORS / name).read_bytes()) == digest, name
    assert {f["path"] for f in MANIFEST["files"]} == on_disk - {"manifest.json", "README.md"}
    for entry in MANIFEST["files"]:
        assert _sha((VECTORS / entry["path"]).read_bytes()) == entry["sha256"], entry["path"]


def test_top_level_registers_the_directory():
    top = dict(reversed(line.split("  ", 1)) for line in
               (ROOT / "vectors" / "SHA256SUMS").read_text(encoding="utf-8").splitlines())
    for path in VECTORS.rglob("*"):
        if path.is_file() and path.name != "SHA256SUMS":
            rel = path.relative_to(ROOT / "vectors").as_posix()
            assert top.get(rel) == _sha(path.read_bytes()), rel
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text(encoding="utf-8"))["corpora"]
    assert corpora["minimum_necessary"] == "minimum-necessary/manifest.json"


def test_registry_names_are_the_ones_in_registry_md():
    registry = (ROOT / "spec" / "REGISTRY.md").read_text(encoding="utf-8")
    entries = MANIFEST["registry_entries"]
    for token in [*entries["evidence_bundle_extension_kinds"], entries["evidence_request_derivation"]]:
        assert f"| `{token}` |" in registry, token
    assert '`agent_input_version: "1"`' in registry


# ---------------------------------------------------------------------------
# SD-JWT issuance and presentations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["sdjwt-issue-claim", "sdjwt-issue-note", "sdjwt-issue-eligibility"])
def test_issued_sd_jwt_verifies_and_binds_every_field(name):
    case = _case(name)
    inp, exp = case["input"], case["expected"]
    parsed = _parse_presentation(exp["issuer_signed_jwt"] + "~")
    assert parsed["payload"] == exp["jwt_payload"] and parsed["header"] == exp["jwt_header"]
    assert _issuer_signature_valid(parsed, ISSUER_JWK)
    payload = parsed["payload"]
    assert payload["iss"] == inp["iss"] and payload["vct"] == inp["vct"] and payload["iat"] == inp["iat"]
    sealed = [f for f in inp["record"] if f not in inp["clear_fields"]]
    for field in inp["clear_fields"]:
        assert payload[field] == inp["record"][field]
    for field in sealed:
        assert field not in payload, f"{field} is sealed, never in the clear"
        entry = exp["disclosures"][field]
        assert json.loads(_b64u_decode(entry["disclosure"])) == [inp["salts"][field], field, inp["record"][field]]
        assert _disclosure_digest(entry["disclosure"]) == entry["digest"]
        assert entry["digest"] in payload["_sd"]
    assert set(exp["disclosures"]) == set(sealed)
    assert sorted(payload["_sd"]) == payload["_sd"] == exp["sd"]
    assert set(payload["_sd"]) == {exp["disclosures"][f]["digest"] for f in sealed} | set(inp["decoy_digests"])


@pytest.mark.parametrize("name", ["presentation-P1", "presentation-A1"])
def test_presentation_carries_exactly_the_allowed_disclosures(name):
    case = _case(name)
    inp, exp = case["input"], case["expected"]
    value = exp["agent_input"]
    assert value == {"agent_input_version": "1", "presentations": exp["presentations"]}
    assert jcs(value).decode("utf-8") == exp["agent_input_canonical"]
    assert _digest(value) == exp["agent_input_digest"]
    for presentation in value["presentations"]:
        assert presentation.split("~")[0] in inp["issuer_signed_jwts"].values()
    check = _check_agent_input(value, inp["policy_decision"], {ISSUER: ISSUER_JWK})
    assert check == exp["check"]
    assert check["status"] == "pass"


@pytest.mark.parametrize("name,capsule_case", [("policy-decision-P1", "capsule-pricing"),
                                               ("policy-decision-A1", "capsule-audit")])
def test_policy_decision_digest_is_the_constraint_evidence_digest(name, capsule_case):
    case = _case(name)
    decision = case["input"]["policy_decision"]
    assert jcs(decision).decode("utf-8") == case["expected"]["canonical"]
    assert _digest(decision) == case["expected"]["json_digest"]
    capsule = _case(capsule_case)["expected"]["capsule"]
    assert [c["evidence_digest"] for c in capsule["constraints"]] == [case["expected"]["json_digest"]]
    for source in decision["sources"]:
        assert not set(source["revealed"]) & set(source["withheld"])


# ---------------------------------------------------------------------------
# Capsules
# ---------------------------------------------------------------------------


def _check_capsule(name: str, runtime: str) -> dict[str, Any]:
    case = _case(name)
    exp = case["expected"]
    capsule = exp["capsule"]
    payload = {k: v for k, v in capsule.items() if k != "capsule_id"}
    assert payload == case["input"]["capsule_payload"]
    assert jcs(payload).decode("utf-8") == exp["canonical_preimage"]
    assert compute_capsule_id(capsule) == capsule["capsule_id"] == exp["capsule_id"]
    assert verify(capsule).ok is exp["class1"]["ok"] is True
    assert exp["producer_key_hex"] == MANIFEST["keys"][runtime]["public_key_hex"]
    assert verify_producer_envelope(capsule["capsule_id"], bytes.fromhex(exp["producer_envelope_hex"])).ok
    compute = capsule["model_attestation"]["compute_attestation"]
    assert compute["agent_input_digest"] == _digest(case["input"]["agent_input"])
    [record] = capsule["constraints"]
    assert set(record) == {"id", "check_type", "method", "result", "severity", "blocking", "evidence_digest"}
    for label in ("id", "check_type", "method"):
        assert "." in record[label], "unseeded constraint labels carry a namespace prefix"
    assert record["blocking"] is True and record["result"] in ("pass", "fail", "n/a")
    return case


@pytest.mark.parametrize("name,runtime,decision_case", [
    ("capsule-pricing", "claims-processor runtime", "policy-decision-P1"),
    ("capsule-audit", "claim-audit runtime", "policy-decision-A1"),
])
def test_capsule_binds_input_output_and_decision(name, runtime, decision_case):
    case = _check_capsule(name, runtime)
    capsule = case["expected"]["capsule"]
    compute = capsule["model_attestation"]["compute_attestation"]
    assert compute["agent_output_digest"] == _digest(case["input"]["agent_output"])
    decision = _case(decision_case)["input"]["policy_decision"]
    check = _check_agent_input(case["input"]["agent_input"], decision,
                               {ISSUER: ISSUER_JWK})
    assert check["status"] == capsule["constraints"][0]["result"] == "pass"
    assert capsule["disposition"]["verdict_class"] == "executed"


def test_policy_fail_blocks_the_action():
    case = _check_capsule("capsule-policy-fail", "claims-processor runtime")
    exp = case["expected"]
    capsule = exp["capsule"]
    check = _check_agent_input(case["input"]["agent_input"], case["input"]["policy_decision"],
                               {ISSUER: ISSUER_JWK})
    assert check["status"] == "fail"
    extra = [f"{p['vct']}#{n}" for p in check["presentations"] for n in p["disclosed"] if n not in p["decision_revealed"]]
    assert extra == exp["extra_disclosures"] == ["https://data.example.org/types/claim-837p/v1#patient_name"]
    assert capsule["constraints"][0]["result"] == exp["constraint_result"] == "fail"
    assert capsule["disposition"]["verdict_class"] == exp["verdict_class"] == "blocked"
    assert capsule["disposition"]["decision"] == "reject"
    assert "agent_output_digest" not in capsule["model_attestation"]["compute_attestation"]
    assert capsule["constraints"][0]["evidence_digest"] == _digest(case["input"]["policy_decision"])


# ---------------------------------------------------------------------------
# Log
# ---------------------------------------------------------------------------


def test_log_mmr_recomputes_from_the_cll_hash_rules():
    exp = _case("log-two-records")["expected"]
    ids = [_case("capsule-pricing")["expected"]["capsule_id"], _case("capsule-audit")["expected"]["capsule_id"]]
    leaves = [hashlib.sha256(b"\x00" + bytes.fromhex(i)).digest() for i in ids]
    parent = hashlib.sha256((3).to_bytes(8, "big") + leaves[0] + leaves[1]).digest()
    assert exp["mmr_nodes"] == [leaves[0].hex(), leaves[1].hex(), parent.hex()]
    assert exp["root"] == parent.hex() and exp["mmr_size"] == 3
    assert [(e["seq"], e["leaf_index"], e["capsule_id"]) for e in exp["entries"]] == [(1, 0, ids[0]), (2, 1, ids[1])]
    assert exp["commitment_hex"] == "815820" + parent.hex()


def test_log_proofs_and_checkpoint_verify_with_the_log_reference():
    checkpoint = pytest.importorskip("cll.checkpoint")
    from cll.checkpoint.index import RangeProof, verify_range

    exp = _case("log-two-records")["expected"]
    root = bytes.fromhex(exp["root"])
    for capsule_id, member in exp["memberships"].items():
        p = member["inclusion_proof"]
        proof = checkpoint.InclusionProof(p["v"], p["kind"], p["size"], p["leaf_index"], tuple(p["witness"]),
                                          tuple(p["peaks_left"]), tuple(p["peaks_right"]))
        assert checkpoint.verify_inclusion(root, p["size"], p["leaf_index"], bytes.fromhex(capsule_id), proof)
    rp = exp["range_proof"]
    assert verify_range(root, 1, 2, [bytes.fromhex(e["capsule_id"]) for e in exp["entries"]],
                        RangeProof(rp["from_seq"], rp["to_seq"], rp["size"], rp["from_index"], rp["to_index"],
                                   tuple(rp["witness"])))
    result = checkpoint.verify_checkpoint_cose_offline(_b64u_decode(exp["checkpoint_cose"]))
    assert result.ok, result.errors
    assert result.decoded.log_id == exp["log_id"] and result.decoded.mmr_size == 3
    assert result.decoded.root == exp["root"]
    assert result.decoded.key_id == MANIFEST["keys"]["log checkpoint"]["public_key_hex"]


# ---------------------------------------------------------------------------
# Bundles
# ---------------------------------------------------------------------------

BUNDLES = ["bundle-internal-audit", "bundle-external-auditor", "bundle-mismatch", "bundle-not-registered"]


def _cll_available() -> bool:
    try:
        import cll.checkpoint  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.mark.parametrize("name", BUNDLES)
def test_bundle_core_checks_match_the_evidence_bundle_verifier(name):
    case = _case(name)
    bundle, exp = case["input"]["bundle"], case["expected"]
    result = verify_bundle(bundle)
    assert result.bundle_digest == exp["bundle_digest"]
    assert (result.graph_closure.status, list(result.graph_closure.findings)) == ("pass", [])
    got = sorted((d.capsule_id, d.member, d.status) for d in result.disclosures)
    assert got == sorted((d["capsule_id"], d["member"], d["status"]) for d in exp["disclosures"])
    assert [(e.kind, e.status) for e in result.extensions] == [(k, "uninterpreted") for k in exp["extensions"]]
    if _cll_available():
        for claim in ("interval_coverage", "per_record_membership"):
            got_claim = getattr(result, claim)
            assert (got_claim.status, list(got_claim.findings)) == (exp[claim]["status"], exp[claim]["findings"])


@pytest.mark.parametrize("name", BUNDLES)
def test_bundle_extension_checks(name):
    case = _case(name)
    bundle, exp = case["input"]["bundle"], case["expected"]
    records = {r["capsule_id"]: r for r in bundle["records"]}
    decisions = bundle["extensions"]["disclosure_policy_decisions/v1"]
    issuers = bundle["extensions"]["sd_jwt_issuers/v1"]
    assert set(decisions) == set(records)
    for capsule_id, decision in decisions.items():
        digest = _digest(decision)
        [record] = [c for c in records[capsule_id]["constraints"] if c["evidence_digest"] == digest]
        assert exp["policy_decisions"][capsule_id] == {"decision_digest": digest, "status": "match",
                                                       "constraint_result": record["result"]}
        disclosed = bundle.get("disclosures", {}).get(capsule_id, {})
        stored = records[capsule_id]["model_attestation"]["compute_attestation"]["agent_input_digest"]
        if "agent_input" not in disclosed:
            assert exp["sd_jwt_presentations"][capsule_id] == {"status": "not_evaluated",
                                                               "reason": "agent_input_withheld"}
        elif _digest(disclosed["agent_input"]) != stored:
            assert exp["sd_jwt_presentations"][capsule_id] == {"status": "not_evaluated",
                                                               "reason": "agent_input_disclosure_mismatch"}
        else:
            check = _check_agent_input(disclosed["agent_input"], decision, issuers)
            assert check == exp["sd_jwt_presentations"][capsule_id]
            assert check["status"] == "pass"


def test_bundle_mismatch_changes_only_the_altered_capsule():
    good = _case("bundle-internal-audit")["expected"]
    bad = _case("bundle-mismatch")["expected"]
    pricing = _case("capsule-pricing")["expected"]["capsule_id"]
    changed = [(a, b) for a, b in zip(good["disclosures"], bad["disclosures"]) if a != b]
    assert changed == [({"capsule_id": pricing, "member": "agent_input", "status": "disclosure_match"},
                        {"capsule_id": pricing, "member": "agent_input", "status": "disclosure_mismatch"})]
    for key in ("graph_closure", "interval_coverage", "per_record_membership", "policy_decisions", "extensions"):
        assert good[key] == bad[key], key
    assert {k: v for k, v in good["sd_jwt_presentations"].items() if k != pricing} == \
           {k: v for k, v in bad["sd_jwt_presentations"].items() if k != pricing}


def test_bundle_not_registered_is_qualified():
    exp = _case("bundle-not-registered")["expected"]
    bundle = _case("bundle-not-registered")["input"]["bundle"]
    assert "cose" not in bundle["checkpoint"] and "receipts" not in bundle["checkpoint"]
    for claim in ("interval_coverage", "per_record_membership"):
        assert exp[claim] == {"status": "pass", "findings": ["checkpoint_unverified"]}


def _record_values() -> Iterator[str]:
    for name in ("sdjwt-issue-claim", "sdjwt-issue-note", "sdjwt-issue-eligibility"):
        inp = _case(name)["input"]
        for field, value in inp["record"].items():
            if field in inp["clear_fields"]:
                continue
            if isinstance(value, (dict, list)):
                yield jcs(value).decode("utf-8")
            elif isinstance(value, str) and len(value) >= 5:
                # Scalars shorter than this ("11", 1, true) collide with unrelated text.
                yield value
        yield from inp["salts"].values()
        yield from (d["disclosure"] for d in _case(name)["expected"]["disclosures"].values())


def test_external_auditor_bundle_carries_no_record_value():
    text = json.dumps(_case("bundle-external-auditor")["input"]["bundle"], ensure_ascii=False)
    found = [v for v in _record_values() if v in text]
    assert found == []
    assert "~" not in text


# ---------------------------------------------------------------------------
# Never-enters tier: no member identity in any Capsule, in clear or hashed
# ---------------------------------------------------------------------------


def _forms(field: str, value: str) -> dict[str, str]:
    raw = value.encode("utf-8")
    as_json = jcs(value)
    forms = {
        "clear": value,
        "sha256-hex(raw)": _sha(raw),
        "sha256-hex(json)": _sha(as_json),
        "sha256-b64u(raw)": _b64u(hashlib.sha256(raw).digest()),
        "sha256-b64u(json)": _b64u(hashlib.sha256(as_json).digest()),
        "b64u(raw)": _b64u(raw),
    }
    for name in ("sdjwt-issue-claim", "sdjwt-issue-eligibility"):
        entry = _case(name)["expected"]["disclosures"].get(field)
        if entry is not None:
            forms[f"{name}:disclosure"] = entry["disclosure"]
            forms[f"{name}:disclosure-digest"] = entry["digest"]
            forms[f"{name}:disclosure-digest-hex"] = _b64u_decode(entry["digest"]).hex()
    return forms


def _all_capsules() -> Iterator[tuple]:
    for name in EXPECTED_CASES:
        case = _case(name)
        if name.startswith("capsule-"):
            yield name, case["expected"]["capsule"]
            yield name, case["input"]["capsule_payload"]
        if name.startswith("bundle-"):
            for record in case["input"]["bundle"]["records"]:
                yield name, record


def _leaks(where: str, capsule: dict[str, Any]) -> list[tuple]:
    text = json.dumps(capsule, ensure_ascii=False)
    lowered = text.lower()
    leaks = []
    for field, value in MANIFEST["member_identifiers"].items():
        for form, needle in _forms(field, value).items():
            hex_form = form.startswith("sha256-hex") or form.endswith("-hex")
            if (needle.lower() in lowered) if hex_form else (needle in text):
                leaks.append((where, field, form))
    return leaks


def test_never_enters_no_member_identity_in_any_capsule():
    identifiers = MANIFEST["member_identifiers"]
    assert identifiers == {"member_id": "M48213377", "patient_name": "J. Doe", "patient_dob": "1971-03-22"}
    capsules = list(_all_capsules())
    assert len(capsules) == 3 * 2 + 4 * 2
    assert [leak for where, capsule in capsules for leak in _leaks(where, capsule)] == []


@pytest.mark.parametrize("field", ["member_id", "patient_name", "patient_dob"])
def test_never_enters_scan_catches_a_planted_identifier(field):
    """The scan is not vacuous: a Capsule carrying any one form of any identifier is caught."""
    capsule = _case("capsule-pricing")["expected"]["capsule"]
    for form, needle in _forms(field, MANIFEST["member_identifiers"][field]).items():
        planted = dict(capsule, constraints=[dict(capsule["constraints"][0], evidence_digest=needle.upper()
                                                  if form.endswith("-hex") or form.startswith("sha256-hex")
                                                  else needle)])
        assert ("planted", field, form) in _leaks("planted", planted), form
