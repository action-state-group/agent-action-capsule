# SPDX-License-Identifier: BSD-3-Clause
"""The draft-mih-agent-settlement-profile-00 vectors are reproducible and agree with the draft.

The generator writes the expectations by hand. This test re-runs it and requires
byte-identical output, recomputes every Capsule ID and checks every leg against the
base profile's Class 1 verifier, authenticates every Producer Envelope, and then
derives the failures and the settlement states with an independent reading of the
draft (sections 3 to 9) and compares them with the stated expectations.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_action_capsule import compute_capsule_id
from agent_action_capsule.verify import verify

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "settlement"
GENERATOR = ROOT / "python" / "scripts" / "generate_settlement_vectors.py"
DRAFT_TXT = ROOT / "spec" / "draft-mih-agent-settlement-profile-00.txt"
HAND_WRITTEN = ("README.md",)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load(name: str) -> dict:
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))


CASES = _load("cases")
REGISTRY = _load("registry")


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---------------------------------------------------------------------------
# Reproducibility and registration
# ---------------------------------------------------------------------------


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
    listed = dict(reversed(line.split("  ", 1)) for line in
                  (VECTORS / "SHA256SUMS").read_text(encoding="utf-8").splitlines())
    on_disk = {p.name for p in VECTORS.iterdir() if p.is_file() and p.name != "SHA256SUMS"}
    assert set(listed) == on_disk
    for name, digest in listed.items():
        assert _sha((VECTORS / name).read_bytes()) == digest, name
    manifest = _load("manifest")
    assert {f["path"] for f in manifest["files"]} == {p.name for p in VECTORS.glob("*.json")} - {"manifest.json"}
    for entry in manifest["files"]:
        assert _sha((VECTORS / entry["path"]).read_bytes()) == entry["sha256"], entry["path"]


def test_top_level_registers_the_directory():
    top = dict(reversed(line.split("  ", 1)) for line in
               (ROOT / "vectors" / "SHA256SUMS").read_text(encoding="utf-8").splitlines())
    for path in VECTORS.iterdir():
        if path.name != "SHA256SUMS":
            assert top.get(f"settlement/{path.name}") == _sha(path.read_bytes()), path.name
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text(encoding="utf-8"))["corpora"]
    assert corpora["settlement"] == "settlement/manifest.json"


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
    for c in CASES["cases"]:
        cited.update(c["section"])
    for ref in cited:
        m = re.match(r"^§(\d+(?:\.\d+)*) (.+)$", ref)
        assert m, ref
        assert headings.get(m.group(1)) == m.group(2), ref


def test_readme_lists_every_case_and_the_case_ids_are_unique():
    readme = (VECTORS / "README.md").read_text(encoding="utf-8")
    ids = [c["id"] for c in CASES["cases"]]
    assert len(ids) == len(set(ids)) == CASES["count"]
    for case_id in ids:
        assert f"`{case_id}`" in readme, case_id


def test_the_draft_names_every_payment_ref_and_wrapped_type():
    text = DRAFT_TXT.read_text(encoding="utf-8")
    for name in list(REGISTRY["payment_ref_types"]) + list(REGISTRY["wrapped_types"]):
        assert name in text, name
    for code in REGISTRY["failure_codes"] + REGISTRY["informational_codes"]:
        assert code in text, code


# ---------------------------------------------------------------------------
# Every leg is a real Capsule with a real envelope
# ---------------------------------------------------------------------------


def _records():
    for c in CASES["cases"]:
        for r in c["records"]:
            yield c["id"], r


def test_capsule_ids_recompute_with_an_independent_rfc8785():
    rfc8785 = pytest.importorskip("rfc8785")
    for case_id, r in _records():
        if r["capsule_id"] is None:
            continue
        body = {k: v for k, v in r["capsule"].items() if k != "capsule_id"}
        assert _sha(rfc8785.dumps(body)) == r["capsule_id"], (case_id, r["label"])
        assert compute_capsule_id(r["capsule"]) == r["capsule_id"], (case_id, r["label"])


def test_legs_pass_class1_unless_the_case_says_capsule_invalid():
    for c in CASES["cases"]:
        bad = {lbl for f in c["expect"]["failures"] if f["code"] == "capsule_invalid" for lbl in f["records"]}
        for r in c["records"]:
            result = verify(r["capsule"])
            assert result.ok is (r["label"] not in bad), (c["id"], r["label"], result.errors)


def test_producer_envelopes_authenticate_the_stated_key():
    pytest.importorskip("scitt_cose")
    from agent_action_capsule.producer_envelope import verify_producer_envelope

    for case_id, r in _records():
        if r["capsule_id"] is None:
            assert "envelope_hex" not in r
            continue
        result = verify_producer_envelope(r["capsule_id"], bytes.fromhex(r["envelope_hex"]))
        assert result.ok, (case_id, r["label"], result.findings)
        assert result.public_key.hex() == r["envelope_kid"]


def test_wrapped_objects_hash_to_their_digests_and_keys_derive_from_seeds():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    for c in CASES["cases"]:
        for w in c["wrapped_objects"]:
            assert _sha(_b64u_decode(w["octets_b64u"])) == w["digest"], (c["id"], w["type"])
            assert w["type"] in REGISTRY["wrapped_types"]
    for key in CASES["keys"].values():
        pub = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key["seed_hex"])).public_key()
        assert pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex() == key["public_key_hex"]


# ---------------------------------------------------------------------------
# An independent derivation from the draft text
# ---------------------------------------------------------------------------

VALUE_RE = re.compile(r"^(0|[1-9][0-9]*)$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _amount_ok(a: Any) -> bool:  # §6 rules 1-2
    return (isinstance(a, dict) and set(a) == {"value", "assetCode", "assetScale"}
            and isinstance(a["value"], str) and VALUE_RE.match(a["value"]) is not None
            and isinstance(a["assetCode"], str) and a["assetCode"] != ""
            and isinstance(a["assetScale"], int) and not isinstance(a["assetScale"], bool)
            and 0 <= a["assetScale"] <= 255)


def amounts_equal(a: dict, b: dict) -> bool:  # §6 rule 3-4, exact integer arithmetic
    if a["assetCode"] != b["assetCode"]:
        return False
    scale = max(a["assetScale"], b["assetScale"])
    return int(a["value"]) * 10 ** (scale - a["assetScale"]) == int(b["value"]) * 10 ** (scale - b["assetScale"])


def _normal_ref(ref: dict) -> dict:  # §7.2 normal forms
    out = dict(ref)
    if ref["type"] == "x402.transaction" and ref.get("network", "").startswith("eip155:"):
        out["value"] = ref["value"].lower()
    return out


def _structure_failures(s: Any) -> list[str]:  # §4.2, §3 item 4, §5.4, §6
    if not isinstance(s, dict) or s.get("version") != "0" or s.get("leg") not in REGISTRY["legs"] \
            or s.get("sealer_role") not in REGISTRY["sealer_roles"]:
        return ["settlement_malformed"]
    out: list[str] = []
    members = REGISTRY["settlement_members"][s["leg"]]
    if not set(members["required"]) <= set(s) or not set(s) <= set(members["required"]) | set(members["optional"]):
        out.append("settlement_malformed")
    leg, role = s["leg"], s["sealer_role"]
    if (leg == "payer_observed" and role != "payer") or (leg == "payee_observed" and role != "payee"):
        out.append("leg_role_mismatch")
    if "amount" in s and not _amount_ok(s["amount"]):
        out.append("amount_not_exact")
    if leg.endswith("_observed") and s.get("status") not in REGISTRY["statuses"]:
        out.append("settlement_malformed")
    if leg == "delivered":
        d = s.get("delivery")
        if not isinstance(d, dict) or REGISTRY["delivery_directions"].get(d.get("direction")) != role:
            out.append("settlement_malformed")
    ref = s.get("payment_ref")
    if ref is not None:
        if not isinstance(ref, dict) or not isinstance(ref.get("type"), str) or not isinstance(ref.get("value"), str):
            out.append("settlement_malformed")
        elif ref["type"] in REGISTRY["payment_ref_types"]:
            if set(ref) != {"type", "value", *REGISTRY["payment_ref_types"][ref["type"]]}:
                out.append("settlement_malformed")
    return sorted(set(out), key=out.index)


def _jws_verifies(octets: bytes, public_hex: str) -> bool:
    parts = octets.rstrip(b"~").split(b".")
    if len(parts) != 3:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            _b64u_decode(parts[2].decode("ascii")), parts[0] + b"." + parts[1])
        return True
    except (InvalidSignature, ValueError):
        return False


def _wrapped_failures(s: dict, kid: str | None, objects: dict[str, bytes]) -> list[str]:  # §8
    out: list[str] = []
    for w in s.get("wrapped", []) if isinstance(s, dict) else []:
        octets = objects.get(w["digest"])
        if "content" in w:
            content = _b64u_decode(w["content"])
            if _sha(content) != w["digest"]:
                out.append("wrapped_digest_mismatch")
                continue
            octets = content
        issuer = REGISTRY["wrapped_types"].get(w["type"])
        if octets is not None and kid is not None and issuer != s["sealer_role"] and _jws_verifies(octets, kid):
            out.append("wrapped_resigned")
    return out


def derive(case: dict) -> dict:
    objects = {w["digest"]: _b64u_decode(w["octets_b64u"]) for w in case["wrapped_objects"]}
    policy = case["key_policy"]
    failures: list[dict] = []
    findings: list[dict] = []
    legs: dict[str, dict] = {}
    kids: dict[str, str] = {}
    excluded = set()
    for r in case["records"]:
        label, cap = r["label"], r["capsule"]
        s = cap.get("settlement")
        own: list[str] = []
        kid = None
        if r["capsule_id"] is None or not verify(cap).ok:  # §9.1 item 1
            own.append("capsule_invalid")
        else:  # §9.1 item 2
            from agent_action_capsule.producer_envelope import verify_producer_envelope

            env = verify_producer_envelope(r["capsule_id"], bytes.fromhex(r["envelope_hex"]))
            if env.ok:
                kid = env.public_key.hex()
            else:
                own.append("envelope_invalid")
        structural = _structure_failures(s)
        own += structural
        if not structural:
            own += _wrapped_failures(s, kid, objects)
            if kid is not None and kid != policy[s["sealer_role"]]:  # §3 item 2
                own.append("sealer_not_authorized_for_role")
            ref = s.get("payment_ref")
            if isinstance(ref, dict) and ref["type"] not in REGISTRY["payment_ref_types"]:
                findings.append({"records": [label], "code": "payment_ref_type_unknown"})
        for code in own:
            failures.append({"records": [label], "code": code})
        if own:
            excluded.add(label)
        legs[label] = s if isinstance(s, dict) else {}
        if kid is not None:
            kids[label] = kid
    # §3 item 3: distinct keys, a check on the pair that needs no key policy.
    payer_labels = [lbl for lbl, s in legs.items() if s.get("leg") == "payer_observed" and lbl in kids]
    payee_labels = [lbl for lbl, s in legs.items() if s.get("leg") == "payee_observed" and lbl in kids]
    conflated = False
    for p in payer_labels:
        for q in payee_labels:
            if kids[p] == kids[q] and legs[p].get("terms_ref") == legs[q].get("terms_ref"):
                failures.append({"records": [p, q], "code": "sealer_conflation"})
                conflated = True
    live = {lbl: s for lbl, s in legs.items() if lbl not in excluded}
    terms = [s for lbl, s in live.items() if s["leg"] == "terms" and
             any(r["label"] == lbl for r in case["records"])]
    assert len(terms) == 1, "each case carries one terms leg"
    terms_s = terms[0]
    terms_id = next(r["capsule_id"] for r in case["records"] if r["capsule"].get("settlement") is terms_s)
    for lbl, s in live.items():
        if s["leg"] != "terms" and s["terms_ref"] != terms_id:
            failures.append({"records": [lbl], "code": "terms_ref_unresolved"})
    payer = [s for s in live.values() if s["leg"] == "payer_observed"]
    payee = [s for s in live.values() if s["leg"] == "payee_observed"]
    result: dict[str, Any] = {"conforming": not failures, "failures": failures, "findings": findings}
    # §9.2 payment state
    if not payer and not payee:
        result["payment_state"] = "terms_only"
    elif not payee:
        result["payment_state"] = "payer_stated"
    elif not payer:
        result["payment_state"] = "payee_stated"
    else:
        a, b = payer[0], payee[0]
        known = REGISTRY["payment_ref_types"]
        if a["payment_ref"]["type"] not in known or b["payment_ref"]["type"] not in known \
                or a["payment_ref"]["type"] != b["payment_ref"]["type"]:
            result["payment_state"] = "unjoined"
        else:
            differs = []
            if not amounts_equal(a["amount"], b["amount"]):
                differs.append("amount")
            if a["status"] != b["status"]:
                differs.append("status")
            if _normal_ref(a["payment_ref"]) != _normal_ref(b["payment_ref"]):
                differs.append("payment_ref")
            if differs:
                result["payment_state"] = "mismatch"
                result["differs"] = differs
            else:
                assert not conflated, "agreed is never derived for a conflated pair"
                result["payment_state"] = "agreed"
                result["agreed_status"] = a["status"]
                result["terms_amount"] = "equal" if amounts_equal(a["amount"], terms_s["amount"]) else "differs"
    # §9.3 delivery state
    pinned = terms_s.get("deliverable", {}).get("content_digest")
    delivered = [s["delivery"] for s in live.values() if s["leg"] == "delivered"]
    digests = {d["direction"]: d["content_digest"] for d in delivered}
    if not delivered:
        result["delivery_state"] = "none"
    elif (pinned is not None and any(v != pinned for v in digests.values())) or len(set(digests.values())) > 1:
        result["delivery_state"] = "mismatch"
    elif set(digests) == {"sent", "received"}:
        result["delivery_state"] = "matched"
    else:
        result["delivery_state"] = "stated"
    return result


@pytest.mark.parametrize("case", CASES["cases"], ids=lambda c: c["id"])
def test_derivation_matches_the_stated_expectation(case):
    pytest.importorskip("scitt_cose")
    assert derive(case) == case["expect"]


def _reseal(record: dict, seed_hex: str) -> None:
    """Recompute the Capsule ID and re-sign the Producer Envelope after an edit."""
    import cbor2
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    cap = record["capsule"]
    cap.pop("capsule_id", None)
    cap["capsule_id"] = compute_capsule_id(cap)
    record["capsule_id"] = cap["capsule_id"]
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    protected = cbor2.dumps({1: -8, 3: "application/agent-action-capsule-id", 4: pub}, canonical=True)
    payload = bytes.fromhex(cap["capsule_id"])
    sig = key.sign(cbor2.dumps(["Signature1", protected, b"", payload]))
    record["envelope_hex"] = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, sig])).hex()
    record["envelope_kid"] = pub.hex()


def test_flipping_one_fact_moves_the_derived_state():
    """Each rule is live: edit one fact in the two-sided case, reseal, and the state moves."""
    pytest.importorskip("scitt_cose")
    pytest.importorskip("cbor2")
    base = next(c for c in CASES["cases"] if c["id"] == "pos-x402-two-sided-agreed")
    seeds = {name: k["seed_hex"] for name, k in CASES["keys"].items()}

    def run(label: str, path: list[str], value: Any, signer: str | None = None) -> dict:
        c = copy.deepcopy(base)
        r = next(r for r in c["records"] if r["label"] == label)
        target = r["capsule"]["settlement"]
        for key in path[:-1]:
            target = target[key]
        if path:
            target[path[-1]] = value
        _reseal(r, seeds[signer or r["capsule"]["settlement"]["sealer_role"]])
        return derive(c)

    assert derive(copy.deepcopy(base)) == base["expect"]
    tx = base["records"][1]["capsule"]["settlement"]["payment_ref"]["value"]
    assert run("x402-payee-observed", ["status"], "pending")["differs"] == ["status"]
    assert run("x402-payee-observed", ["payment_ref", "value"], tx[:-1] + "0")["differs"] == ["payment_ref"]
    assert run("x402-payee-observed", ["payment_ref", "value"], "0x" + tx[2:].upper())["payment_state"] == "agreed"
    assert run("x402-payee-observed", ["amount", "value"], "1500001")["differs"] == ["amount"]
    assert run("x402-delivered-received", ["delivery", "content_digest"], "0" * 64)["delivery_state"] == "mismatch"
    assert run("x402-payee-observed", ["sealer_role"], "payer")["failures"][0]["code"] == "leg_role_mismatch"
    assert run("x402-payee-observed", ["amount", "value"], "1.5")["failures"][0]["code"] == "amount_not_exact"
    conflated = run("x402-payee-observed", [], None, signer="payer")
    assert [f["code"] for f in conflated["failures"]] == ["sealer_not_authorized_for_role", "sealer_conflation"]
    assert conflated["payment_state"] == "payer_stated"
    # Exact amount comparison, independent of scale.
    a = {"value": "1500000", "assetCode": "X", "assetScale": 6}
    assert amounts_equal(a, {"value": "150000000", "assetCode": "X", "assetScale": 8})
    assert not amounts_equal(a, {"value": "150000001", "assetCode": "X", "assetScale": 8})
    assert not amounts_equal(a, {"value": "1500000", "assetCode": "Y", "assetScale": 6})
    assert not _amount_ok({"value": "01", "assetCode": "X", "assetScale": 0})
    assert not _amount_ok({"value": "1", "assetCode": "X", "assetScale": True})
    assert not _amount_ok({"value": "1", "assetCode": "X", "assetScale": 256})
